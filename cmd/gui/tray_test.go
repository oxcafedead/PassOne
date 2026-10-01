package main

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"
)

// TestRequestQuitIsIdempotent guards the tray quit signal: calling it more than
// once (tray handler races with the watchdog teardown) must not panic or double-close.
func TestRequestQuitIsIdempotent(t *testing.T) {
	requestQuit() // first call closes the channel
	requestQuit() // later calls are safe no-ops
}

// TestRunTrayPinsItsGoroutineToOneOSThread is the regression test for GH #14.
//
// systray's hidden window is serviced by a GetMessageW loop that only drains
// the calling thread's message queue, so the window and the loop reading its
// messages have to stay on one thread. systray pins the thread its package
// init ran on — the main thread, which Wails needs — so the only thing
// protecting the tray once Run is moved onto its own goroutine is the pin in
// runTray. Without it the app degrades to an inert tray icon that can only be
// ended from Task Manager.
//
// A goroutine that blocks hands its thread back to the scheduler and is very
// likely to resume on a different one, so yielding repeatedly is what makes
// the difference observable. The assertion is only that the thread did not
// change, which LockOSThread guarantees outright: this cannot flake.
func TestRunTrayPinsItsGoroutineToOneOSThread(t *testing.T) {
	var first, second uint32
	systrayRun = func(_, _ func()) {
		first = windows.GetCurrentThreadId()
		for range 64 {
			runtime.Gosched()
			time.Sleep(time.Millisecond)
		}
		second = windows.GetCurrentThreadId()
	}
	t.Cleanup(func() { systrayRun = systray.Run })

	select {
	case <-runTray(func() {}, func() {}):
	case <-time.After(30 * time.Second):
		t.Fatal("runTray never reported the loop stopping")
	}

	if first == 0 {
		t.Fatal("the tray loop never ran")
	}
	if first != second {
		t.Errorf("the tray loop moved from OS thread %d to %d, so it is no longer pumping the queue its own window posts to (GH #14)", first, second)
	}
}

// TestClassifyTrayStopTellsAQuietStopFromADeadTray pins the decision
// watchTray acts on. The two cases are opposites and the wrong one is
// destructive: treating a normal quit as a dead tray would exit the process
// with a 1 while it is tearing down on purpose.
func TestClassifyTrayStopTellsAQuietStopFromADeadTray(t *testing.T) {
	notQuitting := make(chan struct{})
	if got := classifyTrayStop(notQuitting); got != trayStopExit {
		t.Errorf("a tray loop that stopped with no quit requested is %v, want trayStopExit", got)
	}

	quitting := make(chan struct{})
	close(quitting)
	if got := classifyTrayStop(quitting); got != trayStopQuiet {
		t.Errorf("a tray loop that stopped after a quit was requested is %v, want trayStopQuiet", got)
	}
}

// TestWatchTrayExitsOnlyWhenItWasNotQuitting pins the recovery itself. The tray
// holds the only Quit item, so a loop that stops on its own while the app is
// meant to be running leaves a process nobody can close (GH #14) — that has to
// end the process. The same stop during a quit is ordinary teardown and must
// be left alone for main to drain.
func TestWatchTrayExitsOnlyWhenItWasNotQuitting(t *testing.T) {
	// A stopped loop, so watchTray has nothing to wait for.
	stopped := make(chan struct{})
	close(stopped)

	for _, tc := range []struct {
		name       string
		quitting   bool
		wantExited bool
	}{
		{name: "the tray died while the app was running", quitting: false, wantExited: true},
		{name: "the tray stopped during a quit", quitting: true, wantExited: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			quitting := make(chan struct{})
			if tc.quitting {
				close(quitting)
			}
			var mu sync.Mutex
			var codes []int
			exit := func(code int) {
				mu.Lock()
				defer mu.Unlock()
				codes = append(codes, code)
			}

			watchTray(stopped, quitting, exit)

			mu.Lock()
			defer mu.Unlock()
			if got := len(codes) > 0; got != tc.wantExited {
				t.Fatalf("exited = %v (codes %v), want %v", got, codes, tc.wantExited)
			}
			if tc.wantExited && codes[0] != 1 {
				t.Errorf("exit code %d, want 1: this is a fault, not a quit the user asked for", codes[0])
			}
		})
	}
}
