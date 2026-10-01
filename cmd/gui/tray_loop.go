package main

import (
	"runtime"

	"github.com/getlantern/golog"
	"github.com/getlantern/systray"
)

// guiLog writes into the data directory's passone.log, which main.go points
// golog at. A GUI app has no stderr to complain to, and a tray that stops
// working leaves no other trace of why.
var guiLog = golog.LoggerFor("passone")

// systrayRun is the systray event loop, held as a variable so a test can stand
// in for it and observe the thread runTray pins its goroutine to.
var systrayRun = systray.Run

// runTray runs the systray event loop on its own goroutine and returns a
// channel that is closed once the loop has stopped.
//
// The goroutine is pinned to its OS thread, and pinning it is the whole reason
// this function exists rather than a bare `go systray.Run(...)`.
//
// systray creates a hidden window and then services it with a GetMessageW loop
// that only ever drains the *calling* thread's message queue. Its package init
// pins whichever thread package initialisation happened to land on, which in a
// program with a main() is the main thread — the one Wails requires for itself,
// which is why this loop cannot simply run there. Moving Run onto a fresh
// goroutine satisfies Wails and silently abandons systray's assumption: nothing
// then keeps the window and the pump that reads its messages on one thread.
//
// The result is the failure reported in GH #14 — the icon stays in the
// notification area, left and right clicks stop doing anything after a while,
// and because the tray holds the only Quit item the process can then only be
// ended from Task Manager. Locking the goroutine to its thread is the fix that
// upstream converged on for the same report (getlantern/systray#149, #161, and
// #269 closed by #281), where the same symptom was traced to exactly this
// missing pin.
func runTray(onReady, onExit func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		systrayRun(onReady, onExit)
	}()
	return done
}

// stopTray asks the systray event loop to stop and waits for it to, so the
// icon is gone from the notification area before the process goes away. It is
// safe to call once the loop has already stopped on its own: the exit is a
// one-shot and waiting on a closed channel returns at once.
func stopTray(done <-chan struct{}) {
	systray.Quit()
	<-done
}

// trayStopAction is what a systray event loop that has stopped means for the
// process.
type trayStopAction int

const (
	// trayStopQuiet means the loop stopped as part of a quit that was already
	// asked for, so main is on its way out and drains the tray itself.
	trayStopQuiet trayStopAction = iota
	// trayStopExit means the loop died while PassOne was still meant to be
	// running, which leaves an inert tray icon and no way to quit.
	trayStopExit
)

// classifyTrayStop decides what a stopped systray loop means. quitting is the
// quitRequested channel, which is closed exactly when the user has asked to
// quit, so the question is asked of the channel rather than of a bool a caller
// might have read before the close landed.
func classifyTrayStop(quitting <-chan struct{}) trayStopAction {
	select {
	case <-quitting:
		return trayStopQuiet
	default:
		return trayStopExit
	}
}

// watchTray ends the process if the systray event loop stops while PassOne is
// still running, so a dead tray can never become an app nobody can close.
//
// The tray owns the process lifetime by design: the window only hides when it
// is closed (HideWindowOnClose) and every exit goes through the tray's Quit
// item, which closes quitRequested before Wails is asked to tear down. That
// makes a loop that stops for any other reason unrecoverable in place — the
// icon is still in the notification area, it opens no menu, and there is no
// other route out. Lingering would also keep holding the single-instance mutex,
// so the next launch would be turned away and find nothing to show; the quit
// watchdog in main.go reasons about that from the other direction.
//
// Exiting is a clean exit of an app that has nothing left to offer, and the log
// line is the only account of it: nothing in the UI could have said it, because
// the UI is unreachable by definition at this point.
func watchTray(systrayDone, quitting <-chan struct{}, exit func(int)) {
	<-systrayDone
	if classifyTrayStop(quitting) == trayStopQuiet {
		return
	}
	_ = guiLog.Errorf("the tray event loop stopped while PassOne was still running; the tray icon no longer opens a menu and is the only way to quit, so the process is exiting")
	exit(1)
}
