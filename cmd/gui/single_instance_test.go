package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

var mutexNameSeq int64

// The single-instance guard is inherently cross-process, so these tests drive
// real Windows mutex states from a helper subprocess (the test binary re-invoked
// with -test.run=TestHelperSingleInstance). Each test uses a unique mutex name to
// stay isolated from both the real app and the other tests.
const (
	singleInstanceHelperEnv  = "PASSONE_TEST_SINGLE_INSTANCE_HELPER"
	singleInstanceHelperMode = "PASSONE_TEST_SINGLE_INSTANCE_MODE"
	singleInstanceHelperName = "PASSONE_TEST_SINGLE_INSTANCE_NAME"

	singleInstanceModeStay  = "stay"  // own the mutex and stay alive
	singleInstanceModeCrash = "crash" // own the mutex then die abruptly
)

const waitTimeoutCode = 0x00000102 // WAIT_TIMEOUT

// TestHelperSingleInstance is not a real test: when run as a subprocess it
// creates and owns the named mutex exactly like the app's startup path, then
// either stays alive or exits abruptly to simulate a crash.
func TestHelperSingleInstance(t *testing.T) {
	if os.Getenv(singleInstanceHelperEnv) == "" {
		return
	}
	name := os.Getenv(singleInstanceHelperName)
	exitFailure := func(reason string) {
		fmt.Fprintln(os.Stderr, "helper failure:", reason)
		os.Exit(2)
	}
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		exitFailure("UTF16PtrFromString: " + err.Error())
	}
	mutex, err := windows.CreateMutex(nil, false, ptr)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		exitFailure("CreateMutex: " + err.Error())
	}
	if mutex == 0 {
		exitFailure("CreateMutex returned zero handle")
	}
	status, _ := windows.WaitForSingleObject(mutex, 0)
	if status == waitTimeoutCode {
		exitFailure("WaitForSingleObject: WAIT_TIMEOUT")
	}
	// Signal the parent that ownership is in place, then act per mode.
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		exitFailure("flush ready: " + err.Error())
	}
	if os.Getenv(singleInstanceHelperMode) == singleInstanceModeCrash {
		os.Exit(3) // exit while owning: leaves an abandoned mutex
	}
	select {}
}

// startHelper spawns the helper with the given mutex name and mode and returns
// once it reports it owns the mutex.
func startHelper(t *testing.T, name, mode string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=TestHelperSingleInstance")
	cmd.Env = append(os.Environ(),
		singleInstanceHelperEnv+"=1",
		singleInstanceHelperMode+"="+mode,
		singleInstanceHelperName+"="+name)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var helperErr strings.Builder
	cmd.Stderr = &helperErr
	if err := cmd.Start(); err != nil {
		t.Fatalf("helper Start: %v", err)
	}
	ready := make(chan struct{})
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		if strings.Contains(line, "ready") {
			close(ready)
		}
	}()
	select {
	case <-ready:
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("helper did not report ownership of the mutex; stderr: %s", strings.TrimSpace(helperErr.String()))
	}
	return cmd
}

func newMutexName(t *testing.T) string {
	t.Helper()
	// time.Now().UnixNano() is not unique enough on Windows (coarse clock
	// granularity makes consecutive calls collide); use pid + counter instead.
	seq := atomic.AddInt64(&mutexNameSeq, 1)
	return fmt.Sprintf("PassOne-test-single-instance-%d-%d", os.Getpid(), seq)
}

// TestSingleInstanceNoOwner: with nobody else around, startup succeeds.
func TestSingleInstanceNoOwner(t *testing.T) {
	singleInstanceMutexName = newMutexName(t)
	if !acquireSingleInstance() {
		t.Fatal("expected to acquire the mutex when nobody else owns it")
	}
}

// TestSingleInstanceLiveOwner: a live instance owns the mutex, so a second
// startup must refuse.
func TestSingleInstanceLiveOwner(t *testing.T) {
	name := newMutexName(t)
	cmd := startHelper(t, name, singleInstanceModeStay)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	singleInstanceMutexName = name
	if acquireSingleInstance() {
		t.Fatal("expected to refuse while a live instance owns the mutex")
	}
}

// TestSingleInstanceAbandonedOwner: a crashed owner leaves an abandoned mutex
// that a relaunch must take over.
func TestSingleInstanceAbandonedOwner(t *testing.T) {
	name := newMutexName(t)
	cmd := startHelper(t, name, singleInstanceModeCrash)
	// The helper exits non-zero by design; that is the "crash" being simulated.
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected the helper to exit non-zero")
	}

	singleInstanceMutexName = name
	if !acquireSingleInstance() {
		t.Fatal("expected to take over the abandoned mutex after a crash")
	}
}
