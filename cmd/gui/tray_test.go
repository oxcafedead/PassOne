package main

import "testing"

// TestRequestQuitIsIdempotent guards the tray quit signal: calling it more than
// once (tray handler races with the watchdog teardown) must not panic or double-close.
func TestRequestQuitIsIdempotent(t *testing.T) {
	requestQuit() // first call closes the channel
	requestQuit() // later calls are safe no-ops
}
