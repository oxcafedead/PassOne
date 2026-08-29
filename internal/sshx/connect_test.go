package sshx

import (
	"testing"
	"time"
)

func TestEnsurePort(t *testing.T) {
	cases := map[string]string{
		"github.com":       "github.com:22",
		"github.com:22":    "github.com:22",
		"git.example:2222": "git.example:2222",
		"EXAMPLE.com":      "EXAMPLE.com:22",
	}
	for in, want := range cases {
		if got := ensurePort(in); got != want {
			t.Errorf("ensurePort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCaptureHostKeyTimesOut(t *testing.T) {
	// Use a port that is extremely unlikely to accept connections.
	// CaptureHostKey should fail quickly thanks to the timeout.
	start := time.Now()
	if _, err := CaptureHostKey("127.0.0.1:1"); err == nil {
		t.Fatal("expected CaptureHostKey to fail")
	}
	if time.Since(start) > 30*time.Second {
		t.Fatal("CaptureHostKey took too long to fail")
	}
}
