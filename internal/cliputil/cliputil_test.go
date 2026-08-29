package cliputil

import (
	"testing"
	"time"

	"github.com/atotto/clipboard"
)

func TestCopiedAndCleared(t *testing.T) {
	// Clipboard access may not be available in headless CI; skip gracefully.
	if err := clipboard.WriteAll("probe"); err != nil {
		t.Skipf("clipboard not available: %v", err)
	}

	sentinel := "test-secret-" + time.Now().String()
	if err := Copied(sentinel, 1); err != nil {
		t.Fatalf("Copied: %v", err)
	}
	got, err := clipboard.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if got != sentinel {
		t.Fatalf("clipboard = %q, want %q", got, sentinel)
	}

	// Wait for the background clear goroutine.
	time.Sleep(1500 * time.Millisecond)
	got, err = clipboard.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll after clear: %v", err)
	}
	if got == sentinel {
		t.Fatal("clipboard was not cleared")
	}
}

func TestCopiedNoClear(t *testing.T) {
	if err := clipboard.WriteAll("probe"); err != nil {
		t.Skipf("clipboard not available: %v", err)
	}

	sentinel := "persistent-secret"
	if err := Copied(sentinel, 0); err != nil {
		t.Fatalf("Copied: %v", err)
	}
	got, err := clipboard.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if got != sentinel {
		t.Fatalf("clipboard = %q, want %q", got, sentinel)
	}
}

func TestClearAfterDoesNotOverwriteChangedClipboard(t *testing.T) {
	if err := clipboard.WriteAll("probe"); err != nil {
		t.Skipf("clipboard not available: %v", err)
	}

	// Pre-seed the clipboard with a value other than the sentinel so the
	// clear goroutine sees cur != sentinel and leaves it alone.
	const other = "do-not-touch"
	if err := clipboard.WriteAll(other); err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	clearAfter("sentinel-value", 10*time.Millisecond)

	got, err := clipboard.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if got != other {
		t.Fatalf("clipboard changed to %q, want %q", got, other)
	}
}
