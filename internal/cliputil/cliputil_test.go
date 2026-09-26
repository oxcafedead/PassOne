package cliputil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// skipIfNoClipboard skips the test when the clipboard is unusable, which is the
// case in a headless session.
func skipIfNoClipboard(t *testing.T) {
	t.Helper()
	if _, err := writeText("", nil); err != nil {
		t.Skipf("clipboard not available: %v", err)
	}
}

// currentText returns what the clipboard holds as text, failing the test when it
// cannot be read.
func currentText(t *testing.T) string {
	t.Helper()
	got, err := readText(openAttempts, openRetryDelay)
	if err != nil {
		t.Fatalf("readText: %v", err)
	}
	return got
}

// readRegisteredDword returns the DWORD stored under a registered clipboard
// format, reporting false when the format is not on the clipboard at all.
func readRegisteredDword(t *testing.T, name string) (uint32, bool) {
	t.Helper()
	id, err := registerFormat(name)
	if err != nil {
		t.Fatalf("registerFormat(%s): %v", name, err)
	}
	var value uint32
	found := false
	err = withClipboard(openAttempts, openRetryDelay, func() error {
		h, err := win32(procGetClipboardData, uintptr(id))
		if err != nil || h == 0 {
			return nil
		}
		b, err := globalRead(h)
		if err != nil {
			return err
		}
		if len(b) < 4 {
			return fmt.Errorf("%s holds %d bytes, want at least 4", name, len(b))
		}
		value, found = binary.LittleEndian.Uint32(b), true
		return nil
	})
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return value, found
}

func TestCopiedAndCleared(t *testing.T) {
	skipIfNoClipboard(t)

	sentinel := "test-secret-" + time.Now().String()
	if _, err := Copied(sentinel, 1); err != nil {
		t.Fatalf("Copied: %v", err)
	}
	if got := currentText(t); got != sentinel {
		t.Fatalf("clipboard = %q, want %q", got, sentinel)
	}

	// Wait for the background clear goroutine.
	time.Sleep(1500 * time.Millisecond)
	if got := currentText(t); got == sentinel {
		t.Fatal("clipboard was not cleared")
	}
}

func TestCopiedNoClear(t *testing.T) {
	skipIfNoClipboard(t)

	const sentinel = "persistent-secret"
	if _, err := Copied(sentinel, 0); err != nil {
		t.Fatalf("Copied: %v", err)
	}
	if got := currentText(t); got != sentinel {
		t.Fatalf("clipboard = %q, want %q", got, sentinel)
	}
}

// The Windows formats that keep a secret out of Clipboard History and the cloud
// clipboard have to be on the item itself: those stores snapshot it as it is
// set, so a later clear cannot reach what they already took.
func TestCopiedMarksItemForHistoryExclusion(t *testing.T) {
	skipIfNoClipboard(t)

	const sentinel = "marked-secret"
	res, err := Copied(sentinel, 0)
	if err != nil {
		t.Fatalf("Copied: %v", err)
	}
	if !res.HistoryExcluded {
		t.Fatalf("HistoryExcluded = false, want true (Caveat %q)", res.Caveat())
	}
	if res.Caveat() != "" {
		t.Fatalf("Caveat = %q, want empty", res.Caveat())
	}
	if got := currentText(t); got != sentinel {
		t.Fatalf("clipboard = %q, want %q", got, sentinel)
	}

	for _, want := range []struct {
		name  string
		value uint32
	}{
		{"ExcludeClipboardContentFromMonitorProcessing", 1},
		{"CanIncludeInClipboardHistory", 0},
		{"CanUploadToCloudClipboard", 0},
	} {
		got, ok := readRegisteredDword(t, want.name)
		if !ok {
			t.Errorf("clipboard item carries no %s format", want.name)
			continue
		}
		if got != want.value {
			t.Errorf("%s = %d, want %d", want.name, got, want.value)
		}
	}
}

// The marker decision travels back in the Result, not through the warning
// handler. That handler exists for the delayed clear, which has no caller left
// to return to; a copy that may reach history is reported once, by the copy that
// caused it.
func TestCopiedLeavesTheWarningHandlerAlone(t *testing.T) {
	skipIfNoClipboard(t)

	var mu sync.Mutex
	var warned []string
	SetWarningFunc(func(msg string) {
		mu.Lock()
		warned = append(warned, msg)
		mu.Unlock()
	})
	defer SetWarningFunc(nil)

	if _, err := Copied("quiet-copy", 0); err != nil {
		t.Fatalf("Copied: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(warned) != 0 {
		t.Fatalf("warnings = %v, want none", warned)
	}
}

// A secret that cannot be read back is still a secret on the clipboard, so the
// clear has to wipe it rather than assume the user moved on, and the caller has
// to hear that the wipe was unconditional.
func TestClearFailsClosedOnUnreadableClipboard(t *testing.T) {
	skipIfNoClipboard(t)

	const sentinel = "fail-closed-secret"
	if _, err := Copied(sentinel, 0); err != nil {
		t.Fatalf("Copied: %v", err)
	}

	restore := stubReadClipboard(func(int, time.Duration) (string, error) {
		return "", errors.New("simulated clipboard read failure")
	})
	defer restore()

	var mu sync.Mutex
	var warned string
	SetWarningFunc(func(msg string) {
		mu.Lock()
		warned = msg
		mu.Unlock()
	})
	defer SetWarningFunc(nil)

	clearAfter(sentinel, time.Millisecond)

	if got := currentText(t); strings.Contains(got, sentinel) {
		t.Fatalf("clipboard still holds the secret: %q", got)
	}
	mu.Lock()
	msg := warned
	mu.Unlock()
	if !strings.Contains(msg, "unconditionally") {
		t.Fatalf("warning = %q, want it to report an unconditional clear", msg)
	}
}

func TestClearAfterDoesNotOverwriteChangedClipboard(t *testing.T) {
	skipIfNoClipboard(t)

	// Put a value other than the sentinel on the clipboard so the clear sees
	// cur != sentinel and leaves it alone.
	const other = "do-not-touch"
	if _, err := writeText(other, nil); err != nil {
		t.Fatalf("writeText: %v", err)
	}
	clearAfter("sentinel-value", 10*time.Millisecond)

	if got := currentText(t); got != other {
		t.Fatalf("clipboard changed to %q, want %q", got, other)
	}
}

// A value copied after the secret is not a secret and must survive, which is the
// whole reason the clear reads the clipboard before wiping it.
func TestClearLeavesALaterValueAlone(t *testing.T) {
	skipIfNoClipboard(t)

	const secret, later = "the-secret", "copied-afterwards"
	if _, err := Copied(secret, 0); err != nil {
		t.Fatalf("Copied: %v", err)
	}
	if _, err := writeText(later, nil); err != nil {
		t.Fatalf("writeText: %v", err)
	}
	if err := clear(secret); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := currentText(t); got != later {
		t.Fatalf("clipboard = %q, want %q", got, later)
	}
}

// A clipboard that can neither be read nor written is the one case the user has
// to handle themselves, so the error has to say so instead of claiming the
// secret is gone.
func TestClearReportsAClipboardItCannotWipe(t *testing.T) {
	skipIfNoClipboard(t)

	const sentinel = "unwipeable-secret"
	if _, err := Copied(sentinel, 0); err != nil {
		t.Fatalf("Copied: %v", err)
	}

	defer stubReadClipboard(func(int, time.Duration) (string, error) {
		return "", errors.New("simulated clipboard read failure")
	})()
	prev := wipeClipboard
	wipeClipboard = func() error { return errors.New("simulated clipboard write failure") }
	defer func() { wipeClipboard = prev }()

	err := clear(sentinel)
	if err == nil {
		t.Fatal("clear reported success while the clipboard was neither readable nor writable")
	}
	if !strings.Contains(err.Error(), "could not be cleared") {
		t.Fatalf("error = %q, want it to report the failed clear", err)
	}
	if got := currentText(t); got != sentinel {
		t.Fatalf("clipboard = %q, want the secret still there so the warning is not a lie", got)
	}
}

func TestHistoryOff(t *testing.T) {
	one := uint64(1)
	zero := uint64(0)

	tests := []struct {
		name   string
		values map[string]*uint64
		want   bool
	}{
		{name: "absent everywhere keeps the windows default", values: map[string]*uint64{}, want: false},
		{name: "everything on", values: map[string]*uint64{
			"AllowClipboardHistory": &one, "AllowCrossDeviceClipboard": &one,
			"EnableClipboardHistory": &one, "EnableCloudClipboard": &one,
		}, want: false},
		{name: "one user toggle off", values: map[string]*uint64{
			"EnableClipboardHistory": &zero,
		}, want: true},
		{name: "policy off wins over the user setting", values: map[string]*uint64{
			"AllowClipboardHistory": &zero, "EnableClipboardHistory": &one,
		}, want: true},
		{name: "cross-device policy off", values: map[string]*uint64{
			"AllowCrossDeviceClipboard": &zero,
		}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := historyOff(func(_ registry.Key, _, name string) (*uint64, error) {
				return tc.values[name], nil
			})
			if err != nil {
				t.Fatalf("historyOff: %v", err)
			}
			if got != tc.want {
				t.Fatalf("historyOff = %v, want %v", got, tc.want)
			}
		})
	}
}

// An unreadable setting proves nothing, so it must not be reported as off.
func TestHistoryOffPropagatesReadFailures(t *testing.T) {
	_, err := historyOff(func(registry.Key, string, string) (*uint64, error) {
		return nil, errors.New("access denied")
	})
	if err == nil {
		t.Fatal("historyOff ignored a read failure")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("error = %q, want it to name the read failure", err)
	}
}

func TestHistoryEnabledOnThisMachine(t *testing.T) {
	on, err := HistoryEnabled()
	if err != nil {
		t.Skipf("clipboard history settings are not readable here: %v", err)
	}
	t.Logf("Windows clipboard history reported as enabled: %v", on)
}

func TestReadDwordMissingValue(t *testing.T) {
	v, err := readDword(registry.CURRENT_USER, `Software\PassOneCliputilNoSuchKey`, "EnableClipboardHistory")
	if err != nil {
		t.Fatalf("readDword: %v", err)
	}
	if v != nil {
		t.Fatalf("readDword = %d, want nil for a key that does not exist", *v)
	}
}

// stubReadClipboard replaces the clipboard read for the duration of a test.
func stubReadClipboard(fn func(int, time.Duration) (string, error)) func() {
	prev := readClipboard
	readClipboard = fn
	return func() { readClipboard = prev }
}
