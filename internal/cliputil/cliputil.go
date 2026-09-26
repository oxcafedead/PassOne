// Package cliputil writes secrets to the Windows clipboard, keeps them out of
// Windows Clipboard History and the cross-device cloud clipboard, and clears
// them after a delay. Shared by the CLI and the desktop UI.
//
// Two guarantees are deliberately reported rather than assumed, because Windows
// can refuse both:
//
//   - Clipboard History and the cloud clipboard snapshot an item when it is set.
//     Clearing later cannot reach what they already took, so Copied marks the
//     item with the formats Windows reads for that decision and reports whether
//     the marker went on in the Result it returns.
//   - The delayed clear runs after the copy call returned, so a failure to
//     clear cannot travel back in that Result and is reported through
//     SetWarningFunc instead.
package cliputil

import (
	"fmt"
	"sync"
	"time"
)

const (
	// openAttempts and openRetryDelay bound how long a clipboard operation
	// waits out another application that holds the clipboard open.
	openAttempts   = 8
	openRetryDelay = 25 * time.Millisecond
	// readAttempts is used when checking whether the clipboard still holds a
	// secret. It is deliberately more patient than openAttempts: an unreadable
	// clipboard makes the clear fall back to wiping unconditionally, so it is
	// worth waiting longer to avoid wiping something the user just copied.
	readAttempts = 12
)

// Result reports what a clipboard write actually achieved, so a caller can tell
// the user when a guarantee could not be made.
type Result struct {
	// HistoryExcluded reports that the clipboard item carried the formats
	// Windows reads to keep it out of Clipboard History and the cloud
	// clipboard. It is false when the marker could not be written, in which
	// case the text was still copied.
	HistoryExcluded bool
}

// Caveat returns a short warning for the user about what the write could not
// guarantee, or the empty string when there is nothing to say.
func (r Result) Caveat() string {
	if r.HistoryExcluded {
		return ""
	}
	return "Windows may keep this in Clipboard History or sync it to your other devices"
}

// Copied writes text to the clipboard, marks it so Windows keeps it out of
// Clipboard History and the cloud clipboard, and clears it after clearSeconds.
// A clearSeconds of 0 or less leaves the text in place.
func Copied(text string, clearSeconds int) (Result, error) {
	marked, err := writeText(text, historySuppression)
	if err != nil {
		return Result{}, err
	}
	res := Result{HistoryExcluded: marked}
	if clearSeconds > 0 {
		go clearAfter(text, time.Duration(clearSeconds)*time.Second)
	}
	return res, nil
}

// clearAfter waits for d, then removes sentinel from the clipboard.
func clearAfter(sentinel string, d time.Duration) {
	time.Sleep(d)
	if err := clear(sentinel); err != nil {
		warnf("%v", err)
	}
}

// readClipboard reads the clipboard for clear, and wipeClipboard is the wipe it
// falls back to. Both are indirected so a test can inject an unreadable or
// unwipeable clipboard and assert what happens then.
var (
	readClipboard = readText
	wipeClipboard = wipe
)

// clear removes sentinel from the clipboard.
//
// It leaves the clipboard alone when it holds anything else, so a value the
// user copied after this one survives. When the clipboard cannot be read at all
// it fails closed: an unreadable clipboard is not evidence that the user moved
// on, and a secret left behind is the worse outcome, so it wipes unconditionally
// and says that is what happened.
func clear(sentinel string) error {
	cur, err := readClipboard(readAttempts, openRetryDelay)
	if err != nil {
		if werr := wipeClipboard(); werr != nil {
			return fmt.Errorf("the clipboard was unreadable (%v) and could not be cleared either: %w", err, werr)
		}
		return fmt.Errorf("the clipboard was unreadable (%v), so it was cleared unconditionally", err)
	}
	if cur != sentinel {
		return nil
	}
	return wipeClipboard()
}

// wipe empties the clipboard. The empty item is marked for exclusion too, so
// clearing a secret does not push a blank entry into Clipboard History.
func wipe() error {
	if _, err := writeText("", historySuppression); err != nil {
		return fmt.Errorf("could not clear the clipboard: %w", err)
	}
	return nil
}

// warning holds the callback registered with SetWarningFunc.
var warning struct {
	mu sync.Mutex
	fn func(string)
}

// SetWarningFunc registers a callback that receives a human-readable warning
// whenever a clipboard guarantee could not be met, above all when the delayed
// clear failed. It is package-level because that failure happens on a timer
// with no caller left to return to; the CLI and the GUI each register one at
// startup. Pass nil to unregister.
func SetWarningFunc(fn func(string)) {
	warning.mu.Lock()
	warning.fn = fn
	warning.mu.Unlock()
}

// warnf reports a clipboard guarantee that could not be met.
func warnf(format string, a ...any) {
	warning.mu.Lock()
	fn := warning.fn
	warning.mu.Unlock()
	if fn == nil {
		return
	}
	fn(fmt.Sprintf(format, a...))
}
