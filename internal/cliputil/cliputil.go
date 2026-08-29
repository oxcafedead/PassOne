// Package cliputil writes text to the system clipboard with an optional
// automatic clear, shared by the CLI and the desktop UI.
package cliputil

import (
	"time"

	"github.com/atotto/clipboard"
)

// Copied writes text to the system clipboard and, when clearSeconds > 0,
// clears it after that many seconds if it still holds the same value.
func Copied(text string, clearSeconds int) error {
	if err := clipboard.WriteAll(text); err != nil {
		return err
	}
	if clearSeconds > 0 {
		go clearAfter(text, time.Duration(clearSeconds)*time.Second)
	}
	return nil
}

func clearAfter(sentinel string, d time.Duration) {
	time.Sleep(d)
	cur, err := clipboard.ReadAll()
	if err == nil && cur == sentinel {
		_ = clipboard.WriteAll("")
	}
}
