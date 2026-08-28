// Package ui provides a Wails-friendly facade over the core application.
// It is the single entry point the desktop frontend binds against; nothing in
// internal/app or lower layers knows about the UI.
package ui

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/oxcafedead/passone/internal/app"
	"github.com/oxcafedead/passone/internal/cliputil"
	"github.com/oxcafedead/passone/internal/security"
)

// GUI wraps the core App for the desktop interface. It mirrors the CLI surface
// (list, show, copy, status...) so the frontend never touches internal/app.
type GUI struct {
	core *app.App
	mu   sync.Mutex
	ctx  context.Context
}

// New boots the core application with the same data directory as the CLI
// (%LOCALAPPDATA%\PassOne unless PASSONE_DIR overrides it).
func New() (*GUI, error) {
	core, err := app.New()
	if err != nil {
		return nil, err
	}
	g := &GUI{core: core}
	core.OnLock(func() { g.emit("passone:locked") })
	core.OnUnlock(func() { g.emit("passone:unlocked") })
	return g, nil
}

// SetContext receives the Wails runtime context during startup; it enables the
// lock/unlock event stream delivered to the frontend.
func (g *GUI) SetContext(ctx context.Context) {
	g.mu.Lock()
	g.ctx = ctx
	g.mu.Unlock()
}

func (g *GUI) emit(name string) {
	g.mu.Lock()
	ctx := g.ctx
	g.mu.Unlock()
	if ctx != nil {
		runtime.EventsEmit(ctx, name, nil)
	}
}

// IsUnlocked reports whether decrypted key material is in memory.
func (g *GUI) IsUnlocked() bool { return g.core.IsUnlocked() }

// Lock drops all decrypted keys from memory.
func (g *GUI) Lock() { g.core.Lock() }

// Unlock validates the stored key passphrases. Empty strings are treated as
// no passphrase (relevant for unprotected keys).
func (g *GUI) Unlock(pgpPass, sshPass string) error {
	return g.core.Unlock([]byte(pgpPass), []byte(sshPass))
}

// HasStoredPGPKey reports whether a secret OpenPGP key was imported.
func (g *GUI) HasStoredPGPKey() bool { return g.core.HasStoredPGPKey() }

// HasStoredSSHKey reports whether an SSH private key was imported.
func (g *GUI) HasStoredSSHKey() bool { return g.core.HasStoredSSHKey() }

// DataDir returns the application data directory.
func (g *GUI) DataDir() string { return g.core.DataDir() }

// StorePath returns the configured store path (may be empty).
func (g *GUI) StorePath() string { return g.core.Config().StorePath }

// AutoLockMinutes returns the configured idle timeout in minutes.
func (g *GUI) AutoLockMinutes() int { return g.core.Config().AutoLockMinutes }

// ClipboardClearSeconds returns how long copied secrets stay on the clipboard.
func (g *GUI) ClipboardClearSeconds() int { return g.core.Config().ClipboardClearSeconds }

// ListPasswords returns all password paths in the configured store. It does
// not require an unlocked session and never reveals secret material.
func (g *GUI) ListPasswords() ([]string, error) {
	return g.core.ListPasswords()
}

// ShowPassword decrypts and returns the full plaintext of an entry for display.
func (g *GUI) ShowPassword(name string) (string, error) {
	plaintext, err := g.core.ShowPassword(name)
	if err != nil {
		return "", err
	}
	text := string(plaintext)
	security.Zero(plaintext)
	return text, nil
}

// CopyPassword writes the first line of an entry to the Windows clipboard and
// schedules clearing it, mirroring the CLI 'copy' behaviour. The secret is
// never returned to the frontend.
func (g *GUI) CopyPassword(name string) error {
	plaintext, err := g.core.ShowPassword(name)
	if err != nil {
		return err
	}
	defer security.Zero(plaintext)
	text := string(plaintext)
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	if err := cliputil.Copied(text, g.core.Config().ClipboardClearSeconds); err != nil {
		return fmt.Errorf("unable to write to the Windows clipboard: %w", err)
	}
	return nil
}