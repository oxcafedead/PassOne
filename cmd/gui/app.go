package main

import (
	"fmt"

	"github.com/oxcafedead/passone/internal/ui"
)

// App is the request-handling surface bound into the frontend under
// wailsjs/go/main/App.
type App struct {
	gui *ui.GUI
}

func NewApp(g *ui.GUI) *App { return &App{gui: g} }

// IsUnlocked reports whether decrypted key material is in memory.
func (a *App) IsUnlocked() bool { return a.gui.IsUnlocked() }

// Unlock validates the stored key passphrases.
func (a *App) Unlock(pgpPass, sshPass string) error { return a.gui.Unlock(pgpPass, sshPass) }

// Lock drops all decrypted keys from memory.
func (a *App) Lock() { a.gui.Lock() }

// AppInfo describes the current environment for the unlock screen.
func (a *App) AppInfo() map[string]string {
	return map[string]string{
		"dataDir":   a.gui.DataDir(),
		"storePath": presence(a.gui.StorePath()),
		"pgpKey":    presenceBool(a.gui.HasStoredPGPKey()),
		"sshKey":    presenceBool(a.gui.HasStoredSSHKey()),
		"autoLock":  autoLockText(a.gui.AutoLockMinutes()),
	}
}

// ListPasswords returns all password paths in the store.
func (a *App) ListPasswords() ([]string, error) { return a.gui.ListPasswords() }

// ShowPassword decrypts and returns an entry's full plaintext.
func (a *App) ShowPassword(name string) (string, error) { return a.gui.ShowPassword(name) }

// CopyPassword copies the first line of an entry to the clipboard.
func (a *App) CopyPassword(name string) error { return a.gui.CopyPassword(name) }

// ClipboardClearSeconds returns how long copied secrets stay on the clipboard.
func (a *App) ClipboardClearSeconds() int { return a.gui.ClipboardClearSeconds() }

// CreatePassword adds a new password entry.
func (a *App) CreatePassword(name, password, confirm, body string) (string, error) {
	return a.gui.CreatePassword(name, password, confirm, body)
}

// UpdatePassword edits an existing password entry.
func (a *App) UpdatePassword(name, password, body string, keepPassword bool) (string, error) {
	return a.gui.UpdatePassword(name, password, body, keepPassword)
}

// RemovePassword deletes a password entry.
func (a *App) RemovePassword(name string) error { return a.gui.RemovePassword(name) }

func presence(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func presenceBool(ok bool) string {
	if ok {
		return "imported"
	}
	return "not imported"
}

func autoLockText(m int) string {
	if m <= 0 {
		return "off"
	}
	if m%60 == 0 {
		return fmt.Sprintf("%d h", m/60)
	}
	if m < 60 {
		return fmt.Sprintf("%d min", m)
	}
	return fmt.Sprintf("%dh %dm", m/60, m%60)
}