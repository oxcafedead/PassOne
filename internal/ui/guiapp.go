// Package ui provides a Wails-friendly facade over the core application.
// It is the single entry point the desktop frontend binds against; nothing in
// internal/app or lower layers knows about the UI.
package ui

import (
	"github.com/oxcafedead/passone/internal/app"
)

// GUI wraps the core App for the desktop interface.
type GUI struct {
	core *app.App
}

// New boots the core application with the same data directory as the CLI
// (%LOCALAPPDATA%\PassOne unless PASSONE_DIR overrides it).
func New() (*GUI, error) {
	core, err := app.New()
	if err != nil {
		return nil, err
	}
	return &GUI{core: core}, nil
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