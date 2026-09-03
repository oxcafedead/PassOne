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

// NewApp creates the Wails-bound application facade.
func NewApp(g *ui.GUI) *App { return &App{gui: g} }

// IsUnlocked reports whether decrypted key material is in memory.
func (a *App) IsUnlocked() bool { return a.gui.IsUnlocked() }

// Unlock validates and loads the stored keys using the single lock password.
func (a *App) Unlock(lockPassword string) error { return a.gui.Unlock(lockPassword) }

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

// PickPrivateKey opens a file dialog for a private key file.
func (a *App) PickPrivateKey(title string) (ui.Picked, error) { return a.gui.PickPrivateKey(title) }

// PickStoreDir opens a directory dialog for a password store.
func (a *App) PickStoreDir() (ui.Picked, error) { return a.gui.PickStoreDir() }

// ImportPGPKeyFile imports an on-disk OpenPGP private key.
func (a *App) ImportPGPKeyFile(path, passphrase, lockPassword string) (string, error) {
	return a.gui.ImportPGPKeyFile(path, passphrase, lockPassword)
}

// ImportSSHKeyFile imports an on-disk OpenSSH private key.
func (a *App) ImportSSHKeyFile(path, passphrase, lockPassword string) (string, error) {
	return a.gui.ImportSSHKeyFile(path, passphrase, lockPassword)
}

// HasSSHKeyLoaded reports whether the SSH signer is in memory for transport.
func (a *App) HasSSHKeyLoaded() bool { return a.gui.HasSSHKeyLoaded() }

// LoadSSHKey decrypts the stored SSH key into memory without unlocking the
// session. Used by onboarding to make cloning possible after a restart.
func (a *App) LoadSSHKey(lockPassword string) error { return a.gui.LoadSSHKey(lockPassword) }

// OpenLocalStore validates and activates a local pass store directory.
func (a *App) OpenLocalStore(path string) error { return a.gui.OpenLocalStore(path) }

// StoredStores lists local pass stores under the app stores directory.
func (a *App) StoredStores() []string { return a.gui.StoredStores() }

// PrepareClone probes an SSH git URL and reports the server host key state.
func (a *App) PrepareClone(url string) (ui.ClonePrep, error) { return a.gui.PrepareClone(url) }

// TrustHost records the just-probed host key as trusted.
func (a *App) TrustHost(hostport string) error { return a.gui.TrustHost(hostport) }

// CloneStore clones an SSH git URL and activates the resulting store.
func (a *App) CloneStore(url, dir string) error { return a.gui.CloneStore(url, dir) }

// CurrentSettings returns the environment for the setup screen.
func (a *App) CurrentSettings() ui.SettingsInfo { return a.gui.CurrentSettings() }

// SetAutoLock updates the idle auto-lock timeout in minutes.
func (a *App) SetAutoLock(minutes int) error { return a.gui.SetAutoLock(minutes) }

// SetClipboardClear updates the clipboard clear delay in seconds.
func (a *App) SetClipboardClear(seconds int) error { return a.gui.SetClipboardClear(seconds) }

// SetGitAuthor updates the git commit identity.
func (a *App) SetGitAuthor(name, email string) error { return a.gui.SetGitAuthor(name, email) }

// Status returns git status text for the active store.
func (a *App) Status() (string, error) { return a.gui.Status() }

// Sync performs fetch → pull → push for the active store and returns a
// human-readable summary.
func (a *App) Sync() (string, error) { return a.gui.Sync() }

// KnownHosts lists trusted SSH hosts.
func (a *App) KnownHosts() []string { return a.gui.KnownHosts() }

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
