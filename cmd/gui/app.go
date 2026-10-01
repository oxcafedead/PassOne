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

// ChangeLockPassword replaces the lock password after verifying the current
// password, re-sealing the stored keys.
func (a *App) ChangeLockPassword(oldPassword, newPassword string) error {
	return a.gui.ChangeLockPassword(oldPassword, newPassword)
}

// Lock drops all decrypted keys from memory.
func (a *App) Lock() { a.gui.Lock() }

// AppInfo describes the current environment for the unlock screen. Every value
// is a location, a key identifier or a setting the user can act on, never
// secret material: the keys are identified by the fingerprint a user is asked
// to confirm, not by the file they are sealed in, which the app has no reason
// to put on screen.
func (a *App) AppInfo() map[string]string {
	return map[string]string{
		"dataDir":   a.gui.DataDir(),
		"storePath": presence(a.gui.StorePath()),
		"pgpKey":    a.gui.PGPKeyFingerprint(),
		"sshKey":    a.gui.SSHKeyID(),
		"autoLock":  autoLockText(a.gui.AutoLockMinutes()),
	}
}

// CopyKeyID puts the app's own OpenPGP fingerprint or SSH key identifier on the
// clipboard. It is not cleared on a timer; a fingerprint is public and has to
// survive being pasted.
func (a *App) CopyKeyID(kind string) error { return a.gui.CopyKeyID(kind) }

// RevealPath opens one of the app's own directories in Windows Explorer.
func (a *App) RevealPath(path string) error { return a.gui.RevealPath(path) }

// ListPasswords returns all password paths in the store.
func (a *App) ListPasswords() ([]string, error) { return a.gui.ListPasswords() }

// ShowPassword decrypts and returns an entry's full plaintext.
func (a *App) ShowPassword(name string) (string, error) { return a.gui.ShowPassword(name) }

// ShowNotes returns an entry's notes — everything below its password line — for
// the edit form. The password is not part of the answer.
func (a *App) ShowNotes(name string) (string, error) { return a.gui.ShowNotes(name) }

// CopyPassword copies the first line of an entry to the clipboard.
func (a *App) CopyPassword(name string) error { return a.gui.CopyPassword(name) }

// CopyTOTP generates the current TOTP code for an entry and copies it to the
// clipboard. The entry must contain an otpauth:// URI in its body.
func (a *App) CopyTOTP(name string) (string, error) { return a.gui.CopyTOTP(name) }

// CopyUsername copies an entry's login to the clipboard. The login is derived
// from the entry body or its file name per the configured username source.
func (a *App) CopyUsername(name string) error { return a.gui.CopyUsername(name) }

// Username returns the login of an entry per the configured username source,
// without revealing the rest of its plaintext.
func (a *App) Username(name string) (string, error) { return a.gui.Username(name) }

// HasTOTP reports whether an entry carries an otpauth:// URI without revealing
// its plaintext. It lets the UI show the TOTP action before the entry content
// is displayed.
func (a *App) HasTOTP(name string) (bool, error) { return a.gui.HasTOTP(name) }

// UsernameSource returns the configured login extraction mode.
func (a *App) UsernameSource() string { return a.gui.UsernameSource() }

// SetUsernameSource persists the login extraction mode (auto, body, filename).
func (a *App) SetUsernameSource(mode string) error { return a.gui.SetUsernameSource(mode) }

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

// MovePassword renames a password entry or moves it into another folder. The
// stored file is renamed, so the entry is never re-encrypted.
func (a *App) MovePassword(from, to string) (string, error) {
	return a.gui.MovePassword(from, to)
}

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

// GeneratePGPKey creates a new OpenPGP key and seals it under lockPassword,
// returning its fingerprint.
func (a *App) GeneratePGPKey(name, email, passphrase, lockPassword string) (string, error) {
	return a.gui.GeneratePGPKey(name, email, passphrase, lockPassword)
}

// CreateStore creates a new pass store in an empty folder, encrypted to the
// OpenPGP key the app holds, and activates it. The remote is optional and is
// recorded without being contacted.
func (a *App) CreateStore(path, remote string) error { return a.gui.CreateStore(path, remote) }

// DefaultStoreDir resolves a store name typed in the wizard into a path under
// the app stores directory, or "" when the name cannot be used.
func (a *App) DefaultStoreDir(name string) string { return a.gui.DefaultStoreDir(name) }

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

// ClipboardHistoryEnabled reports whether Windows is keeping a Clipboard History
// for this user, or may sync the clipboard to their other devices.
func (a *App) ClipboardHistoryEnabled() bool { return a.gui.ClipboardHistoryEnabled() }

// SetGitAuthor updates the git commit identity.
func (a *App) SetGitAuthor(name, email string) error { return a.gui.SetGitAuthor(name, email) }

// Status returns git status text for the active store.
func (a *App) Status() (string, error) { return a.gui.Status() }

// Sync performs fetch → pull → push for the active store and returns a
// human-readable summary.
func (a *App) Sync() (string, error) { return a.gui.Sync() }

// KnownHosts lists trusted SSH hosts.
func (a *App) KnownHosts() []string { return a.gui.KnownHosts() }

// CheckForUpdates asks GitHub whether a newer published PassOne release exists.
//
// Nothing is downloaded, replaced or installed: the answer is a message for the
// UI to show, and the caller decides whether it is worth interrupting for.
func (a *App) CheckForUpdates() (ui.UpdateInfo, error) { return a.gui.CheckForUpdates() }

func presence(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
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
