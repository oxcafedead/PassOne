// Package ui provides a Wails-friendly facade over the core application.
// It is the single entry point the desktop frontend binds against; nothing in
// internal/app or lower layers knows about the UI.
package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/crypto/ssh"

	"github.com/oxcafedead/passone/internal/app"
	"github.com/oxcafedead/passone/internal/cliputil"
	"github.com/oxcafedead/passone/internal/security"
	"github.com/oxcafedead/passone/internal/sshx"
)

// GUI wraps the core App for the desktop interface. It mirrors the CLI surface
// (list, show, copy, status...) so the frontend never touches internal/app.
type GUI struct {
	core *app.App
	mu   sync.Mutex
	ctx  context.Context
	// probed holds the key PrepareClone last saw for a host, keyed on
	// sshx.HostPortKey, so TrustHost can store the very key the user was shown
	// instead of asking the server a second time.
	probed map[string]ssh.PublicKey
}

// New boots the core application with the same data directory as the CLI
// (%LOCALAPPDATA%\PassOne unless PASSONE_DIR overrides it).
func New() (*GUI, error) {
	core, err := app.New()
	if err != nil {
		return nil, err
	}
	g := &GUI{core: core}
	core.OnLock(func() { g.emit("passone:locked", nil) })
	core.OnUnlock(func() { g.emit("passone:unlocked", nil) })
	cliputil.SetWarningFunc(g.clipboardWarning)
	return g, nil
}

// SetContext receives the Wails runtime context during startup; it enables the
// lock/unlock event stream delivered to the frontend.
func (g *GUI) SetContext(ctx context.Context) {
	g.mu.Lock()
	g.ctx = ctx
	g.mu.Unlock()
}

func (g *GUI) emit(name string, data any) {
	g.mu.Lock()
	ctx := g.ctx
	g.mu.Unlock()
	if ctx != nil {
		runtime.EventsEmit(ctx, name, data)
	}
}

// clipboardWarning surfaces a clipboard guarantee that could not be kept, above
// all a delayed clear that failed. It arrives long after the copy call returned,
// so there is no return value left to carry it and the frontend hears about it
// through the event stream instead.
func (g *GUI) clipboardWarning(msg string) {
	g.emit("passone:clipboard-warning", msg)
}

// IsUnlocked reports whether decrypted key material is in memory.
func (g *GUI) IsUnlocked() bool { return g.core.IsUnlocked() }

// Lock drops all decrypted keys from memory.
func (g *GUI) Lock() { g.core.Lock() }

// Unlock validates and loads the stored keys using the single mandatory lock
// password. Each key's own passphrase is recovered automatically from the
// sealed vault.
func (g *GUI) Unlock(lockPassword string) error {
	return g.core.Unlock([]byte(lockPassword))
}

// HasSSHKeyLoaded reports whether the SSH signer is in memory for transport.
func (g *GUI) HasSSHKeyLoaded() bool { return g.core.HasSSHKeyLoaded() }

// LoadSSHKey decrypts the stored SSH key into memory without starting an
// unlocked session. Used by onboarding to make cloning possible after a
// restart, before the user deliberately unlocks.
func (g *GUI) LoadSSHKey(lockPassword string) error {
	return g.core.LoadStoredSSHKey([]byte(lockPassword))
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

// ClipboardHistoryEnabled reports whether Windows is keeping a Clipboard History
// for this user, or may sync the clipboard to their other devices. PassOne marks
// its copies so Windows skips both, but it cannot force that: an unreadable
// setting is reported as enabled so the frontend keeps showing the caveat, and
// the copy is reported as not excluded when the marker itself did not go on.
func (g *GUI) ClipboardHistoryEnabled() bool {
	on, err := cliputil.HistoryEnabled()
	if err != nil {
		return true
	}
	return on
}

// copySecret writes a secret to the clipboard and warns the user when Windows
// could not be asked to keep it out of Clipboard History.
func (g *GUI) copySecret(text string) error {
	res, err := cliputil.Copied(text, g.core.Config().ClipboardClearSeconds)
	if err != nil {
		return fmt.Errorf("unable to write to the Windows clipboard: %w", err)
	}
	if caveat := res.Caveat(); caveat != "" {
		g.clipboardWarning(caveat)
	}
	return nil
}

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

// CopyPassword writes the first line of an entry to the Windows clipboard,
// marked so Clipboard History and the cloud clipboard skip it, and schedules
// clearing it, mirroring the CLI 'copy' behaviour. The secret is never returned
// to the frontend.
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
	return g.copySecret(text)
}

// CopyTOTP generates the current TOTP code for the named entry and copies it
// to the Windows clipboard. The entry must contain an otpauth:// URI in its
// body (pass-otp convention).
func (g *GUI) CopyTOTP(name string) (string, error) {
	code, err := g.core.ShowTOTP(name)
	if err != nil {
		return "", err
	}
	if err := g.copySecret(code); err != nil {
		return "", err
	}
	return code, nil
}

// HasTOTP decrypts the named entry and reports whether it contains an
// otpauth:// URI. It is used to surface the TOTP action before the entry's
// content is shown; no plaintext reaches the frontend.
func (g *GUI) HasTOTP(name string) (bool, error) {
	return g.core.HasTOTP(name)
}

// UsernameSource returns the configured login extraction mode
// (auto, body or filename).
func (g *GUI) UsernameSource() string { return g.core.UsernameSource() }

// SetUsernameSource persists the login extraction mode (auto, body, filename).
func (g *GUI) SetUsernameSource(mode string) error {
	return g.core.SetUsernameSource(strings.TrimSpace(mode))
}

// Username decrypts the named entry and returns its login per the configured
// username source. An entry without a recognizable login yields the empty
// string; the plaintext is never returned.
func (g *GUI) Username(name string) (string, error) {
	return g.core.Username(name)
}

// CopyUsername extracts the entry's login and writes it to the Windows
// clipboard with the configured auto-clear, mirroring CopyPassword. An entry
// without a recognizable login is reported as an error.
func (g *GUI) CopyUsername(name string) error {
	user, err := g.core.Username(name)
	if err != nil {
		return err
	}
	if user == "" {
		return fmt.Errorf("no username found for %s (check the entry body or its file name)", name)
	}
	return g.copySecret(user)
}

// CreatePassword adds a new entry from a form. The name becomes the first
// plaintext structure (first line password, optional body below). The secret
// never leaves the Go process beyond the encrypted .gpg file.
func (g *GUI) CreatePassword(name, password, confirm, body string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("enter a password path")
	}
	if strings.HasSuffix(name, "/") || strings.HasSuffix(name, "\\") {
		return "", errors.New("password path cannot end with a slash")
	}
	if password == "" {
		return "", errors.New("enter a password")
	}
	if strings.ContainsAny(password, "\r\n") {
		return "", errors.New("password cannot contain newlines")
	}
	if password != confirm {
		return "", errors.New("passwords do not match")
	}
	exists, err := g.core.PasswordExists(name)
	if err != nil {
		return "", err
	}
	if exists {
		return "", fmt.Errorf("already exists: %s (use edit instead)", name)
	}
	content := password + "\n" + body
	packed := []byte(content)
	defer security.Zero(packed)
	if err := g.core.SetPassword(name, packed, false); err != nil {
		return "", err
	}
	return "Created " + name, nil
}

// UpdatePassword edits an existing entry. With keepPassword set the stored
// first line is preserved and password is ignored (it may be empty); otherwise
// password replaces it. An empty body is ambiguous with "keep current notes",
// so a fully empty body always means "do not touch anything".
func (g *GUI) UpdatePassword(name, password, body string, keepPassword bool) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("enter a password path")
	}
	if !keepPassword {
		if password == "" {
			return "", errors.New("enter a new password or keep the existing one")
		}
		if strings.ContainsAny(password, "\r\n") {
			return "", errors.New("password cannot contain newlines")
		}
	}
	exists, err := g.core.PasswordExists(name)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("password not found: %s (use add to create it)", name)
	}
	if keepPassword && body == "" {
		return "No changes to " + name, nil
	}
	content := password + "\n" + body
	packed := []byte(content)
	defer security.Zero(packed)
	if err := g.core.SetPassword(name, packed, keepPassword); err != nil {
		return "", err
	}
	return "Saved " + name, nil
}

// RemovePassword deletes a named entry. It decrypts nothing.
func (g *GUI) RemovePassword(name string) error {
	return g.core.RemovePassword(strings.TrimSpace(name))
}

// Picked is the result of a native file/directory dialog.
type Picked struct {
	Path     string `json:"path"`
	Canceled bool   `json:"canceled"`
}

// PickPrivateKey opens a file dialog for a private key file. Canceled is true
// when the user dismissed the dialog without choosing anything.
func (g *GUI) PickPrivateKey(title string) (Picked, error) {
	ctx := g.ctxOrNil()
	if ctx == nil {
		return Picked{}, errors.New("window runtime is not ready")
	}
	if title == "" {
		title = "Select a private key file"
	}
	path, err := runtime.OpenFileDialog(ctx, runtime.OpenDialogOptions{
		Title: title,
		Filters: []runtime.FileFilter{
			{DisplayName: "Key files", Pattern: "*.asc;*.gpg;*.key;*.pem;*"},
			{DisplayName: "All files", Pattern: "*.*"},
		},
	})
	if err != nil {
		return Picked{}, err
	}
	if path == "" {
		return Picked{Canceled: true}, nil
	}
	return Picked{Path: path}, nil
}

// PickStoreDir opens a directory dialog for a password store.
func (g *GUI) PickStoreDir() (Picked, error) {
	ctx := g.ctxOrNil()
	if ctx == nil {
		return Picked{}, errors.New("window runtime is not ready")
	}
	path, err := runtime.OpenDirectoryDialog(ctx, runtime.OpenDialogOptions{
		Title: "Select a password store directory",
	})
	if err != nil {
		return Picked{}, err
	}
	if path == "" {
		return Picked{Canceled: true}, nil
	}
	return Picked{Path: path}, nil
}

// ImportPGPKeyFile imports an on-disk ASCII-armored OpenPGP private key. The
// file bytes are wiped from memory after import. lockPassword seals the stored
// key (and every stored key) in the vault.
func (g *GUI) ImportPGPKeyFile(path, passphrase, lockPassword string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	defer security.Zero(data)
	infos, err := g.core.ImportPGPKey(data, []byte(passphrase), []byte(lockPassword))
	if err != nil {
		return "", err
	}
	if len(infos) == 0 {
		return "", errors.New("no usable OpenPGP private key found in file")
	}
	return fmt.Sprintf("Imported OpenPGP key %s", infos[0].Fingerprint), nil
}

// ImportSSHKeyFile imports an on-disk OpenSSH private key.
func (g *GUI) ImportSSHKeyFile(path, passphrase, lockPassword string) (string, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	defer security.Zero(pem)
	k, err := g.core.ImportSSHKey(pem, []byte(passphrase), []byte(lockPassword))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Imported SSH key %s / %s", k.Algorithm(), k.Fingerprint()), nil
}

// OpenLocalStore validates a local pass store directory and records it as the
// active store.
func (g *GUI) OpenLocalStore(path string) error {
	return g.core.OpenLocalStore(strings.TrimSpace(path))
}

// StoredStores lists local pass stores under the app stores directory.
func (g *GUI) StoredStores() []string { return g.core.StoredStores() }

// ClonePrep is the outcome of probing an SSH git URL before cloning.
type ClonePrep struct {
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
	Known       bool   `json:"known"`
}

// PrepareClone captures the server host key of a git SSH URL and reports
// whether it is already trusted. It never touches the store. The captured key
// is remembered until the next probe of the same host so TrustHost can store
// the key this fingerprint belongs to.
func (g *GUI) PrepareClone(url string) (ClonePrep, error) {
	hostport, err := g.core.CloneHostport(strings.TrimSpace(url))
	if err != nil {
		return ClonePrep{}, err
	}
	pub, known, err := g.core.HostCheck(hostport)
	if err != nil {
		if errors.Is(err, sshx.ErrHostKeyChanged) {
			return ClonePrep{}, fmt.Errorf("possible man-in-the-middle on %s, not trusting automatically: %w", sshx.NormalizeHost(hostport), err)
		}
		return ClonePrep{}, err
	}
	g.rememberProbed(hostport, pub)
	return ClonePrep{
		Host:        hostport,
		Fingerprint: sshx.HostKeyFingerprint(pub),
		Known:       known,
	}, nil
}

// TrustHost records the host key that PrepareClone put on screen. It must not
// probe the host again: a second connection can be answered with a different
// key than the one the user confirmed, and that key is the one that would be
// written to known_hosts.
func (g *GUI) TrustHost(hostport string) error {
	key, ok := g.probedKey(hostport)
	if !ok {
		return fmt.Errorf("no host key confirmed for %s; check the host key first", sshx.NormalizeHost(hostport))
	}
	return g.core.TrustHost(hostport, key)
}

func (g *GUI) rememberProbed(hostport string, key ssh.PublicKey) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.probed == nil {
		g.probed = make(map[string]ssh.PublicKey)
	}
	g.probed[sshx.HostPortKey(hostport)] = key
}

func (g *GUI) probedKey(hostport string) (ssh.PublicKey, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	key, ok := g.probed[sshx.HostPortKey(hostport)]
	return key, ok
}

// CloneStore clones an SSH git URL into dir (auto-derived when empty) and
// opens the result as the active store. The host must be trusted first.
func (g *GUI) CloneStore(url, dir string) error {
	return g.core.CloneStore(strings.TrimSpace(url), strings.TrimSpace(dir))
}

// SettingsInfo describes the current environment for the setup screen.
type SettingsInfo struct {
	DataDir               string `json:"dataDir"`
	StorePath             string `json:"storePath"`
	GitRemote             string `json:"gitRemote"`
	PGPKeyFingerprint     string `json:"pgpKeyFingerprint"`
	SSHKeyID              string `json:"sshKeyId"`
	AutoLockMinutes       int    `json:"autoLockMinutes"`
	ClipboardClearSeconds int    `json:"clipboardClearSeconds"`
	GitAuthorName         string `json:"gitAuthorName"`
	GitAuthorEmail        string `json:"gitAuthorEmail"`
	UsernameSource        string `json:"usernameSource"`
	HasPGP                bool   `json:"hasPgp"`
	HasSSH                bool   `json:"hasSsh"`
}

// CurrentSettings returns a snapshot of the current configuration.
func (g *GUI) CurrentSettings() SettingsInfo {
	cfg := g.core.Config()
	return SettingsInfo{
		DataDir:               g.core.DataDir(),
		StorePath:             cfg.StorePath,
		GitRemote:             g.core.StoreRemoteURL(),
		PGPKeyFingerprint:     cfg.PGPKeyFingerprint,
		SSHKeyID:              cfg.SSHKeyID,
		AutoLockMinutes:       cfg.AutoLockMinutes,
		ClipboardClearSeconds: cfg.ClipboardClearSeconds,
		GitAuthorName:         cfg.GitAuthorName,
		GitAuthorEmail:        cfg.GitAuthorEmail,
		UsernameSource:        cfg.UsernameSource,
		HasPGP:                g.core.HasStoredPGPKey(),
		HasSSH:                g.core.HasStoredSSHKey(),
	}
}

// SetAutoLock updates the idle auto-lock timeout (0 disables it).
func (g *GUI) SetAutoLock(minutes int) error { return g.core.SetAutoLock(minutes) }

// ChangeLockPassword replaces the lock password after verifying the current
// password, re-sealing the stored keys.
func (g *GUI) ChangeLockPassword(oldPassword, newPassword string) error {
	return g.core.ChangeLockPassword([]byte(oldPassword), []byte(newPassword))
}

// SetClipboardClear updates how long copied secrets stay on the clipboard.
func (g *GUI) SetClipboardClear(seconds int) error { return g.core.SetClipboardClear(seconds) }

// SetGitAuthor updates the identity used for git commits.
func (g *GUI) SetGitAuthor(name, email string) error {
	return g.core.SetGitAuthor(strings.TrimSpace(name), strings.TrimSpace(email))
}

// Status returns git status text for the active store.
func (g *GUI) Status() (string, error) { return g.core.Status() }

// Sync performs fetch → pull → push for the active store and returns a
// human-readable summary.
func (g *GUI) Sync() (string, error) { return g.core.Sync() }

// KnownHosts lists previously trusted SSH hosts with fingerprints.
func (g *GUI) KnownHosts() []string { return g.core.KnownHostsList() }

func (g *GUI) ctxOrNil() context.Context {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ctx
}
