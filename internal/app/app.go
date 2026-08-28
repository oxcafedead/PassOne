package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"golang.org/x/crypto/ssh"

	"github.com/oxcafedead/passone/internal/config"
	"github.com/oxcafedead/passone/internal/gitx"
	"github.com/oxcafedead/passone/internal/pgp"
	"github.com/oxcafedead/passone/internal/security"
	"github.com/oxcafedead/passone/internal/sshx"
	"github.com/oxcafedead/passone/internal/store"
)

// App coordinates the store, OpenPGP, SSH, Git and security subsystems.
type App struct {
	mu       sync.Mutex
	paths    config.Paths
	manager  *config.Manager
	cfg      *config.Config
	vault    *security.Vault
	known    *sshx.KnownHostsStore
	pgpSvc   *pgp.Service
	sshKey   *sshx.SSHKey
	store    *store.Store
	unlocked bool

	lastActivity time.Time
	stopTimer    chan struct{}

	lockHandlers   []func()
	unlockHandlers []func()
}

// ErrLocked is returned when an operation needs unlocked key material.
var ErrLocked = errors.New("the application is locked; run unlock first")

// New boots the application: resolves data paths, opens the vault and loads
// configuration. No key material is loaded until Unlock.
func New() (*App, error) {
	paths := config.ResolvePaths()
	m := config.NewManager(paths)
	if err := m.EnsureDirectories(); err != nil {
		return nil, err
	}
	cfg, err := m.Load()
	if err != nil {
		return nil, err
	}
	vault, err := security.OpenVault(paths)
	if err != nil {
		return nil, err
	}
	known, err := sshx.NewKnownHostsStore(paths.KnownHostsFile)
	if err != nil {
		return nil, err
	}
	return &App{
		paths:   paths,
		manager: m,
		cfg:     cfg,
		vault:   vault,
		known:   known,
		pgpSvc:  pgp.New(),
	}, nil
}

// Config returns a copy of the current configuration.
func (a *App) Config() *config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := *a.cfg
	return &c
}

func (a *App) saveConfig() error {
	a.mu.Lock()
	c := *a.cfg
	a.mu.Unlock()
	return a.manager.Save(&c)
}

// DataDir returns the application data directory.
func (a *App) DataDir() string { return a.paths.Base }

// HasStoredPGPKey reports whether a secret OpenPGP key was imported.
func (a *App) HasStoredPGPKey() bool { return fileExists(a.paths.PGPKeyFile) }

// HasStoredSSHKey reports whether an SSH private key was imported.
func (a *App) HasStoredSSHKey() bool { return fileExists(a.paths.SSHKeyFile) }

// IsUnlocked reports whether decrypted key material is in memory.
func (a *App) IsUnlocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.unlocked
}

// PGPKeyFingerprint returns the configured primary fingerprint.
func (a *App) PGPKeyFingerprint() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.PGPKeyFingerprint
}

// SSHKeyID returns the configured SSH key identifier.
func (a *App) SSHKeyID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.SSHKeyID
}

// ImportPGPKey imports an armored secret OpenPGP key. The passphrase is
// validated; only the original (still passphrase-protected) armored block is
// stored locally, sealed by the vault.
func (a *App) ImportPGPKey(block, passphrase []byte) ([]*pgp.KeyInfo, error) {
	infos, err := a.pgpSvc.ImportSecret(block, passphrase)
	if err != nil {
		return nil, err
	}
	if err := a.vault.Store(a.paths.PGPKeyFile, block); err != nil {
		return nil, fmt.Errorf("unable to store the OpenPGP key locally: %v", err)
	}
	a.mu.Lock()
	a.cfg.PGPKeyFingerprint = infos[0].Fingerprint
	a.unlocked = true
	a.touchLocked()
	a.mu.Unlock()
	if err := a.saveConfig(); err != nil {
		return nil, err
	}
	a.startAutoLock()
	a.notifyUnlocked()
	return infos, nil
}

// ImportSSHKey imports an OpenSSH private key. The original file bytes (still
// encrypted with their passphrase) are stored locally, sealed by the vault.
func (a *App) ImportSSHKey(pem, passphrase []byte) (*sshx.SSHKey, error) {
	k, err := sshx.ImportPrivateKey(pem, passphrase)
	if err != nil {
		return nil, err
	}
	if err := a.vault.Store(a.paths.SSHKeyFile, pem); err != nil {
		return nil, fmt.Errorf("unable to store the SSH key locally: %v", err)
	}
	a.mu.Lock()
	a.sshKey = k
	a.cfg.SSHKeyID = k.Fingerprint()
	a.unlocked = true
	a.touchLocked()
	a.mu.Unlock()
	if err := a.saveConfig(); err != nil {
		return nil, err
	}
	a.startAutoLock()
	a.notifyUnlocked()
	return k, nil
}

// Unlock loads and decrypts the stored keys into memory. Each key's passphrase
// is validated at this point. Nil passphrases are treated as empty.
func (a *App) Unlock(pgpPass, sshPass []byte) error {
	a.mu.Lock()
	if err := a.unlockPGPLocked(pgpPass); err != nil {
		a.mu.Unlock()
		return err
	}
	if err := a.unlockSSHLocked(sshPass); err != nil {
		a.mu.Unlock()
		return err
	}
	if err := a.validateStoreLocked(); err != nil {
		a.mu.Unlock()
		return err
	}
	a.finalizeUnlockLocked()
	a.mu.Unlock()
	a.startAutoLock()
	a.notifyUnlocked()
	return nil
}

// UnlockPGP unlocks only the stored OpenPGP key. No SSH key is loaded; remote
// git operations will fail until UnlockSSH is called.
func (a *App) UnlockPGP(pgpPass []byte) error {
	a.mu.Lock()
	if err := a.unlockPGPLocked(pgpPass); err != nil {
		a.mu.Unlock()
		return err
	}
	if err := a.validateStoreLocked(); err != nil {
		a.mu.Unlock()
		return err
	}
	a.finalizeUnlockLocked()
	a.mu.Unlock()
	a.startAutoLock()
	a.notifyUnlocked()
	return nil
}

// UnlockSSH unlocks only the stored SSH key.
func (a *App) UnlockSSH(sshPass []byte) error {
	a.mu.Lock()
	if err := a.unlockSSHLocked(sshPass); err != nil {
		a.mu.Unlock()
		return err
	}
	a.finalizeUnlockLocked()
	a.mu.Unlock()
	a.startAutoLock()
	a.notifyUnlocked()
	return nil
}

func (a *App) unlockPGPLocked(pgpPass []byte) error {
	if !a.HasStoredPGPKey() {
		return nil
	}
	armored, err := a.vault.LoadSealed(a.paths.PGPKeyFile)
	if err != nil {
		return fmt.Errorf("unable to read the stored OpenPGP key: %v", err)
	}
	defer security.Zero(armored)
	return a.pgpSvc.Unlock(armored, pgpPass)
}

func (a *App) unlockSSHLocked(sshPass []byte) error {
	if !a.HasStoredSSHKey() {
		return nil
	}
	pem, err := a.vault.LoadSealed(a.paths.SSHKeyFile)
	if err != nil {
		return fmt.Errorf("unable to read the stored SSH key: %v", err)
	}
	defer security.Zero(pem)
	k, err := sshx.ImportPrivateKey(pem, sshPass)
	if err != nil {
		return err
	}
	a.sshKey = k
	return nil
}

// validateStoreLocked opens the configured store and checks that the loaded
// OpenPGP key can decrypt its recipients. Callers must hold a.mu.
func (a *App) validateStoreLocked() error {
	if a.cfg.StorePath == "" {
		return nil
	}
	if err := a.openConfiguredStoreLocked(); err != nil {
		return fmt.Errorf("unable to open the configured store: %v", err)
	}
	st := a.store
	if len(a.pgpSvc.DescribeOwn()) == 0 {
		return errors.New("no OpenPGP key is imported; unable to decrypt this store")
	}
	if _, err := a.pgpSvc.ResolveRecipients(st.GPGIDs()); err != nil {
		return fmt.Errorf("the stored OpenPGP key cannot decrypt this store: %w", err)
	}
	return nil
}

// finalizeUnlockLocked marks the session unlocked and refreshes the idle timer.
func (a *App) finalizeUnlockLocked() {
	a.unlocked = true
	a.touchLocked()
}

// HasSSHKeyLoaded reports whether an SSH key is currently decrypted in memory.
func (a *App) HasSSHKeyLoaded() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sshKey != nil
}

// Lock drops all decrypted key material, passphrases and password data from
// memory (best effort).
func (a *App) Lock() {
	a.mu.Lock()
	if a.stopTimer != nil {
		close(a.stopTimer)
		a.stopTimer = nil
	}
	a.lockLocked()
	a.mu.Unlock()
	a.notifyLocked()
}

// OnLock registers fn to be invoked every time the app transitions to the
// locked state, either through Lock or the idle auto-lock (including the lazy
// lock performed at the start of an operation on an expired session). Handlers
// run on their own goroutines and must not call back into Lock.
func (a *App) OnLock(fn func()) {
	a.mu.Lock()
	a.lockHandlers = append(a.lockHandlers, fn)
	a.mu.Unlock()
}

// OnUnlock registers fn to be invoked whenever a session becomes unlocked.
// See OnLock for handler semantics.
func (a *App) OnUnlock(fn func()) {
	a.mu.Lock()
	a.unlockHandlers = append(a.unlockHandlers, fn)
	a.mu.Unlock()
}

// notifyLocked runs the registered lock handlers. Must be called without
// holding a.mu.
func (a *App) notifyLocked() {
	a.mu.Lock()
	hs := make([]func(), len(a.lockHandlers))
	copy(hs, a.lockHandlers)
	a.mu.Unlock()
	for _, h := range hs {
		go h()
	}
}

// notifyUnlocked runs the registered unlock handlers. Must be called without
// holding a.mu.
func (a *App) notifyUnlocked() {
	a.mu.Lock()
	hs := make([]func(), len(a.unlockHandlers))
	copy(hs, a.unlockHandlers)
	a.mu.Unlock()
	for _, h := range hs {
		go h()
	}
}

func (a *App) lockLocked() {
	a.pgpSvc.Lock()
	if a.sshKey != nil {
		a.sshKey.Lock()
	}
	a.sshKey = nil
	a.store = nil
	a.unlocked = false
}

func (a *App) touchLocked() {
	a.lastActivity = time.Now()
}

// requireUnlocked checks the lock state, enforcing the idle timeout.
func (a *App) requireUnlocked() error {
	a.mu.Lock()
	if !a.unlocked {
		a.mu.Unlock()
		return ErrLocked
	}
	timeout := time.Duration(a.cfg.AutoLockMinutes) * time.Minute
	idleLocked := false
	if timeout > 0 && time.Since(a.lastActivity) > timeout {
		a.lockLocked()
		idleLocked = true
	}
	a.touchLocked()
	a.mu.Unlock()
	if idleLocked {
		a.notifyLocked()
		return ErrLocked
	}
	return nil
}

// touch marks activity; it auto-locks if the timeout elapsed.
func (a *App) touch() error {
	return a.requireUnlocked()
}

// startAutoLock uses the configured timeout.
func (a *App) startAutoLock() {
	a.mu.Lock()
	timeout := time.Duration(a.cfg.AutoLockMinutes) * time.Minute
	a.mu.Unlock()
	a.startAutoLockWithTimeout(timeout)
}

func (a *App) startAutoLockWithTimeout(timeout time.Duration) {
	a.mu.Lock()
	if a.stopTimer != nil {
		close(a.stopTimer)
	}
	stop := make(chan struct{})
	a.stopTimer = stop
	a.mu.Unlock()

	if timeout <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				a.mu.Lock()
				expired := a.unlocked && time.Since(a.lastActivity) > timeout
				a.mu.Unlock()
				if expired {
					a.Lock()
					return
				}
			}
		}
	}()
}

// ListPasswords lists all password paths (no decryption requires unlocking).
func (a *App) ListPasswords() ([]string, error) {
	if err := a.ensureStoreOpen(); err != nil {
		return nil, err
	}
	st := a.storePath()
	return st.ListPasswords()
}

// ensureStoreOpen lazily opens the configured store if not already open. The
// store can be opened in-memory without unlocking keys, so listing works
// without revealing any secret material.
func (a *App) ensureStoreOpen() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.store != nil {
		return nil
	}
	return a.openConfiguredStoreLocked()
}

// openConfiguredStoreLocked opens a.store from cfg.StorePath. Callers must hold
// a.mu.
func (a *App) openConfiguredStoreLocked() error {
	if a.cfg.StorePath == "" {
		return errors.New("no password store is open; use 'open' or 'clone' first")
	}
	st, err := store.Open(a.cfg.StorePath)
	if err != nil {
		return fmt.Errorf("unable to open the configured store at %s: %v", a.cfg.StorePath, err)
	}
	a.store = st
	return nil
}

// ShowPassword decrypts and returns the full plaintext of a password file.
func (a *App) ShowPassword(name string) ([]byte, error) {
	if err := a.requireUnlocked(); err != nil {
		return nil, err
	}
	st := a.storePath()
	if st == nil {
		return nil, errors.New("no password store is open; use 'open' or 'clone' first")
	}
	ciphertext, err := st.Read(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("password not found: %s", name)
		}
		return nil, fmt.Errorf("unable to read %s: %v", name, err)
	}
	defer security.Zero(ciphertext)
	a.mu.Lock()
	plaintext, err := a.pgpSvc.Decrypt(ciphertext)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// SavePassword encrypts new plaintext and atomically replaces the password
// file. The original file is only replaced after encryption succeeds.
func (a *App) SavePassword(name string, plaintext []byte) error {
	if err := a.requireUnlocked(); err != nil {
		return err
	}
	st := a.storePath()
	if st == nil {
		return errors.New("no password store is open; use 'open' or 'clone' first")
	}
	a.mu.Lock()
	recipients, err := a.pgpSvc.ResolveRecipients(st.GPGIDs())
	a.mu.Unlock()
	if err != nil {
		return err
	}
	ciphertext, err := pgp.Encrypt(plaintext, recipients)
	if err != nil {
		return err
	}
	defer security.Zero(ciphertext)
	return st.WriteEncrypted(name, ciphertext)
}

// CommitPassword stages and commits the named password file. The push must be
// requested explicitly (see Sync).
func (a *App) CommitPassword(name string) error {
	if err := a.requireUnlocked(); err != nil {
		return err
	}
	st := a.storePath()
	if st == nil {
		return errors.New("no password store open")
	}
	if !isGitRepo(st.Root()) {
		return errors.New("the store is not a git repository; nothing to commit")
	}
	msg := "Update " + name
	if err := gitx.Add(st.Root(), name+".gpg"); err != nil {
		return err
	}
	if _, err := gitx.Commit(st.Root(), msg, a.cfg.GitAuthorName, a.cfg.GitAuthorEmail); err != nil {
		if errors.Is(err, gitx.ErrUpToDate) {
			return nil
		}
		return err
	}
	return nil
}

func (a *App) storePath() *store.Store {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.store
}

// SSHPublicKey returns the imported public key in authorized_keys format.
func (a *App) SSHPublicKey() ([]byte, error) {
	if err := a.requireUnlocked(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sshKey == nil {
		return nil, errors.New("no SSH key imported")
	}
	return a.sshKey.PublicAuthorizedKey(), nil
}

// HostCheck captures the server host key and reports whether it is known.
// On first contact the key is returned with known=false for user confirmation.
func (a *App) HostCheck(hostport string) (ssh.PublicKey, bool, error) {
	pub, err := sshx.CaptureHostKey(hostport)
	if err != nil {
		return nil, false, err
	}
	host := sshx.NormalizeHost(hostport)
	verifyErr := a.known.Verify(host, pub)
	if verifyErr == nil {
		return pub, true, nil
	}
	if errors.Is(verifyErr, sshx.ErrHostKeyChanged) {
		return pub, false, verifyErr
	}
	return pub, false, nil
}

// TrustHost records the user-approved host key.
func (a *App) TrustHost(hostport string, key ssh.PublicKey) error {
	return a.known.Add(sshx.NormalizeHost(hostport), key)
}

// KnownHostsList lists trusted hosts with fingerprints.
func (a *App) KnownHostsList() []string { return a.known.List() }

// TestSSH verifies the host key and authenticates to hostport.
func (a *App) TestSSH(hostport string) error {
	if err := a.requireUnlocked(); err != nil {
		return err
	}
	a.mu.Lock()
	k := a.sshKey
	a.mu.Unlock()
	if k == nil {
		return errors.New("no SSH key imported")
	}
	return sshx.TestConnection("git", hostport, k.Signer(), a.known.Callback())
}

// OpenLocalStore validates a local pass store directory and records it.
func (a *App) OpenLocalStore(dir string) error {
	st, err := store.Open(dir)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.unlocked && len(a.pgpSvc.DescribeOwn()) > 0 {
		if _, err := a.pgpSvc.ResolveRecipients(st.GPGIDs()); err != nil {
			a.mu.Unlock()
			return err
		}
	}
	a.store = st
	a.cfg.StorePath = st.Root()
	a.mu.Unlock()
	return a.saveConfig()
}

// CloneStore implements first-run Flow B: verify host, clone, open, validate.
// The host key must have been confirmed already (see TrustHost).
func (a *App) CloneStore(url, dir string) error {
	if dir == "" {
		dir = a.defaultCloneDir(url)
	}
	host := gitHostFromURL(url)
	if host == "" {
		return fmt.Errorf("cannot determine SSH host from %q", url)
	}
	hostport := host + ":22"

	if err := a.requireUnlocked(); err != nil {
		return err
	}
	if a.sshKeyOrNil() == nil {
		return errors.New("no SSH key imported; import an SSH private key first")
	}

	// Host key verification: capture and compare with our known_hosts store.
	known, verifyErr := knownHostTrusted(a.known, hostport)
	if errors.Is(verifyErr, sshx.ErrHostKeyChanged) {
		return fmt.Errorf("SSH host key changed for %s; refusing to connect", host)
	}
	if verifyErr != nil || !known {
		return fmt.Errorf("host key for %s is not yet trusted; run 'test-ssh %s' first and confirm the fingerprint", host, host)
	}

	if err := gitx.Clone(url, dir, a.sshAuth()); err != nil {
		return err
	}

	st, err := store.Open(dir)
	if err != nil {
		return fmt.Errorf("cloned repository is not a pass store: %w", err)
	}
	a.mu.Lock()
	if _, err := a.pgpSvc.ResolveRecipients(st.GPGIDs()); err != nil {
		a.mu.Unlock()
		return err
	}
	a.store = st
	a.cfg.StorePath = st.Root()
	a.cfg.GitRemote = url
	a.mu.Unlock()
	return a.saveConfig()
}

// sshAuth builds the go-git SSH auth method from the unlocked key.
func (a *App) sshAuth() transport.AuthMethod {
	a.mu.Lock()
	defer a.mu.Unlock()
	return gitx.PublicKeys("git", a.sshKey, a.known.Callback())
}

func (a *App) sshKeyOrNil() *sshx.SSHKey {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sshKey
}

// Sync fetches, merges and pushes: fetch → pull/merge → push. Diverged
// histories are reported as a conflict and never silently overwritten.
func (a *App) Sync() error {
	if err := a.requireUnlocked(); err != nil {
		return err
	}
	if err := a.ensureStoreOpen(); err != nil {
		return err
	}
	st := a.storePath()
	if st == nil {
		return errors.New("no password store open")
	}
	if a.sshKeyOrNil() == nil {
		return errors.New("no SSH key imported; unable to sync over SSH")
	}
	auth := a.sshAuth()
	root := st.Root()

	fetchErr := gitx.Fetch(root, auth)
	if fetchErr != nil && !errors.Is(fetchErr, gitx.ErrUpToDate) {
		return fetchErr
	}
	pullErr := gitx.Pull(root, auth)
	if pullErr != nil && !errors.Is(pullErr, gitx.ErrUpToDate) {
		return pullErr
	}
	pushErr := gitx.Push(root, auth)
	if pushErr != nil && !errors.Is(pushErr, gitx.ErrUpToDate) {
		return pushErr
	}
	return nil
}

// Status returns git status text for the store.
func (a *App) Status() (string, error) {
	if err := a.ensureStoreOpen(); err != nil {
		return "", err
	}
	st := a.storePath()
	if st == nil {
		return "", errors.New("no password store open")
	}
	return gitx.Status(st.Root())
}

// PGPKeyNeedsPassphrase reports whether the stored PGP key is passphrase-protected.
func (a *App) PGPKeyNeedsPassphrase() (bool, error) {
	if !a.HasStoredPGPKey() {
		return false, nil
	}
	armored, err := a.vault.LoadSealed(a.paths.PGPKeyFile)
	if err != nil {
		return false, err
	}
	defer security.Zero(armored)
	return pgp.BlockRequiresPassphrase(armored)
}

// SSHKeyNeedsPassphrase reports whether the stored SSH key is encrypted.
func (a *App) SSHKeyNeedsPassphrase() (bool, error) {
	if !a.HasStoredSSHKey() {
		return false, nil
	}
	pem, err := a.vault.LoadSealed(a.paths.SSHKeyFile)
	if err != nil {
		return false, err
	}
	defer security.Zero(pem)
	return sshx.PrivateKeyRequiresPassphrase(pem)
}

// SetGitAuthor persists the author identity used for commits.
func (a *App) SetGitAuthor(name, email string) error {
	a.mu.Lock()
	a.cfg.GitAuthorName = name
	a.cfg.GitAuthorEmail = email
	a.mu.Unlock()
	return a.saveConfig()
}

func (a *App) defaultCloneDir(url string) string {
	s := url
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSuffix(s, ".git")
	s = strings.ReplaceAll(s, "/", "-")
	return filepath.Join(a.paths.StoresDir, s)
}

var scpLike = regexp.MustCompile(`^([^@]+)@([^:]+):(.+)$`)

func gitHostFromURL(url string) string {
	if m := scpLike.FindStringSubmatch(url); m != nil {
		return m[2]
	}
	s := strings.TrimPrefix(url, "ssh://")
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

func knownHostTrusted(known *sshx.KnownHostsStore, hostport string) (bool, error) {
	pub, err := sshx.CaptureHostKey(hostport)
	if err != nil {
		return false, err
	}
	host := sshx.NormalizeHost(hostport)
	verifyErr := known.Verify(host, pub)
	if verifyErr == nil {
		return true, nil
	}
	return false, verifyErr
}

func isGitRepo(dir string) bool {
	_, err := gitx.Open(dir)
	return err == nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
