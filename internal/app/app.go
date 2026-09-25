package app

import (
	"crypto/subtle"
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
	"github.com/oxcafedead/passone/internal/totp"
	"github.com/oxcafedead/passone/internal/username"
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

	keyDisk []byte

	lastActivity time.Time
	stopTimer    chan struct{}

	lockHandlers   []func()
	unlockHandlers []func()
}

// ErrLocked is returned when an operation needs unlocked key material.
var ErrLocked = errors.New("the application is locked; run unlock first")

// ErrSplitVault reports that the stored key blobs are not all sealed under
// the same lock password, which is the state an interrupted lock password
// change leaves behind: one blob published under the new key while the other
// is still under the old one. No key material is lost, but no single password
// opens the whole vault either, so the user has to try both.
var ErrSplitVault = errors.New("the stored keys are sealed under different lock passwords")

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

// StorePath returns the currently configured store directory.
func (a *App) StorePath() string {
	return a.cfg.StorePath
}

// StoredStores lists local pass stores found under the app stores directory,
// e.g. repositories that were cloned once but never recorded in the config.
func (a *App) StoredStores() []string {
	entries, err := os.ReadDir(a.paths.StoresDir)
	if err != nil {
		return []string{}
	}
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(a.paths.StoresDir, e.Name())
		if _, err := store.Open(dir); err == nil {
			out = append(out, dir)
		}
	}
	return out
}

// ImportPGPKey imports an armored secret OpenPGP key. The key's own passphrase
// (keyPassphrase, which may be empty for unarmored keys) is validated; the
// original armored block plus that passphrase are stored locally, sealed by the
// vault using key_disk = KDF(lockPassword). lockPassword is mandatory and
// non-empty so every stored key is always protected, even when the key itself
// has an empty passphrase. Importing does not start an unlocked session: local
// secrets stay gated on an explicit Unlock. The decrypted entities are still
// resident afterwards, so the idle auto-lock is armed to drop them.
func (a *App) ImportPGPKey(block, keyPassphrase, lockPassword []byte) ([]*pgp.KeyInfo, error) {
	if len(lockPassword) == 0 {
		return nil, errors.New("a non-empty lock password is required to import a key")
	}
	infos, err := a.pgpSvc.ImportSecret(block, keyPassphrase)
	if err != nil {
		return nil, err
	}
	key, err := a.verifyImportLockLocked(lockPassword)
	if err != nil {
		return nil, err
	}
	defer security.Zero(key)
	payload, err := packKeyMaterial(keyPassphrase, block)
	if err != nil {
		return nil, err
	}
	defer security.Zero(payload)
	if err := a.vault.Store(key, a.paths.PGPKeyFile, payload); err != nil {
		return nil, fmt.Errorf("unable to store the OpenPGP key locally: %v", err)
	}
	a.mu.Lock()
	a.cfg.PGPKeyFingerprint = infos[0].Fingerprint
	a.mu.Unlock()
	a.noteKeyMaterialResident()
	if err := a.saveConfig(); err != nil {
		return nil, err
	}
	return infos, nil
}

// ImportSSHKey imports an OpenSSH private key. The original file bytes (still
// encrypted with their own keyPassphrase, which may be empty) plus that
// passphrase are stored locally, sealed by the vault using
// key_disk = KDF(lockPassword). The decrypted signer is kept in memory so
// transport operations (clone) work without a full session unlock, but the
// session itself stays locked and the idle auto-lock is armed to drop the
// signer again.
func (a *App) ImportSSHKey(pem, keyPassphrase, lockPassword []byte) (*sshx.SSHKey, error) {
	if len(lockPassword) == 0 {
		return nil, errors.New("a non-empty lock password is required to import a key")
	}
	k, err := sshx.ImportPrivateKey(pem, keyPassphrase)
	if err != nil {
		return nil, err
	}
	key, err := a.verifyImportLockLocked(lockPassword)
	if err != nil {
		return nil, err
	}
	defer security.Zero(key)
	payload, err := packKeyMaterial(keyPassphrase, pem)
	if err != nil {
		return nil, err
	}
	defer security.Zero(payload)
	if err := a.vault.Store(key, a.paths.SSHKeyFile, payload); err != nil {
		return nil, fmt.Errorf("unable to store the SSH key locally: %v", err)
	}
	a.mu.Lock()
	a.sshKey = k
	a.cfg.SSHKeyID = k.Fingerprint()
	a.mu.Unlock()
	a.noteKeyMaterialResident()
	if err := a.saveConfig(); err != nil {
		return nil, err
	}
	return k, nil
}

// Unlock loads and decrypts the stored keys into memory using the single
// mandatory lock password. Unlocking with the correct lock password
// automatically recovers each key's own passphrase (stored inside the sealed
// blob), so the user types one password regardless of how the individual keys
// are protected.
func (a *App) Unlock(lockPassword []byte) error {
	if len(lockPassword) == 0 {
		return errors.New("a non-empty lock password is required to unlock")
	}
	a.mu.Lock()
	if err := a.unlockPGPLocked(lockPassword); err != nil {
		a.mu.Unlock()
		return err
	}
	if err := a.unlockSSHLocked(lockPassword); err != nil {
		a.mu.Unlock()
		return err
	}
	if err := a.validateStoreLocked(); err != nil {
		a.mu.Unlock()
		return err
	}
	a.finalizeUnlockLocked()
	a.mu.Unlock()
	a.noteKeyMaterialResident()
	a.notifyUnlocked()
	return nil
}

// UnlockPGP unlocks only the stored OpenPGP key using the lock password.
func (a *App) UnlockPGP(lockPassword []byte) error {
	if len(lockPassword) == 0 {
		return errors.New("a non-empty lock password is required to unlock")
	}
	a.mu.Lock()
	if err := a.unlockPGPLocked(lockPassword); err != nil {
		a.mu.Unlock()
		return err
	}
	if err := a.validateStoreLocked(); err != nil {
		a.mu.Unlock()
		return err
	}
	a.finalizeUnlockLocked()
	a.mu.Unlock()
	a.noteKeyMaterialResident()
	a.notifyUnlocked()
	return nil
}

// UnlockSSH unlocks only the stored SSH key using the lock password.
func (a *App) UnlockSSH(lockPassword []byte) error {
	if len(lockPassword) == 0 {
		return errors.New("a non-empty lock password is required to unlock")
	}
	a.mu.Lock()
	if err := a.unlockSSHLocked(lockPassword); err != nil {
		a.mu.Unlock()
		return err
	}
	a.finalizeUnlockLocked()
	a.mu.Unlock()
	a.noteKeyMaterialResident()
	a.notifyUnlocked()
	return nil
}

// LoadStoredSSHKey decrypts the stored SSH key into memory for transport
// operations (clone, sync) without starting an unlocked session. The session
// stays locked until an explicit Unlock, and the idle auto-lock is armed so
// the signer does not stay resident indefinitely.
func (a *App) LoadStoredSSHKey(lockPassword []byte) error {
	a.mu.Lock()
	if !a.HasStoredSSHKey() {
		a.mu.Unlock()
		return errors.New("no SSH key is stored; import one first")
	}
	if err := a.unlockSSHLocked(lockPassword); err != nil {
		a.mu.Unlock()
		return err
	}
	// Only the signer is needed for transport; the vault key that unlocked it
	// has no reader on this path, so it is wiped rather than kept for a
	// session that was never started.
	a.dropKeyDiskLocked()
	a.mu.Unlock()
	a.noteKeyMaterialResident()
	return nil
}

// storedKey is one sealed key file on disk.
type storedKey struct {
	name string
	path string
}

// storedKeys lists the sealed key blobs in the order an unlock, a re-key or an
// import check has to process them.
func (a *App) storedKeys() []storedKey {
	return []storedKey{
		{"OpenPGP", a.paths.PGPKeyFile},
		{"SSH", a.paths.SSHKeyFile},
	}
}

// splitVaultError reports the split-vault condition: the blob at failedPath
// does not open with the derived key while the other stored blob does. Without
// it the only symptom is one integrity error per attempt, and a user who has
// just changed their lock password concludes the vault is corrupt. It returns
// nil when there is no such asymmetry, leaving the caller to report the real
// failure, and never retains either plaintext.
func (a *App) splitVaultError(key []byte, failedName, failedPath string) error {
	for _, k := range a.storedKeys() {
		if k.path == failedPath || !fileExists(k.path) {
			continue
		}
		payload, err := a.vault.LoadSealed(key, k.path)
		if err != nil {
			continue
		}
		security.Zero(payload)
		return fmt.Errorf("%w: the stored %s key does not open with this lock password but the stored %s key does, so a lock password change was interrupted; use the lock password from before that change",
			ErrSplitVault, failedName, k.name)
	}
	return nil
}

func (a *App) unlockPGPLocked(lockPassword []byte) error {
	if !a.HasStoredPGPKey() {
		return nil
	}
	key, err := a.deriveKeyDisk(lockPassword)
	if err != nil {
		return err
	}
	defer security.Zero(key)
	payload, err := a.vault.LoadSealed(key, a.paths.PGPKeyFile)
	if err != nil {
		if split := a.splitVaultError(key, "OpenPGP", a.paths.PGPKeyFile); split != nil {
			return split
		}
		return fmt.Errorf("unable to read the stored OpenPGP key: %v", err)
	}
	defer security.Zero(payload)
	keyPass, armored, err := unpackKeyMaterial(payload)
	if err != nil {
		return fmt.Errorf("unable to read the stored OpenPGP key: %v", err)
	}
	defer security.Zero(keyPass)
	if err := a.pgpSvc.Unlock(armored, keyPass); err != nil {
		return err
	}
	a.setKeyDisk(key)
	return nil
}

func (a *App) unlockSSHLocked(lockPassword []byte) error {
	if !a.HasStoredSSHKey() {
		return nil
	}
	key, err := a.deriveKeyDisk(lockPassword)
	if err != nil {
		return err
	}
	defer security.Zero(key)
	payload, err := a.vault.LoadSealed(key, a.paths.SSHKeyFile)
	if err != nil {
		if split := a.splitVaultError(key, "SSH", a.paths.SSHKeyFile); split != nil {
			return split
		}
		return fmt.Errorf("unable to read the stored SSH key: %v", err)
	}
	defer security.Zero(payload)
	keyPass, pem, err := unpackKeyMaterial(payload)
	if err != nil {
		return fmt.Errorf("unable to read the stored SSH key: %v", err)
	}
	defer security.Zero(keyPass)
	k, err := sshx.ImportPrivateKey(pem, keyPass)
	if err != nil {
		return err
	}
	a.sshKey = k
	a.setKeyDisk(key)
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
	a.dropKeyDiskLocked()
}

// setKeyDisk stores a copy of the derived vault key in memory. The caller must
// still wipe the source; setKeyDisk retains its own copy for the session.
func (a *App) setKeyDisk(key []byte) {
	security.Zero(a.keyDisk)
	a.keyDisk = append(a.keyDisk[:0], key...)
}

// dropKeyDiskLocked wipes the retained vault key. Callers must hold a.mu. The
// key is only ever read by ChangeLockPassword, which requires an unlocked
// session, so paths that load key material purely for transport must not keep
// it around.
func (a *App) dropKeyDiskLocked() {
	security.Zero(a.keyDisk)
	a.keyDisk = nil
}

// deriveKeyDisk computes key_disk = Argon2id(passphrase, salt) using the
// on-disk vault salt. The returned key must be wiped by the caller.
func (a *App) deriveKeyDisk(passphrase []byte) ([]byte, error) {
	salt, err := a.vault.LoadOrCreateSalt()
	if err != nil {
		return nil, err
	}
	defer security.Zero(salt)
	return security.DeriveKey(passphrase, salt), nil
}

// verifyImportLockLocked confirms that the lock password supplied for an
// import derives the same key that already seals every stored key blob. This
// keeps the whole vault under a single lock password: without it, importing a
// key while typed under a different (e.g. previous) lock password would seal
// the new blob under another key and fragment the store. It returns the
// derived key, which the caller must wipe. Stored blobs are only decrypted to
// authenticate the password, never retained.
func (a *App) verifyImportLockLocked(lockPassword []byte) ([]byte, error) {
	key, err := a.deriveKeyDisk(lockPassword)
	if err != nil {
		return nil, err
	}
	for _, k := range a.storedKeys() {
		if !fileExists(k.path) {
			continue
		}
		payload, err := a.vault.LoadSealed(key, k.path)
		security.Zero(payload)
		if err != nil {
			if split := a.splitVaultError(key, k.name, k.path); split != nil {
				security.Zero(key)
				return nil, split
			}
			security.Zero(key)
			return nil, errors.New("the lock password does not match the key already stored; import under the current lock password")
		}
	}
	return key, nil
}

// packKeyMaterial encodes a key's own passphrase together with its (still
// passphrase-encrypted) material so that a single lock password suffices to
// unlock every stored key. Format: version(1) || passLen(2, big-endian) ||
// passphrase || material.
func packKeyMaterial(keyPassphrase, material []byte) ([]byte, error) {
	if len(keyPassphrase) > 65535 {
		return nil, errors.New("key passphrase is too long")
	}
	out := make([]byte, 0, 1+2+len(keyPassphrase)+len(material))
	out = append(out, keyBlobVersion)
	out = append(out, byte(len(keyPassphrase)>>8), byte(len(keyPassphrase)))
	out = append(out, keyPassphrase...)
	out = append(out, material...)
	return out, nil
}

// unpackKeyMaterial reverses packKeyMaterial, returning the key's own
// passphrase and its material.
func unpackKeyMaterial(payload []byte) (keyPassphrase, material []byte, err error) {
	if len(payload) < 3 || payload[0] != keyBlobVersion {
		return nil, nil, errors.New("unsupported or corrupt sealed key blob")
	}
	passLen := int(payload[1])<<8 | int(payload[2])
	if 3+passLen > len(payload) {
		return nil, nil, errors.New("corrupt sealed key blob")
	}
	keyPassphrase = payload[3 : 3+passLen]
	material = payload[3+passLen:]
	return keyPassphrase, material, nil
}

// keyBlobVersion is the version tag for sealed key blobs that package a key's
// own passphrase with its material under the single lock-password model.
const keyBlobVersion = 1

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

// keyMaterialResidentLocked reports whether decrypted key material is held in
// memory. That is true for an unlocked session, but also for the paths that
// load a key without starting one (key import, LoadStoredSSHKey): those keep an
// entity list or a signer resident so transport operations work while the UI
// still reports "locked". The idle auto-lock must cover all of them.
// Callers must hold a.mu.
func (a *App) keyMaterialResidentLocked() bool {
	return a.sshKey != nil || len(a.keyDisk) > 0 || a.pgpSvc.HasSecretMaterial()
}

// noteKeyMaterialResident refreshes the idle clock and (re)arms the auto-lock
// timer after key material is admitted to memory. Every path that loads a key
// must call it: a timer only runs once it has been armed here, and an unarmed
// session leaves key material resident until process exit. Must be called
// without holding a.mu.
func (a *App) noteKeyMaterialResident() {
	a.mu.Lock()
	a.touchLocked()
	a.mu.Unlock()
	a.startAutoLock()
}

// startAutoLock uses the configured timeout.
func (a *App) startAutoLock() {
	a.mu.Lock()
	timeout := time.Duration(a.cfg.AutoLockMinutes) * time.Minute
	a.mu.Unlock()
	a.startAutoLockWithTimeout(timeout)
}

// autoLockTick is how often the idle timer re-evaluates resident key material.
// It is a variable so tests can shorten the interval.
var autoLockTick = 10 * time.Second

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
		ticker := time.NewTicker(autoLockTick)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				a.mu.Lock()
				expired := a.keyMaterialResidentLocked() && time.Since(a.lastActivity) > timeout
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

// StoreRemoteURL returns the origin remote URL of the active store, or "" for
// a local-only or plain directory store. It reads the repository state
// directly, so UI features driven by it (sync button visibility, settings
// display) reflect the real remote rather than a config mirror that only the
// clone flow updates.
func (a *App) StoreRemoteURL() string {
	if err := a.ensureStoreOpen(); err != nil {
		return ""
	}
	st := a.storePath()
	if st == nil || !isGitRepo(st.Root()) {
		return ""
	}
	state, err := gitx.GetRepoState(st.Root())
	if err != nil || !state.HasRemote {
		return ""
	}
	return state.RemoteURL
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

// ShowTOTP decrypts the named entry, extracts the otpauth:// URI and generates
// the current time-based one-time password.
func (a *App) ShowTOTP(name string) (string, error) {
	plaintext, err := a.ShowPassword(name)
	if err != nil {
		return "", err
	}
	defer security.Zero(plaintext)
	uri, err := totp.ExtractURI(plaintext)
	if err != nil {
		return "", err
	}
	return totp.GenerateCode(uri)
}

// HasTOTP decrypts the named entry and reports whether its body carries an
// otpauth:// URI. No plaintext is returned to the caller, so the UI can surface
// the TOTP action for an entry without revealing its content.
func (a *App) HasTOTP(name string) (bool, error) {
	plaintext, err := a.ShowPassword(name)
	if err != nil {
		return false, err
	}
	defer security.Zero(plaintext)
	_, err = totp.ExtractURI(plaintext)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, totp.ErrNoOTP) {
		return false, nil
	}
	return false, err
}

// UsernameSource returns the configured login extraction mode
// (auto, body or filename).
func (a *App) UsernameSource() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.UsernameSource
}

// SetUsernameSource persists the login extraction mode
// (auto, body or filename).
func (a *App) SetUsernameSource(mode string) error {
	if !username.Valid(mode) {
		return fmt.Errorf("unknown username source %q; use auto, body or filename", mode)
	}
	a.mu.Lock()
	a.cfg.UsernameSource = username.Normalize(mode)
	a.mu.Unlock()
	return a.saveConfig()
}

// Username decrypts the named entry and returns its login according to the
// configured username source. An entry without a recognizable login yields an
// empty string; the encrypted content never leaves this method.
func (a *App) Username(name string) (string, error) {
	plaintext, err := a.ShowPassword(name)
	if err != nil {
		return "", err
	}
	defer security.Zero(plaintext)
	mode, err := username.ParseMode(a.UsernameSource())
	if err != nil {
		return "", err
	}
	return username.Extract(name, plaintext, mode), nil
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
	if err := st.WriteEncrypted(name, ciphertext); err != nil {
		return err
	}
	a.autoCommit("Save", name)
	return nil
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
	rel := name + ".gpg"
	fullPath := filepath.Join(st.Root(), filepath.FromSlash(rel))
	if fileExists(fullPath) {
		if err := gitx.Add(st.Root(), rel); err != nil {
			return err
		}
	} else {
		if err := gitx.Remove(st.Root(), rel); err != nil {
			return err
		}
	}
	msg := "Update " + name
	if _, err := gitx.Commit(st.Root(), msg, a.cfg.GitAuthorName, a.cfg.GitAuthorEmail); err != nil {
		if errors.Is(err, gitx.ErrUpToDate) {
			return nil
		}
		return err
	}
	return nil
}

func (a *App) autoCommit(action, name string) {
	st := a.storePath()
	if st == nil || !isGitRepo(st.Root()) {
		return
	}
	rel := name + ".gpg"
	if action == "Remove" {
		_ = gitx.Remove(st.Root(), rel)
	} else {
		_ = gitx.Add(st.Root(), rel)
	}
	msg := action + " " + name
	_, _ = gitx.Commit(st.Root(), msg, a.cfg.GitAuthorName, a.cfg.GitAuthorEmail)
}

// PasswordExists reports whether the named password is stored. It never touches
// secret material.
func (a *App) PasswordExists(name string) (bool, error) {
	st := a.storePath()
	if st == nil {
		return false, errors.New("no password store is open; use 'open' or 'clone' first")
	}
	_, err := st.Read(name)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// SetPassword encrypts and writes the named entry. With keepOld set, the first
// line (the password) of an existing entry is preserved and plaintext replaces
// the remainder; creating a brand-new entry with keepOld is an error.
func (a *App) SetPassword(name string, plaintext []byte, keepOld bool) error {
	if err := a.requireUnlocked(); err != nil {
		return err
	}
	if keepOld {
		st := a.storePath()
		if st == nil {
			return errors.New("no password store is open; use 'open' or 'clone' first")
		}
		oldPlain, err := a.ShowPassword(name)
		if err != nil {
			if os.IsNotExist(err) || strings.Contains(err.Error(), "password not found") {
				return fmt.Errorf("password not found: %s", name)
			}
			return err
		}
		defer security.Zero(oldPlain)
		oldText := string(oldPlain)
		var oldPass string
		if i := strings.IndexByte(oldText, '\n'); i >= 0 {
			oldPass = oldText[:i]
		} else {
			oldPass = oldText
		}
		var sb strings.Builder
		sb.WriteString(oldPass)
		sb.WriteByte('\n')
		sb.Write(plaintext)
		final := []byte(sb.String())
		defer security.Zero(final)
		return a.SavePassword(name, final)
	}
	if len(plaintext) == 0 {
		return errors.New("empty password content")
	}
	return a.SavePassword(name, plaintext)
}

// RemovePassword deletes the named password file.
func (a *App) RemovePassword(name string) error {
	if err := a.requireUnlocked(); err != nil {
		return err
	}
	st := a.storePath()
	if st == nil {
		return errors.New("no password store is open; use 'open' or 'clone' first")
	}
	if err := st.Remove(name); err != nil {
		return err
	}
	a.autoCommit("Remove", name)
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

	if a.sshKeyOrNil() == nil {
		return errors.New("SSH key is not loaded; import an SSH private key or unlock first")
	}

	// Host key verification: capture and compare with our known_hosts store.
	known, verifyErr := knownHostTrusted(a.known, hostport)
	if errors.Is(verifyErr, sshx.ErrHostKeyChanged) {
		return fmt.Errorf("SSH host key changed for %s; refusing to connect", host)
	}
	if verifyErr != nil || !known {
		return fmt.Errorf("host key for %s is not yet trusted; run 'test-ssh %s' first and confirm the fingerprint", host, host)
	}

	if err := a.cloneOrReuse(url, dir); err != nil {
		return err
	}

	st, err := store.Open(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("cloned repository is not a pass store: %w", err)
	}
	a.mu.Lock()
	a.store = st
	a.cfg.StorePath = st.Root()
	a.cfg.GitRemote = url
	a.mu.Unlock()
	return a.saveConfig()
}

// cloneOrReuse brings the store directory in line with the remote. A target
// that is already a valid pass store is reused as-is (a previous clone that
// succeeded but could not be validated, or an already-configured store). When
// the target is missing or an empty leftover, the repository is cloned into a
// temporary sibling directory and moved into place, so an interrupted or
// failed clone never leaves a half-cloned store behind.
func (a *App) cloneOrReuse(url, dir string) error {
	if st, err := store.Open(dir); err == nil {
		a.mu.Lock()
		a.store = st
		a.mu.Unlock()
		return nil
	}
	if entries, err := os.ReadDir(dir); err == nil {
		if len(entries) > 0 {
			return fmt.Errorf("target directory %q is not empty and is not a pass store; refusing to touch it", dir)
		}
		_ = os.Remove(dir) // drop an empty leftover before cloning
	}
	tmp := dir + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := gitx.Clone(url, tmp, a.sshAuth()); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	return nil
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
// On success it returns a human-readable summary of what happened.
// For local-only stores with no remote configured, Sync is a no-op that
// returns early without requiring an SSH key.
func (a *App) Sync() (string, error) {
	if err := a.requireUnlocked(); err != nil {
		return "", err
	}
	if err := a.ensureStoreOpen(); err != nil {
		return "", err
	}
	st := a.storePath()
	if st == nil {
		return "", errors.New("no password store open")
	}
	if !isGitRepo(st.Root()) {
		return "", errors.New("the store is not a git repository")
	}
	root := st.Root()

	// Check whether a remote is configured before requiring an SSH key.
	state, err := gitx.GetRepoState(root)
	if err != nil {
		return "", err
	}
	if !state.HasRemote {
		return "No remote configured; local store only.", nil
	}

	if a.sshKeyOrNil() == nil {
		return "", errors.New("SSH key is not loaded; import an SSH private key or unlock first")
	}
	auth := a.sshAuth()

	fetched := false
	fetchErr := gitx.Fetch(root, auth)
	if fetchErr != nil {
		if !errors.Is(fetchErr, gitx.ErrUpToDate) {
			return "", fetchErr
		}
	} else {
		fetched = true
	}

	pulled := false
	pullErr := gitx.Pull(root, auth)
	if pullErr != nil {
		if !errors.Is(pullErr, gitx.ErrUpToDate) {
			return "", pullErr
		}
	} else {
		pulled = true
	}

	pushed := false
	pushErr := gitx.Push(root, auth)
	if pushErr != nil {
		if !errors.Is(pushErr, gitx.ErrUpToDate) {
			return "", pushErr
		}
	} else {
		pushed = true
	}

	if !fetched && !pulled && !pushed {
		return "Already up to date with origin.", nil
	}

	parts := make([]string, 0, 3)
	if fetched {
		parts = append(parts, "fetched remote updates")
	}
	if pulled {
		parts = append(parts, "pulled updates")
	}
	if pushed {
		parts = append(parts, "pushed local commits")
	}
	return "Synced: " + strings.Join(parts, ", ") + ".", nil
}

// Status returns a human-readable summary of the repository state.
func (a *App) Status() (string, error) {
	if err := a.ensureStoreOpen(); err != nil {
		return "", err
	}
	st := a.storePath()
	if st == nil {
		return "", errors.New("no password store open")
	}
	if !isGitRepo(st.Root()) {
		return "Store is not a git repository.", nil
	}
	state, err := gitx.GetRepoState(st.Root())
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "On branch %s\n", state.Branch)
	if state.HasRemote {
		fmt.Fprintf(&b, "Remote: %s\n", state.RemoteURL)
	} else {
		fmt.Fprintln(&b, "No remote configured.")
	}
	if state.Head != "" {
		fmt.Fprintf(&b, "Last commit: %s — %s\n", state.Head, state.LastCommit)
	}
	if state.IsClean {
		fmt.Fprintln(&b, "Working tree: clean")
	} else {
		fmt.Fprintln(&b, "Working tree: has uncommitted changes")
	}
	if state.HasRemote {
		switch {
		case state.IsDiverged:
			fmt.Fprintln(&b, "Local and remote histories have diverged.")
		case state.Ahead == 0 && state.Behind == 0:
			fmt.Fprintln(&b, "In sync with origin.")
		default:
			parts := make([]string, 0, 2)
			if state.Ahead > 0 {
				parts = append(parts, fmt.Sprintf("%d commit(s) ahead", state.Ahead))
			}
			if state.Behind > 0 {
				parts = append(parts, fmt.Sprintf("%d commit(s) behind", state.Behind))
			}
			fmt.Fprintf(&b, "%s origin.\n", strings.Join(parts, ", "))
		}
	}
	return b.String(), nil
}

// SetGitAuthor persists the author identity used for commits.
func (a *App) SetGitAuthor(name, email string) error {
	a.mu.Lock()
	a.cfg.GitAuthorName = name
	a.cfg.GitAuthorEmail = email
	a.mu.Unlock()
	return a.saveConfig()
}

// SetAutoLock persists the idle auto-lock timeout in minutes (0 disables it).
// When a timeout is armed while key material is already resident (e.g. raising
// it from 0), the idle timer is started too, otherwise that material would
// have nothing bounding its lifetime.
func (a *App) SetAutoLock(minutes int) error {
	if minutes < 0 {
		return errors.New("auto-lock cannot be negative")
	}
	a.mu.Lock()
	a.cfg.AutoLockMinutes = minutes
	resident := a.keyMaterialResidentLocked()
	a.mu.Unlock()
	if err := a.saveConfig(); err != nil {
		return err
	}
	if resident {
		a.startAutoLock()
	}
	return nil
}

// SetClipboardClear persists how long copied secrets stay on the clipboard.
func (a *App) SetClipboardClear(seconds int) error {
	if seconds < 1 {
		return errors.New("clipboard clear must be at least 1 second")
	}
	a.mu.Lock()
	a.cfg.ClipboardClearSeconds = seconds
	a.mu.Unlock()
	return a.saveConfig()
}

// ChangeLockPassword replaces the lock password, first verifying the supplied
// current password and then re-sealing every stored key (OpenPGP and SSH)
// under a key derived from newPassword. It must be called while unlocked. The
// current password is checked against the in-memory key_disk; a mismatch is
// rejected. On success the in-memory key is replaced with the one derived from
// newPassword, keeping this session unlocked. The re-seal is transactional:
// if it cannot be completed the vault is left sealed under the old password.
func (a *App) ChangeLockPassword(oldPassword, newPassword []byte) error {
	if len(newPassword) == 0 {
		return errors.New("a non-empty lock password is required")
	}
	if !a.IsUnlocked() {
		return ErrLocked
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	oldKey, err := a.deriveKeyDisk(oldPassword)
	if err != nil {
		return err
	}
	defer security.Zero(oldKey)
	if subtle.ConstantTimeCompare(oldKey, a.keyDisk) != 1 {
		return errors.New("the current lock password does not match; unable to change it")
	}

	newKey, err := a.deriveKeyDisk(newPassword)
	if err != nil {
		return err
	}
	defer security.Zero(newKey)

	if err := a.resealKeyBlobsLocked(oldKey, newKey); err != nil {
		return err
	}

	security.Zero(a.keyDisk)
	a.keyDisk = append(a.keyDisk[:0], newKey...)
	return nil
}

// keyBlob is one sealed key file taking part in a re-key transaction. The
// plaintext it was opened from is retained for the whole transaction so a
// published blob can be put back if a later one cannot be written.
type keyBlob struct {
	name      string
	path      string
	plaintext []byte
	staged    *security.StagedSeal
}

// resealKeyBlobsLocked re-seals every stored key blob from oldKey to newKey as
// a single transaction. Each blob is decrypted and its replacement staged
// before anything on disk changes; the staged files are then moved into place
// back to back, so no error path can leave the OpenPGP blob under one password
// and the SSH blob under the other. A failure while loading or staging touches
// nothing. A failure during the moves rewrites the blobs that were already
// published from the retained plaintext, leaving the vault openable with
// oldKey. Callers must hold a.mu.
func (a *App) resealKeyBlobsLocked(oldKey, newKey []byte) error {
	var blobs []keyBlob
	for _, f := range a.storedKeys() {
		if !fileExists(f.path) {
			continue
		}
		payload, err := a.vault.LoadSealed(oldKey, f.path)
		if err != nil {
			wipeKeyBlobs(blobs)
			return fmt.Errorf("unable to re-seal the stored %s key: %w", f.name, err)
		}
		staged, err := a.vault.Stage(newKey, f.path, payload)
		if err != nil {
			security.Zero(payload)
			wipeKeyBlobs(blobs)
			return fmt.Errorf("unable to re-seal the stored %s key: %w", f.name, err)
		}
		blobs = append(blobs, keyBlob{name: f.name, path: f.path, plaintext: payload, staged: staged})
	}

	published := 0
	for i := range blobs {
		err := blobs[i].staged.Commit()
		if err == nil {
			published++
			continue
		}
		err = fmt.Errorf("unable to re-seal the stored %s key: %w", blobs[i].name, err)
		err = a.rollbackKeyBlobsLocked(oldKey, blobs[:published], err)
		wipeKeyBlobs(blobs)
		return err
	}
	wipeKeyBlobs(blobs)
	return nil
}

// rollbackKeyBlobsLocked restores the blobs that were already published back
// under oldKey and reports what the user is left with. A blob that cannot be
// restored is named, because that is the only outcome that needs their
// attention; otherwise the change is undone and the old password still works.
func (a *App) rollbackKeyBlobsLocked(oldKey []byte, published []keyBlob, cause error) error {
	if len(published) == 0 {
		return cause
	}
	var unrestored []string
	for i := range published {
		if err := a.vault.Store(oldKey, published[i].path, published[i].plaintext); err != nil {
			unrestored = append(unrestored, published[i].name)
		}
	}
	if len(unrestored) > 0 {
		return fmt.Errorf("%w; the %s key could not be restored, so the vault now mixes both lock passwords and must be repaired from a backup",
			cause, strings.Join(unrestored, " and "))
	}
	return fmt.Errorf("%w; the change was undone, so the current lock password still opens the vault", cause)
}

// wipeKeyBlobs drops the staged replacements and zeroes the retained
// plaintexts of a re-key transaction, committed blobs included.
func wipeKeyBlobs(blobs []keyBlob) {
	for i := range blobs {
		blobs[i].staged.Discard()
		security.Zero(blobs[i].plaintext)
	}
}

// CloneHostport extracts the host:22 hostport for a git SSH URL so the host
// key can be checked and trusted before cloning.
func (a *App) CloneHostport(url string) (string, error) {
	host := gitHostFromURL(url)
	if host == "" {
		return "", fmt.Errorf("cannot determine SSH host from %q", url)
	}
	return host + ":22", nil
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
