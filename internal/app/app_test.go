package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	goGit "github.com/go-git/go-git/v5"
	goGitConfig "github.com/go-git/go-git/v5/config"
	"github.com/oxcafedead/passone/internal/gitx"
	"github.com/oxcafedead/passone/internal/security"
	"github.com/oxcafedead/passone/internal/sshx"
	"github.com/oxcafedead/passone/internal/store"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

const testPGPPassphrase = "app-test-pass"
const testLockPass = "test-lock-pass"

// fileURL returns a RFC 8089 file:// URL for an absolute local path.
// It works on both Windows (file:///C:/...) and Unix (file:///tmp/...).
func fileURL(path string) string {
	path = filepath.ToSlash(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return (&url.URL{Scheme: "file", Path: path}).String()
}

// newTestApp returns an App bound to an isolated data directory; the
// PASSONE_DIR env override is restored after the test.
func newTestApp(t *testing.T) *App {
	t.Helper()
	t.Setenv("PASSONE_DIR", t.TempDir())
	a, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func armoredTestKey(t *testing.T) []byte {
	t.Helper()
	cfg := &packet.Config{}
	e, err := openpgp.NewEntity("App Tester", "", "app@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	if err := e.EncryptPrivateKeys([]byte(testPGPPassphrase), cfg); err != nil {
		t.Fatalf("EncryptPrivateKeys: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Encrypted keys cannot be re-signed; existing self-signatures are valid.
	if err := e.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func entityFingerprint(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}

func TestImportUnlockDecryptFlow(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	fp := ""

	// Parse the fingerprint from the same key before importing.
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	fp = entityFingerprint(el[0])

	infos, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass))
	if err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if len(infos) == 0 || infos[0].Fingerprint != fp {
		t.Fatalf("infos = %+v", infos)
	}
	if a.IsUnlocked() {
		t.Fatal("expected the app to stay locked after import; unlocking must be explicit")
	}

	// Set up a local pass store and open it.
	storeDir := filepath.Join(t.TempDir(), "pass")
	st, err := store.Create(storeDir, []string{fp})
	if err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	_ = st
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}

	// A session unlock with the OpenPGP passphrase makes the store usable.
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Save, list, show.
	if err := a.SavePassword("github/personal", []byte("hunter2\nurl: https://example.com\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	listed, err := a.ListPasswords()
	if err != nil {
		t.Fatalf("ListPasswords: %v", err)
	}
	if len(listed) != 1 || listed[0] != "github/personal" {
		t.Fatalf("ListPasswords = %v", listed)
	}
	plain, err := a.ShowPassword("github/personal")
	if err != nil {
		t.Fatalf("ShowPassword: %v", err)
	}
	if string(plain) != "hunter2\nurl: https://example.com\n" {
		t.Fatalf("ShowPassword = %q", plain)
	}

	// The encrypted file on disk must not contain the plaintext.
	raw, err := os.ReadFile(filepath.Join(storeDir, "github", "personal.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("hunter2")) {
		t.Fatal("encrypted file leaks plaintext")
	}

	// Lock drops key material; secrets are gone from memory.
	a.Lock()
	if a.IsUnlocked() {
		t.Fatal("expected lock to clear unlocked state")
	}
	if _, err := a.ShowPassword("github/personal"); err == nil {
		t.Fatal("expected ShowPassword to fail after lock")
	}

	// Unlock with the wrong passphrase fails; the right one works.
	if err := a.Unlock([]byte("wrong")); err == nil {
		t.Fatal("expected wrong pgp passphrase to fail")
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	plain2, err := a.ShowPassword("github/personal")
	if err != nil {
		t.Fatalf("ShowPassword after unlock: %v", err)
	}
	if string(plain2) != "hunter2\nurl: https://example.com\n" {
		t.Fatalf("ShowPassword after unlock = %q", plain2)
	}
}

// armoredNoPassphraseKey builds a key whose private key is NOT passphrase
// protected, mirroring a GnuPG key generated with "no passphrase".
func armoredNoPassphraseKey(t *testing.T) []byte {
	t.Helper()
	cfg := &packet.Config{}
	e, err := openpgp.NewEntity("No Pass App", "", "nopass-app@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestNoPassphraseImportUnlockDecryptFlow is the regression for "keys cannot be
// decoded if GPG has no passphrase": a key without a passphrase must import,
// open a store, unlock from the sealed vault, and decrypt password files.
func TestNoPassphraseImportUnlockDecryptFlow(t *testing.T) {
	a := newTestApp(t)
	armored := armoredNoPassphraseKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	fp := entityFingerprint(el[0])

	if _, err := a.ImportPGPKey(armored, []byte(""), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey with empty passphrase: %v", err)
	}

	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	// Unlock reloads the key from the sealed vault blob.
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.SavePassword("test/entry", []byte("no-pass-secret\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	out, err := a.ShowPassword("test/entry")
	if err != nil {
		t.Fatalf("ShowPassword: %v", err)
	}
	if string(out) != "no-pass-secret\n" {
		t.Fatalf("ShowPassword = %q", out)
	}

	// Lock and unlock again to exercise the restart path.
	a.Lock()
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock after lock: %v", err)
	}
	out2, err := a.ShowPassword("test/entry")
	if err != nil {
		t.Fatalf("ShowPassword after lock/unlock: %v", err)
	}
	if string(out2) != "no-pass-secret\n" {
		t.Fatalf("ShowPassword after lock/unlock = %q", out2)
	}
}

// reopenTestApp returns a second App bound to the same data directory, so a
// test can assert what is actually on disk instead of what the first instance
// kept in memory.
func reopenTestApp(t *testing.T) *App {
	t.Helper()
	a, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// denyDelete holds path open without FILE_SHARE_DELETE, which makes a
// MoveFileEx replacing it fail with a sharing violation. It is how a commit
// that fails half way through a re-key is reproduced. The returned function
// releases the handle.
func denyDelete(t *testing.T, path string) func() {
	t.Helper()
	return holdSharing(t, path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, false)
}

// blockStagingWrite creates path and holds it without FILE_SHARE_WRITE, so a
// staged write to it fails with a sharing violation. The returned function
// releases the handle and removes the file again.
func blockStagingWrite(t *testing.T, path string) func() {
	t.Helper()
	return holdSharing(t, path, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, true)
}

func holdSharing(t *testing.T, path string, access, share uint32, remove bool) func() {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, access, share, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("CreateFile(%s): %v", path, err)
	}
	return func() {
		_ = windows.CloseHandle(h)
		if remove {
			_ = os.Remove(path)
		}
	}
}

// assertNoStagingFiles fails if a re-key left staging files behind.
func assertNoStagingFiles(t *testing.T, dir string) {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("staging files left behind: %v", names)
	}
}

func TestChangeLockPassword(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	infos, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass))
	if err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("no keys imported")
	}
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}

	if err := a.ChangeLockPassword([]byte(testLockPass), nil); err == nil {
		t.Fatal("ChangeLockPassword with an empty password should fail")
	}
	if err := a.ChangeLockPassword([]byte("wrong"), []byte("new-lock-pass")); err == nil {
		t.Fatal("ChangeLockPassword while locked should fail")
	}

	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.ChangeLockPassword([]byte("wrong"), []byte("new-lock-pass")); err == nil {
		t.Fatal("ChangeLockPassword with the wrong current password should fail")
	}
	if err := a.ChangeLockPassword([]byte(testLockPass), []byte("new-lock-pass")); err != nil {
		t.Fatalf("ChangeLockPassword: %v", err)
	}
	assertNoStagingFiles(t, a.paths.KeysDir)

	a.Lock()
	if err := a.Unlock([]byte(testLockPass)); err == nil {
		t.Fatal("old lock password should no longer work after change")
	}
	if err := a.Unlock([]byte("new-lock-pass")); err != nil {
		t.Fatalf("Unlock with new password: %v", err)
	}
	// Both blobs must have moved to the new key, not just the OpenPGP one.
	if a.SSHKeyID() == "" {
		t.Fatal("SSH key id should survive the lock password change")
	}
}

// A re-key that cannot be completed must leave the whole vault under the old
// password. Publishing the OpenPGP blob and then failing on the SSH one is the
// case that used to brick the vault: neither password would open everything.
func TestChangeLockPasswordRollsBackWhenACommitFails(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.ImportPGPKey(armoredTestKey(t), []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// The SSH blob is committed last, so blocking its move fails the
	// transaction only after the OpenPGP blob has been published.
	release := denyDelete(t, a.paths.SSHKeyFile)
	err := a.ChangeLockPassword([]byte(testLockPass), []byte("new-lock-pass"))
	release()
	if err == nil {
		t.Fatal("expected the change to fail when a staged move cannot be published")
	}
	if !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("error should name the blob that failed: %v", err)
	}
	if !a.IsUnlocked() {
		t.Fatal("a failed change must leave the session unlocked under the old key")
	}

	// A fresh App reads what is on disk: the old password still opens the
	// vault and the new one does not.
	b := reopenTestApp(t)
	if err := b.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("old lock password should still open the vault after a failed change: %v", err)
	}
	b.Lock()
	if err := b.Unlock([]byte("new-lock-pass")); err == nil {
		t.Fatal("the new lock password must not open a vault whose change failed")
	}
	assertNoStagingFiles(t, a.paths.KeysDir)

	// The rolled-back vault is intact, so the change can simply be retried.
	if err := a.ChangeLockPassword([]byte(testLockPass), []byte("new-lock-pass")); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
	assertNoStagingFiles(t, a.paths.KeysDir)
	a.Lock()
	if err := a.Unlock([]byte("new-lock-pass")); err != nil {
		t.Fatalf("Unlock with the retried password: %v", err)
	}
}

// A failure while staging must not touch any blob, including the one already
// loaded into memory for staging.
func TestChangeLockPasswordStageFailureLeavesEveryBlobAlone(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.ImportPGPKey(armoredTestKey(t), []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Block the staging write of the SSH blob, which is prepared after the
	// OpenPGP replacement, so the change fails with nothing published.
	release := blockStagingWrite(t, a.paths.SSHKeyFile+".tmp")
	err := a.ChangeLockPassword([]byte(testLockPass), []byte("new-lock-pass"))
	release()
	if err == nil {
		t.Fatal("expected the change to fail when a blob cannot be staged")
	}
	assertNoStagingFiles(t, a.paths.KeysDir)

	b := reopenTestApp(t)
	if err := b.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("old lock password should still open the vault: %v", err)
	}
	b.Lock()
	if err := b.Unlock([]byte("new-lock-pass")); err == nil {
		t.Fatal("the new lock password must not open the vault")
	}
}

// splitVault republishes only the OpenPGP blob under a second lock password,
// which is exactly the state a crash between the two commits of a lock
// password change leaves behind. The re-key rolls that back, so the split has
// to be reproduced directly to be tested.
func splitVault(t *testing.T, a *App) {
	t.Helper()
	salt, err := a.vault.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	defer security.Zero(salt)
	oldKey := security.DeriveKey([]byte(testLockPass), salt)
	newKey := security.DeriveKey([]byte("new-lock-pass"), salt)
	defer security.Zero(oldKey)
	defer security.Zero(newKey)

	payload, err := a.vault.LoadSealed(oldKey, a.paths.PGPKeyFile)
	if err != nil {
		t.Fatalf("LoadSealed: %v", err)
	}
	defer security.Zero(payload)
	staged, err := a.vault.Stage(newKey, a.paths.PGPKeyFile, payload)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := staged.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// A split vault must be reported as such from both sides. Reporting it as a
// plain integrity failure is what left a user with a vault they believed was
// corrupt and no way to learn that either password worked for part of it.
func TestSplitVaultIsDiagnosedFromBothPasswords(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.ImportPGPKey(armoredTestKey(t), []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	splitVault(t, a)

	// The pre-change password opens SSH but not OpenPGP.
	err := a.Unlock([]byte(testLockPass))
	if !errors.Is(err, ErrSplitVault) {
		t.Fatalf("Unlock with the old password = %v, want a split vault error", err)
	}
	if !strings.Contains(err.Error(), "OpenPGP") || !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("the error should name both keys: %v", err)
	}

	// The interrupted change's new password opens OpenPGP but not SSH.
	err = a.Unlock([]byte("new-lock-pass"))
	if !errors.Is(err, ErrSplitVault) {
		t.Fatalf("Unlock with the new password = %v, want a split vault error", err)
	}
	if !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("the error should name the key that will not open: %v", err)
	}
	if a.IsUnlocked() {
		t.Fatal("neither password may leave the vault unlocked")
	}
}

// The split must not be reported for an ordinary wrong password: there both
// blobs stay unreadable and the integrity error is the accurate answer.
func TestWrongPasswordIsNotReportedAsSplit(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.ImportPGPKey(armoredTestKey(t), []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	err := a.Unlock([]byte("not-the-password"))
	if err == nil {
		t.Fatal("Unlock with a wrong password should fail")
	}
	if errors.Is(err, ErrSplitVault) {
		t.Fatalf("a wrong password must not be reported as a split vault: %v", err)
	}
	if !strings.Contains(err.Error(), "unable to read the stored OpenPGP key") {
		t.Fatalf("unlock error = %v", err)
	}

	// A vault holding a single key has nothing to compare against.
	b := newTestApp(t)
	if _, err := b.ImportPGPKey(armoredTestKey(t), []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if err := b.Unlock([]byte("not-the-password")); errors.Is(err, ErrSplitVault) {
		t.Fatalf("a single-key vault must not be reported as split: %v", err)
	}
}

// Importing into a split vault must not tell the user their lock password is
// wrong, which is what it did before: they were typing the password that does
// open the other blob.
func TestImportIntoSplitVaultIsDiagnosed(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.ImportPGPKey(armoredTestKey(t), []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	splitVault(t, a)

	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); !errors.Is(err, ErrSplitVault) {
		t.Fatalf("ImportSSHKey into a split vault = %v, want a split vault error", err)
	}
	if _, err := a.ImportPGPKey(armoredTestKey(t), []byte(testPGPPassphrase), []byte("new-lock-pass")); !errors.Is(err, ErrSplitVault) {
		t.Fatalf("ImportPGPKey into a split vault = %v, want a split vault error", err)
	}
}

func TestListWithoutUnlock(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])

	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatal(err)
	}
	// No key imported, never unlocked: listing must still work (no secrets).
	listed, err := a.ListPasswords()
	if err != nil {
		t.Fatalf("ListPasswords without unlock: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("ListPasswords = %v", listed)
	}
}

func TestConfigPersistsStorePath(t *testing.T) {
	a := newTestApp(t)
	if err := a.OpenLocalStore(t.TempDir() + "/does-not-exist-yet"); err == nil {
		t.Fatal("expected open of a non-store dir to fail")
	}
	dir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(dir, []string{"12AB"}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(dir); err != nil {
		t.Fatal(err)
	}
	if a.Config().StorePath == "" {
		t.Fatal("expected a saved StorePath")
	}
}

func TestLockUnlockEventHooks(t *testing.T) {
	a := newTestApp(t)
	lockEvents := make(chan struct{}, 4)
	unlockEvents := make(chan struct{}, 4)
	a.OnLock(func() { lockEvents <- struct{}{} })
	a.OnUnlock(func() { unlockEvents <- struct{}{} })

	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	select {
	case <-unlockEvents:
	case <-time.After(2 * time.Second):
		t.Fatal("expected an unlock event after Unlock")
	}

	a.Lock()
	select {
	case <-lockEvents:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a lock event after Lock")
	}

	// The lazy idle lock inside a failing operation must also fire the hook.
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("second Unlock: %v", err)
	}
	select {
	case <-unlockEvents:
	case <-time.After(2 * time.Second):
		t.Fatal("expected an unlock event after second Unlock")
	}
	a.mu.Lock()
	a.lastActivity = time.Now().Add(-6 * time.Minute)
	a.mu.Unlock()
	if _, err := a.ShowPassword("unused"); err == nil {
		t.Fatal("expected ShowPassword to fail after idle expiry")
	}
	select {
	case <-lockEvents:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a lock event after idle expiry")
	}
}

func TestConfigGettersAndSetters(t *testing.T) {
	a := newTestApp(t)
	if err := a.SetAutoLock(7); err != nil {
		t.Fatalf("SetAutoLock: %v", err)
	}
	if got := a.Config().AutoLockMinutes; got != 7 {
		t.Fatalf("AutoLockMinutes = %d", got)
	}
	if err := a.SetAutoLock(-1); err == nil {
		t.Fatal("expected a negative auto-lock to fail")
	}
	if err := a.SetClipboardClear(45); err != nil {
		t.Fatalf("SetClipboardClear: %v", err)
	}
	if got := a.Config().ClipboardClearSeconds; got != 45 {
		t.Fatalf("ClipboardClearSeconds = %d", got)
	}
	if err := a.SetClipboardClear(0); err == nil {
		t.Fatal("expected a zero clipboard clear to fail")
	}
	if err := a.SetGitAuthor("Bob", "bob@example.com"); err != nil {
		t.Fatalf("SetGitAuthor: %v", err)
	}
	cfg := a.Config()
	if cfg.GitAuthorName != "Bob" || cfg.GitAuthorEmail != "bob@example.com" {
		t.Fatalf("git author = %+v", cfg)
	}
	hp, err := a.CloneHostport("git@github.com:user/pass.git")
	if err != nil {
		t.Fatalf("CloneHostport: %v", err)
	}
	if hp != "github.com:22" {
		t.Fatalf("CloneHostport = %q", hp)
	}
}

func TestSetPasswordCreateEditRemove(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}

	// A session unlock with the OpenPGP passphrase is required before any
	// password operation, even right after an import.
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Creating a brand-new entry with keepOld must fail.
	if err := a.SetPassword("fresh", []byte("x"), true); err == nil {
		t.Fatal("expected keepOld on a missing entry to fail")
	}

	// Create an entry: first line is the password, rest is the body.
	if err := a.SetPassword("work/jira", []byte("pass1\nold note\n"), false); err != nil {
		t.Fatalf("SetPassword create: %v", err)
	}
	plain, err := a.ShowPassword("work/jira")
	if err != nil {
		t.Fatalf("ShowPassword: %v", err)
	}
	if string(plain) != "pass1\nold note\n" {
		t.Fatalf("created = %q", plain)
	}

	// Edit with keepOld: password stays, body is replaced.
	if err := a.SetPassword("work/jira", []byte("new note\n"), true); err != nil {
		t.Fatalf("SetPassword keepOld: %v", err)
	}
	plain, err = a.ShowPassword("work/jira")
	if err != nil {
		t.Fatalf("ShowPassword after edit: %v", err)
	}
	if string(plain) != "pass1\nnew note\n" {
		t.Fatalf("edited = %q", plain)
	}

	// Edit with keepOld and an empty body clears the notes.
	if err := a.SetPassword("work/jira", []byte(""), true); err != nil {
		t.Fatalf("SetPassword clear body: %v", err)
	}
	plain, err = a.ShowPassword("work/jira")
	if err != nil {
		t.Fatalf("ShowPassword after clear: %v", err)
	}
	if string(plain) != "pass1\n" {
		t.Fatalf("cleared = %q", plain)
	}

	// An empty create (no keepOld) is rejected.
	if err := a.SetPassword("empty", []byte(""), false); err == nil {
		t.Fatal("expected empty create to fail")
	}

	// Remove, list, verify gone.
	if err := a.RemovePassword("work/jira"); err != nil {
		t.Fatalf("RemovePassword: %v", err)
	}
	if _, err := a.ShowPassword("work/jira"); err == nil {
		t.Fatal("expected ShowPassword to fail after remove")
	}
	listed, err := a.ListPasswords()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 0 {
		t.Fatalf("ListPasswords after remove = %v", listed)
	}
	if err := a.RemovePassword("work/jira"); err == nil {
		t.Fatal("expected a second remove to fail")
	}
}

func TestAutoCommitOnSaveAndRemove(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	// Initialize git repo in the store directory.
	if _, err := goGit.PlainInit(storeDir, false); err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	if err := gitx.Add(storeDir, ".gpg-id"); err != nil {
		t.Fatalf("gitx.Add: %v", err)
	}
	if _, err := gitx.Commit(storeDir, "init store", "Tester", "t@example.com"); err != nil {
		t.Fatalf("gitx.Commit: %v", err)
	}

	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// 1. Create a password -> should auto-commit.
	if err := a.SetPassword("personal/email", []byte("secret123\nnotes\n"), false); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	st, err := gitx.Status(storeDir)
	if err != nil {
		t.Fatalf("gitx.Status: %v", err)
	}
	if strings.TrimSpace(st) != "" {
		t.Fatalf("expected clean working tree after SetPassword, got:\n%s", st)
	}

	// 2. Edit the password -> should auto-commit.
	if err := a.SetPassword("personal/email", []byte("newpass456\n"), false); err != nil {
		t.Fatalf("SetPassword edit: %v", err)
	}
	st, err = gitx.Status(storeDir)
	if err != nil {
		t.Fatalf("gitx.Status: %v", err)
	}
	if strings.TrimSpace(st) != "" {
		t.Fatalf("expected clean working tree after edit, got:\n%s", st)
	}

	// 3. Remove the password -> should auto-commit.
	if err := a.RemovePassword("personal/email"); err != nil {
		t.Fatalf("RemovePassword: %v", err)
	}
	st, err = gitx.Status(storeDir)
	if err != nil {
		t.Fatalf("gitx.Status: %v", err)
	}
	if strings.TrimSpace(st) != "" {
		t.Fatalf("expected clean working tree after RemovePassword, got:\n%s", st)
	}
}

// moveTestApp returns an unlocked app over a git-backed store holding one
// entry, "work/jira" with the given plaintext. The store is a repository
// because a move has to stage two paths, and that is only observable in git.
func moveTestApp(t *testing.T, plaintext string) (*App, string) {
	t.Helper()
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if _, err := goGit.PlainInit(storeDir, false); err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	if err := gitx.Add(storeDir, ".gpg-id"); err != nil {
		t.Fatalf("gitx.Add: %v", err)
	}
	if _, err := gitx.Commit(storeDir, "init store", "Tester", "t@example.com"); err != nil {
		t.Fatalf("gitx.Commit: %v", err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.SetPassword("work/jira", []byte(plaintext), false); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	return a, storeDir
}

func TestMovePassword(t *testing.T) {
	a, _ := moveTestApp(t, "pass1\nnote\n")

	if err := a.MovePassword("work/jira", "work/jira-renamed"); err != nil {
		t.Fatalf("MovePassword: %v", err)
	}
	// The entry keeps its exact content: a move renames the stored file and
	// never re-encrypts, so there is no window in which a secret is exposed
	// or altered.
	plain, err := a.ShowPassword("work/jira-renamed")
	if err != nil {
		t.Fatalf("ShowPassword after move: %v", err)
	}
	if string(plain) != "pass1\nnote\n" {
		t.Fatalf("moved entry = %q", plain)
	}
	if _, err := a.ShowPassword("work/jira"); err == nil {
		t.Fatal("expected the old path to be gone after a move")
	}
	listed, err := a.ListPasswords()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0] != "work/jira-renamed" {
		t.Fatalf("ListPasswords = %v, want [work/jira-renamed]", listed)
	}
}

func TestMovePasswordIntoNewFolder(t *testing.T) {
	a, storeDir := moveTestApp(t, "pass1\n")
	if err := a.MovePassword("work/jira", "archive/2026/jira"); err != nil {
		t.Fatalf("MovePassword: %v", err)
	}
	if _, err := os.Stat(filepath.Join(storeDir, "archive", "2026", "jira.gpg")); err != nil {
		t.Fatalf("expected the entry under its new folders: %v", err)
	}
	// A move in a git store is a rename in the history, not an add plus a
	// delete: both halves have to land in one commit or the next commit on
	// this repository would silently pick up the missing half.
	status, err := gitx.Status(storeDir)
	if err != nil {
		t.Fatalf("gitx.Status: %v", err)
	}
	if strings.TrimSpace(status) != "" {
		t.Fatalf("expected a clean tree after a move, got:\n%s", status)
	}
	repo, err := goGit.PlainOpen(storeDir)
	if err != nil {
		t.Fatalf("PlainOpen: %v", err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		t.Fatalf("CommitObject: %v", err)
	}
	if commit.Message != "Move work/jira to archive/2026/jira" {
		t.Fatalf("commit message = %q", commit.Message)
	}
	tree, err := commit.Tree()
	if err != nil {
		t.Fatalf("Tree: %v", err)
	}
	if _, err := tree.File("archive/2026/jira.gpg"); err != nil {
		t.Fatalf("the new path is not in the commit: %v", err)
	}
	if _, err := tree.File("work/jira.gpg"); err == nil {
		t.Fatal("the old path is still in the commit: a move committed only one half")
	}
}

func TestMovePasswordRefuses(t *testing.T) {
	a, _ := moveTestApp(t, "pass1\n")
	if err := a.SetPassword("work/other", []byte("pass2\n"), false); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	cases := []struct {
		name     string
		from, to string
	}{
		{"empty source", "", "work/new"},
		{"empty target", "work/jira", ""},
		{"blank source", "   ", "work/new"},
		{"missing source", "work/missing", "work/new"},
		{"target exists", "work/jira", "work/other"},
		{"same name", "work/jira", "work/jira"},
		{"source escapes the store", "../evil", "work/new"},
		{"target escapes the store", "work/jira", "../evil"},
	}
	for _, tc := range cases {
		if err := a.MovePassword(tc.from, tc.to); err == nil {
			t.Errorf("%s: expected MovePassword(%q, %q) to fail", tc.name, tc.from, tc.to)
		}
	}
	// Nothing above may have moved or destroyed anything.
	for _, p := range []string{"work/jira", "work/other"} {
		exists, err := a.PasswordExists(p)
		if err != nil {
			t.Fatalf("PasswordExists(%q): %v", p, err)
		}
		if !exists {
			t.Errorf("%s: a refused move changed the store", p)
		}
	}
	plain, err := a.ShowPassword("work/other")
	if err != nil {
		t.Fatalf("ShowPassword: %v", err)
	}
	if string(plain) != "pass2\n" {
		t.Fatalf("a refused move overwrote an entry: %q", plain)
	}
}

func TestMovePasswordRequiresUnlock(t *testing.T) {
	a, _ := moveTestApp(t, "pass1\n")
	a.Lock()
	if err := a.MovePassword("work/jira", "work/new"); !errors.Is(err, ErrLocked) {
		t.Fatalf("MovePassword while locked = %v, want ErrLocked", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.MovePassword("work/jira", "work/new"); err != nil {
		t.Fatalf("MovePassword: %v", err)
	}
}

func TestMovePasswordWithoutStore(t *testing.T) {
	a := newTestApp(t)
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.MovePassword("a", "b"); err == nil {
		t.Fatal("expected MovePassword without a store to fail")
	}
}

func sshTestKey(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "unit@example.com")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func TestAppGetters(t *testing.T) {
	a := newTestApp(t)
	if a.DataDir() == "" {
		t.Fatal("DataDir empty")
	}
	if a.HasStoredPGPKey() {
		t.Fatal("expected no stored PGP key")
	}
	if a.HasStoredSSHKey() {
		t.Fatal("expected no stored SSH key")
	}
	if a.PGPKeyFingerprint() != "" {
		t.Fatal("expected empty fingerprint")
	}
	if a.SSHKeyID() != "" {
		t.Fatal("expected empty SSH key id")
	}
	if a.StorePath() != "" {
		t.Fatal("expected empty store path")
	}
}

func TestStoredStores(t *testing.T) {
	a := newTestApp(t)
	if stores := a.StoredStores(); len(stores) != 0 {
		t.Fatalf("StoredStores = %v", stores)
	}

	// Create a valid store under the app's stores directory.
	storeName := "my-store"
	storeDir := filepath.Join(a.paths.StoresDir, storeName)
	if _, err := store.Create(storeDir, []string{"AABBCCDD"}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	stores := a.StoredStores()
	if len(stores) != 1 || stores[0] != storeDir {
		t.Fatalf("StoredStores = %v", stores)
	}
}

func TestImportSSHKey(t *testing.T) {
	a := newTestApp(t)
	pemBytes := sshTestKey(t)
	k, err := a.ImportSSHKey(pemBytes, nil, []byte(testLockPass))
	if err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if k.Algorithm() != ssh.KeyAlgoED25519 {
		t.Fatalf("algorithm = %q", k.Algorithm())
	}
	if !a.HasStoredSSHKey() {
		t.Fatal("expected stored SSH key")
	}
	if a.SSHKeyID() == "" {
		t.Fatal("expected SSH key id to be set")
	}
}

func TestImportMustUseCurrentLockPassword(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}

	// Importing an SSH key under a different lock password must be rejected so
	// the vault cannot end up fragmented across two passwords.
	pemBytes := sshTestKey(t)
	if _, err := a.ImportSSHKey(pemBytes, nil, []byte("another-lock-pass")); err == nil {
		t.Fatal("ImportSSHKey under a different lock password should fail")
	}
	if _, err := a.ImportSSHKey(pemBytes, nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey under the matching lock password: %v", err)
	}

	// Re-importing the PGP key under a stale password must also be rejected.
	second := armoredTestKey(t)
	if _, err := a.ImportPGPKey(second, []byte(testPGPPassphrase), []byte("another-lock-pass")); err == nil {
		t.Fatal("ImportPGPKey under a different lock password should fail")
	}
	if _, err := a.ImportPGPKey(second, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey under the matching lock password: %v", err)
	}
}

func TestUnlockPGPOnly(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := a.UnlockPGP([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockPGP: %v", err)
	}
	if !a.IsUnlocked() {
		t.Fatal("expected unlocked")
	}
	if a.HasSSHKeyLoaded() {
		t.Fatal("expected no SSH key loaded")
	}
}

func TestUnlockSSHOnly(t *testing.T) {
	a := newTestApp(t)
	pemBytes := sshTestKey(t)
	if _, err := a.ImportSSHKey(pemBytes, nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.UnlockSSH([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockSSH: %v", err)
	}
	if !a.HasSSHKeyLoaded() {
		t.Fatal("expected SSH key loaded")
	}
}

func TestLoadStoredSSHKey(t *testing.T) {
	a := newTestApp(t)
	pemBytes := sshTestKey(t)
	if _, err := a.ImportSSHKey(pemBytes, nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.LoadStoredSSHKey([]byte(testLockPass)); err != nil {
		t.Fatalf("LoadStoredSSHKey: %v", err)
	}
	if !a.HasSSHKeyLoaded() {
		t.Fatal("expected SSH key loaded")
	}
}

func TestSSHPublicKey(t *testing.T) {
	a := newTestApp(t)
	pemBytes := sshTestKey(t)
	if _, err := a.ImportSSHKey(pemBytes, nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.UnlockSSH([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockSSH: %v", err)
	}
	pub, err := a.SSHPublicKey()
	if err != nil {
		t.Fatalf("SSHPublicKey: %v", err)
	}
	if len(pub) == 0 {
		t.Fatal("expected public key")
	}
}

func TestPasswordExists(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	exists, err := a.PasswordExists("missing")
	if err != nil {
		t.Fatalf("PasswordExists: %v", err)
	}
	if exists {
		t.Fatal("expected missing password not to exist")
	}
	if err := a.SavePassword("existing", []byte("secret\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	exists, err = a.PasswordExists("existing")
	if err != nil {
		t.Fatalf("PasswordExists: %v", err)
	}
	if !exists {
		t.Fatal("expected existing password to exist")
	}
}

func TestCommitPassword(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if _, err := goGit.PlainInit(storeDir, false); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.SavePassword("site", []byte("secret\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	// SavePassword auto-committed; CommitPassword should be a no-op (up to date).
	if err := a.CommitPassword("site"); err != nil {
		t.Fatalf("CommitPassword: %v", err)
	}
}

func TestRemovePasswordNotFound(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.RemovePassword("missing"); err == nil {
		t.Fatal("expected RemovePassword of missing entry to fail")
	}
}

func TestStatusWithoutRemote(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if _, err := goGit.PlainInit(storeDir, false); err != nil {
		t.Fatal(err)
	}
	if err := gitx.Add(storeDir, ".gpg-id"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitx.Commit(storeDir, "init", "T", "t@x"); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatal(err)
	}
	status, err := a.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(status, "No remote configured") {
		t.Fatalf("Status = %q", status)
	}
}

func TestCloneHostportAndGitHost(t *testing.T) {
	a := newTestApp(t)
	hp, err := a.CloneHostport("ssh://git@github.com/user/pass.git")
	if err != nil {
		t.Fatalf("CloneHostport: %v", err)
	}
	if hp != "github.com:22" {
		t.Fatalf("CloneHostport = %q", hp)
	}

	// A port in the URL is part of the host a clone connects to, and trust is
	// keyed on it; the scp-like form has no port, its colon starts the path.
	hostports := map[string]string{
		"git@github.com:user/pass.git":                 "github.com:22",
		"ssh://git@github.com/user/pass.git":           "github.com:22",
		"ssh://git@GitHub.com/user/pass.git":           "github.com:22",
		"ssh://git@git.example.com:2222/user/pass.git": "git.example.com:2222",
		"ssh://git.example.com:2222/user/pass.git":     "git.example.com:2222",
		"git@git.example.com:2222/user/pass-store.git": "git.example.com:22",
		"git@github.com":                               "github.com:22",
	}
	for in, want := range hostports {
		if got := gitHostPortFromURL(in); got != want {
			t.Errorf("gitHostPortFromURL(%q) = %q, want %q", in, got, want)
		}
		got, err := a.CloneHostport(in)
		if err != nil {
			t.Errorf("CloneHostport(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("CloneHostport(%q) = %q, want %q", in, got, want)
		}
	}

	hosts := map[string]string{
		"git@github.com:user/pass.git":                 "github.com",
		"ssh://git@github.com/user/pass.git":           "github.com",
		"ssh://git@git.example.com:2222/user/pass.git": "git.example.com:2222",
		"git@git.example.com:2222/user/pass-store.git": "git.example.com",
		"not-a-url": "not-a-url",
	}
	for in, want := range hosts {
		if got := gitHostFromURL(in); got != want {
			t.Errorf("gitHostFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrustHostAndKnownHosts(t *testing.T) {
	a := newTestApp(t)
	_, pub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	key := signer.PublicKey()
	if err := a.TrustHost("github.com", key); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	list := a.KnownHostsList()
	if len(list) != 1 {
		t.Fatalf("KnownHostsList = %v", list)
	}
	// Re-trusting the same key is a no-op, and a different key for a host that
	// is already trusted is refused: the store keeps the key the user confirmed.
	if err := a.TrustHost("github.com", key); err != nil {
		t.Fatalf("re-TrustHost same key: %v", err)
	}
	_, otherPub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.TrustHost("github.com", otherSigner.PublicKey()); !errors.Is(err, sshx.ErrHostKeyChanged) {
		t.Fatalf("expected ErrHostKeyChanged, got %v", err)
	}
	list = a.KnownHostsList()
	if len(list) != 1 {
		t.Fatalf("KnownHostsList after refused TrustHost = %v", list)
	}
}

// TestTrustHostIsPerPort pins that trust is keyed on host:port: a key confirmed
// for 127.0.0.1:<p1> must not make 127.0.0.1:<p2> known, and a different key
// there is unknown rather than a reported key change.
func TestTrustHostIsPerPort(t *testing.T) {
	a := newTestApp(t)
	firstHostport, firstPub, stopFirst := startTestSSHServer(t)
	defer stopFirst()
	secondHostport, secondPub, stopSecond := startTestSSHServer(t)
	defer stopSecond()

	if err := a.TrustHost(firstHostport, firstPub); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	gotPub, known, err := a.HostCheck(firstHostport)
	if err != nil || !known {
		t.Fatalf("HostCheck trusted port: known=%v err=%v", known, err)
	}
	if !bytes.Equal(gotPub.Marshal(), firstPub.Marshal()) {
		t.Fatal("host public key mismatch")
	}

	gotPub, known, err = a.HostCheck(secondHostport)
	if err != nil {
		t.Fatalf("second port must be unknown, not an error: %v", err)
	}
	if known {
		t.Fatal("trust on one port must not carry to another port")
	}
	if !bytes.Equal(gotPub.Marshal(), secondPub.Marshal()) {
		t.Fatal("captured public key mismatch")
	}
	if known, err := knownHostTrusted(a.known, secondHostport); known || !errors.Is(err, sshx.ErrUnknownHostKey) {
		t.Fatalf("second port must be unknown, got known=%v err=%v", known, err)
	}
	// Trusting the second port's own key is a separate decision and succeeds.
	if err := a.TrustHost(secondHostport, secondPub); err != nil {
		t.Fatalf("TrustHost second port: %v", err)
	}
	if len(a.KnownHostsList()) != 2 {
		t.Fatalf("KnownHostsList = %v, want one record per port", a.KnownHostsList())
	}
}

// startTestSSHServer runs an in-process SSH server that accepts the given
// authorized public keys. It is sufficient for HostKey capture and public-key
// authentication tests; it does not implement the git wire protocol.
func startTestSSHServer(t *testing.T, authorizedKeys ...ssh.PublicKey) (hostport string, hostPub ssh.PublicKey, cleanup func()) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			for _, k := range authorizedKeys {
				if bytes.Equal(k.Marshal(), key.Marshal()) {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("key not authorized")
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				serverConn, chans, reqs, err := ssh.NewServerConn(c, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						return
					}
					go func(in <-chan *ssh.Request) {
						for req := range in {
							if req.Type == "exec" {
								_ = req.Reply(true, nil)
								_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
							} else {
								_ = req.Reply(false, nil)
							}
							_ = channel.Close()
						}
					}(requests)
				}
				_ = serverConn.Close()
			}(conn)
		}
	}()
	return listener.Addr().String(), hostSigner.PublicKey(), func() {
		_ = listener.Close()
		<-done
	}
}

func TestHostCheck(t *testing.T) {
	// Unreachable host -> error.
	a := newTestApp(t)
	if _, _, err := a.HostCheck("127.0.0.1:1"); err == nil {
		t.Fatal("expected HostCheck on unreachable port to fail")
	}

	// Known-trusted server.
	a = newTestApp(t)
	hostport, pub, stop := startTestSSHServer(t)
	defer stop()
	if err := a.TrustHost(hostport, pub); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	gotPub, known, err := a.HostCheck(hostport)
	if err != nil {
		t.Fatalf("HostCheck: %v", err)
	}
	if !known {
		t.Fatal("expected host to be known")
	}
	if !bytes.Equal(gotPub.Marshal(), pub.Marshal()) {
		t.Fatal("host public key mismatch")
	}

	// Known server with a different key -> ErrHostKeyChanged.
	a = newTestApp(t)
	_, otherPub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.TrustHost(hostport, otherSigner.PublicKey()); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	_, known, err = a.HostCheck(hostport)
	if !errors.Is(err, sshx.ErrHostKeyChanged) {
		t.Fatalf("expected ErrHostKeyChanged, got %v", err)
	}
	if known {
		t.Fatal("expected known=false for changed host key")
	}
	// The report has to name both keys, or the user cannot tell a rotation
	// from an attack.
	for _, fp := range []string{sshx.HostKeyFingerprint(pub), sshx.HostKeyFingerprint(otherSigner.PublicKey())} {
		if !strings.Contains(err.Error(), fp) {
			t.Fatalf("change report %q does not name %s", err, fp)
		}
	}

	// Untrusted but reachable server -> pub, false, nil.
	a = newTestApp(t)
	gotPub, known, err = a.HostCheck(hostport)
	if err != nil {
		t.Fatalf("HostCheck untrusted: %v", err)
	}
	if known {
		t.Fatal("expected unknown host")
	}
	if !bytes.Equal(gotPub.Marshal(), pub.Marshal()) {
		t.Fatal("captured public key mismatch")
	}
}

func TestKnownHostTrusted(t *testing.T) {
	a := newTestApp(t)

	// Unreachable host propagates the error.
	if known, err := knownHostTrusted(a.known, "127.0.0.1:1"); err == nil || known {
		t.Fatalf("expected unreachable host to fail, got known=%v err=%v", known, err)
	}

	// Reachable host whose key is trusted.
	hostport, pub, stop := startTestSSHServer(t)
	defer stop()
	if err := a.TrustHost(hostport, pub); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	known, err := knownHostTrusted(a.known, hostport)
	if err != nil || !known {
		t.Fatalf("known=%v err=%v", known, err)
	}

	// Reachable host whose key is unknown.
	a = newTestApp(t)
	known, err = knownHostTrusted(a.known, hostport)
	if err == nil || known {
		t.Fatalf("expected unknown host, got known=%v err=%v", known, err)
	}
	if !errors.Is(err, sshx.ErrUnknownHostKey) {
		t.Fatalf("expected ErrUnknownHostKey, got %v", err)
	}

	// Reachable host whose key changed.
	a = newTestApp(t)
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.TrustHost(hostport, otherSigner.PublicKey()); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	known, err = knownHostTrusted(a.known, hostport)
	if err == nil || known {
		t.Fatalf("expected changed host error, got known=%v err=%v", known, err)
	}
	if !errors.Is(err, sshx.ErrHostKeyChanged) {
		t.Fatalf("expected ErrHostKeyChanged, got %v", err)
	}
}

func TestTestSSH(t *testing.T) {
	a := newTestApp(t)
	pemBytes := sshTestKey(t)
	k, err := a.ImportSSHKey(pemBytes, nil, []byte(testLockPass))
	if err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}

	// Locked -> ErrLocked.
	if err := a.TestSSH("github.com:22"); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}

	if err := a.UnlockSSH([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockSSH: %v", err)
	}

	// No key loaded after locking.
	a.Lock()
	if err := a.UnlockSSH([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockSSH: %v", err)
	}

	// Missing SSH key (remove stored key from disk).
	a2 := newTestApp(t)
	if err := a2.UnlockSSH([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockSSH without stored key: %v", err)
	}
	if err := a2.TestSSH("github.com:22"); err == nil {
		t.Fatal("expected TestSSH to fail without a stored SSH key")
	}

	// Connection failure to an unreachable host.
	if err := a.TestSSH("127.0.0.1:1"); err == nil {
		t.Fatal("expected TestSSH to fail for unreachable host")
	}

	// Successful authentication against the local test server.
	hostport, pub, stop := startTestSSHServer(t, k.Signer().PublicKey())
	defer stop()
	if err := a.TrustHost(hostport, pub); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	if err := a.TestSSH(hostport); err != nil {
		t.Fatalf("TestSSH: %v", err)
	}
}

func TestDefaultCloneDir(t *testing.T) {
	a := newTestApp(t)
	cases := []struct {
		url  string
		want string
	}{
		{"git@github.com:user/pass.git", filepath.Join(a.paths.StoresDir, "user-pass")},
		{"git@github.com:user/pass-store.git", filepath.Join(a.paths.StoresDir, "user-pass-store")},
		{"git@git.example.com:user/repo.git", filepath.Join(a.paths.StoresDir, "user-repo")},
	}
	for _, tc := range cases {
		if got := a.defaultCloneDir(tc.url); got != tc.want {
			t.Errorf("defaultCloneDir(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestCloneOrReuse(t *testing.T) {
	a := newTestApp(t)
	pemBytes := sshTestKey(t)
	if _, err := a.ImportSSHKey(pemBytes, nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}

	// Create a remote store using the file:// transport so no network is needed.
	remoteDir := filepath.Join(t.TempDir(), "remote.git")
	remoteRepo, err := goGit.PlainInit(remoteDir, true)
	if err != nil {
		t.Fatalf("PlainInit remote: %v", err)
	}
	_ = remoteRepo

	// Make the bare repo look like a pass store by creating a commit with .gpg-id.
	work := t.TempDir()
	workRepo, err := goGit.PlainInit(work, false)
	if err != nil {
		t.Fatalf("PlainInit work: %v", err)
	}
	if _, err := workRepo.CreateRemote(&goGitConfig.RemoteConfig{Name: "origin", URLs: []string{remoteDir}}); err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}
	if err := os.WriteFile(filepath.Join(work, ".gpg-id"), []byte("AABBCCDD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gitx.Add(work, ".gpg-id"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := gitx.Commit(work, "init", "T", "t@x"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := gitx.Push(work, nil); err != nil {
		t.Fatalf("Push: %v", err)
	}

	url := fileURL(remoteDir)
	target := filepath.Join(t.TempDir(), "cloned")

	// First clone creates the directory.
	if err := a.cloneOrReuse(url, target); err != nil {
		t.Fatalf("cloneOrReuse first: %v", err)
	}
	if _, err := store.Open(target); err != nil {
		t.Fatalf("cloned target is not a store: %v", err)
	}

	// Second call reuses the existing valid store.
	if err := a.cloneOrReuse(url, target); err != nil {
		t.Fatalf("cloneOrReuse reuse: %v", err)
	}

	// Empty leftover directory is removed and replaced.
	leftover := filepath.Join(t.TempDir(), "leftover")
	if err := os.MkdirAll(leftover, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := a.cloneOrReuse(url, leftover); err != nil {
		t.Fatalf("cloneOrReuse empty leftover: %v", err)
	}
	if _, err := store.Open(leftover); err != nil {
		t.Fatalf("leftover target is not a store: %v", err)
	}

	// Non-empty non-store directory is rejected.
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.cloneOrReuse(url, blocked); err == nil {
		t.Fatal("expected cloneOrReuse to refuse a non-empty non-store directory")
	}

	// Clone failure removes the temporary directory.
	if err := a.cloneOrReuse("file:///does/not/exist", filepath.Join(t.TempDir(), "fail")); err == nil {
		t.Fatal("expected cloneOrReuse to fail for bad URL")
	}
}

func TestCloneStoreValidation(t *testing.T) {
	a := newTestApp(t)
	pemBytes := sshTestKey(t)
	k, err := a.ImportSSHKey(pemBytes, nil, []byte(testLockPass))
	if err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.UnlockSSH([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockSSH: %v", err)
	}

	// Cannot determine host from URL.
	if err := a.CloneStore("not-a-url", ""); err == nil {
		t.Fatal("expected CloneStore to fail for bad URL")
	}

	// SSH key not loaded.
	a2 := newTestApp(t)
	if err := a2.CloneStore("git@github.com:user/pass.git", ""); err == nil {
		t.Fatal("expected CloneStore to fail without SSH key")
	}

	// Host not trusted (unreachable).
	if err := a.CloneStore("git@127.0.0.1:1:user/pass.git", ""); err == nil {
		t.Fatal("expected CloneStore to fail for untrusted host")
	}

	// Host key changed.
	hostport, pub, stop := startTestSSHServer(t, k.Signer().PublicKey())
	defer stop()
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.TrustHost(hostport, otherSigner.PublicKey()); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	url := fmt.Sprintf("git@127.0.0.1:%s:user/pass.git", hostport)
	if err := a.CloneStore(url, ""); err == nil {
		t.Fatal("expected CloneStore to fail for changed host key")
	}

	// Trusted host but clone fails because the server does not serve git.
	a3 := newTestApp(t)
	if _, err := a3.ImportSSHKey(pemBytes, nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a3.UnlockSSH([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockSSH: %v", err)
	}
	if err := a3.TrustHost(hostport, pub); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	if err := a3.CloneStore(url, ""); err == nil {
		t.Fatal("expected CloneStore to fail when clone fails")
	}

	// Explicit non-empty target directory is rejected.
	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a4 := newTestApp(t)
	if _, err := a4.ImportSSHKey(pemBytes, nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a4.UnlockSSH([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockSSH: %v", err)
	}
	hostport4, pub4, stop4 := startTestSSHServer(t, k.Signer().PublicKey())
	defer stop4()
	if err := a4.TrustHost(hostport4, pub4); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	url4 := fmt.Sprintf("git@%s:user/pass.git", hostport4)
	if err := a4.CloneStore(url4, target); err == nil {
		t.Fatal("expected CloneStore to refuse a non-empty target")
	}
}

// setupGitStore creates a pass store directory that is also a git repository
// with an origin remote pointing at a local bare repository.
func setupGitStore(t *testing.T, fp string) (storeDir, bareDir string) {
	t.Helper()
	bareDir = filepath.Join(t.TempDir(), "remote.git")
	if _, err := goGit.PlainInit(bareDir, true); err != nil {
		t.Fatalf("PlainInit bare: %v", err)
	}

	seed := t.TempDir()
	workRepo, err := goGit.PlainInit(seed, false)
	if err != nil {
		t.Fatalf("PlainInit seed: %v", err)
	}
	if _, err := workRepo.CreateRemote(&goGitConfig.RemoteConfig{Name: "origin", URLs: []string{bareDir}}); err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}
	if err := os.WriteFile(filepath.Join(seed, ".gpg-id"), []byte(fp+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gitx.Add(seed, ".gpg-id"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := gitx.Commit(seed, "init", "T", "t@x"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := gitx.Push(seed, nil); err != nil {
		t.Fatalf("Push: %v", err)
	}

	storeDir = filepath.Join(t.TempDir(), "store")
	if err := gitx.Clone(fileURL(bareDir), storeDir, nil); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return storeDir, bareDir
}

func TestSync(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	pemBytes := sshTestKey(t)
	if _, err := a.ImportSSHKey(pemBytes, nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}

	// Locked -> ErrLocked.
	if _, err := a.Sync(); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// No store open.
	a2 := newTestApp(t)
	if _, err := a2.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if _, err := a2.ImportSSHKey(pemBytes, nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a2.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := a2.Sync(); err == nil {
		t.Fatal("expected Sync to fail without a store")
	}

	// Store is not a git repository.
	plainDir := filepath.Join(t.TempDir(), "plain")
	if _, err := store.Create(plainDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(plainDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if _, err := a.Sync(); err == nil {
		t.Fatal("expected Sync to fail for a non-git store")
	}

	// Real git-backed store: up to date.
	storeDir, bareDir := setupGitStore(t, fp)
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	summary, err := a.Sync()
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !strings.Contains(summary, "Already up to date") {
		t.Fatalf("Sync summary = %q", summary)
	}

	// Local commit -> push.
	if err := a.SavePassword("site", []byte("secret\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	summary, err = a.Sync()
	if err != nil {
		t.Fatalf("Sync after save: %v", err)
	}
	if !strings.Contains(summary, "pushed local commits") {
		t.Fatalf("Sync summary after push = %q", summary)
	}

	// Remote update -> fetch and pull.
	other := t.TempDir()
	if _, err := goGit.PlainClone(other, false, &goGit.CloneOptions{URL: fileURL(bareDir)}); err != nil {
		t.Fatalf("PlainClone other: %v", err)
	}
	if err := os.WriteFile(filepath.Join(other, "remote.txt"), []byte("remote\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gitx.Add(other, "remote.txt"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := gitx.Commit(other, "remote update", "R", "r@x"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := gitx.Push(other, nil); err != nil {
		t.Fatalf("Push: %v", err)
	}
	summary, err = a.Sync()
	if err != nil {
		t.Fatalf("Sync after remote update: %v", err)
	}
	if !strings.Contains(summary, "pulled updates") {
		t.Fatalf("Sync summary after pull = %q", summary)
	}
}

func TestSyncNoSSHKey(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir, _ := setupGitStore(t, fp)
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := a.Sync(); err == nil {
		t.Fatal("expected Sync to fail without SSH key")
	}
}

func TestSyncLocalOnlyNoRemote(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if _, err := goGit.PlainInit(storeDir, false); err != nil {
		t.Fatal(err)
	}
	if err := gitx.Add(storeDir, ".gpg-id"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitx.Commit(storeDir, "init", "T", "t@x"); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	// Sync on a local-only store should succeed without an SSH key.
	summary, err := a.Sync()
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !strings.Contains(summary, "No remote configured") {
		t.Fatalf("expected 'No remote configured' in summary, got %q", summary)
	}
}

func TestStatusComprehensive(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])

	// No store open.
	if _, err := a.Status(); err == nil {
		t.Fatal("expected Status to fail without a store")
	}

	// Plain store (not a git repository).
	plainDir := filepath.Join(t.TempDir(), "plain")
	if _, err := store.Create(plainDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(plainDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	status, err := a.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(status, "not a git repository") {
		t.Fatalf("Status = %q", status)
	}

	// Git-backed store without remote.
	a2 := newTestApp(t)
	if _, err := a2.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	gitDir := filepath.Join(t.TempDir(), "git")
	if _, err := goGit.PlainInit(gitDir, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, ".gpg-id"), []byte(fp+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gitx.Add(gitDir, ".gpg-id"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := gitx.Commit(gitDir, "init", "T", "t@x"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := a2.OpenLocalStore(gitDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	status, err = a2.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(status, "No remote configured") {
		t.Fatalf("Status = %q", status)
	}

	// Git-backed store with remote, in sync.
	storeDir, _ := setupGitStore(t, fp)
	if err := a2.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	status, err = a2.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(status, "In sync with origin") {
		t.Fatalf("Status = %q", status)
	}

	// Ahead of origin.
	if err := a2.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a2.SavePassword("ahead", []byte("secret\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	status, err = a2.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(status, "ahead") {
		t.Fatalf("Status = %q", status)
	}

	// Behind origin: fresh clone, then push from another worktree.
	behindDir, behindBare := setupGitStore(t, fp)
	a3 := newTestApp(t)
	if err := a3.OpenLocalStore(behindDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	other := t.TempDir()
	if _, err := goGit.PlainClone(other, false, &goGit.CloneOptions{URL: fileURL(behindBare)}); err != nil {
		t.Fatalf("PlainClone other: %v", err)
	}
	if err := os.WriteFile(filepath.Join(other, "behind.txt"), []byte("remote\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gitx.Add(other, "behind.txt"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := gitx.Commit(other, "behind", "R", "r@x"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := gitx.Push(other, nil); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if err := gitx.Fetch(behindDir, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	status, err = a3.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(status, "behind") {
		t.Fatalf("Status = %q", status)
	}

	// Dirty working tree.
	if err := os.WriteFile(filepath.Join(behindDir, "dirty.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err = a3.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(status, "uncommitted changes") {
		t.Fatalf("Status = %q", status)
	}
}

func TestCommitPasswordPaths(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Not a git repository.
	if err := a.CommitPassword("site"); err == nil {
		t.Fatal("expected CommitPassword to fail for non-git store")
	}

	// Initialize git and create a password; CommitPassword removes it.
	if _, err := goGit.PlainInit(storeDir, false); err != nil {
		t.Fatal(err)
	}
	if err := a.SavePassword("remove-me", []byte("secret\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	if err := os.Remove(filepath.Join(storeDir, "remove-me.gpg")); err != nil {
		t.Fatal(err)
	}
	if err := a.CommitPassword("remove-me"); err != nil {
		t.Fatalf("CommitPassword remove: %v", err)
	}
}

func TestPasswordExistsErrors(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.PasswordExists("x"); err == nil {
		t.Fatal("expected PasswordExists to fail without a store")
	}

	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}

	exists, err := a.PasswordExists("missing")
	if err != nil {
		t.Fatalf("PasswordExists: %v", err)
	}
	if exists {
		t.Fatal("expected missing password not to exist")
	}
}

func TestSavePasswordNoStore(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.SavePassword("x", []byte("secret\n")); err == nil {
		t.Fatal("expected SavePassword to fail without a store")
	}
}

func TestSSHPublicKeyErrors(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.SSHPublicKey(); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
	armored := armoredTestKey(t)
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if err := a.UnlockPGP([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockPGP: %v", err)
	}
	if _, err := a.SSHPublicKey(); err == nil {
		t.Fatal("expected SSHPublicKey to fail without SSH key loaded")
	}
}

func TestOpenLocalStoreValidation(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}

	// Unlocked with a matching key: recipients are validated.
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}

	// Unlocked with a non-matching recipient fails.
	a2 := newTestApp(t)
	if _, err := a2.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if err := a2.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	otherDir := filepath.Join(t.TempDir(), "other")
	if _, err := store.Create(otherDir, []string{"DEADBEEF"}); err != nil {
		t.Fatal(err)
	}
	if err := a2.OpenLocalStore(otherDir); err == nil {
		t.Fatal("expected OpenLocalStore to fail for foreign recipient")
	}
}

func TestStoreRemoteURL(t *testing.T) {
	a := newTestApp(t)
	if got := a.StoreRemoteURL(); got != "" {
		t.Fatalf("StoreRemoteURL without store = %q, want empty", got)
	}

	// A plain pass store (no git) reports no remote.
	plainDir := filepath.Join(t.TempDir(), "plain")
	if _, err := store.Create(plainDir, []string{"DEADBEEF"}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := a.OpenLocalStore(plainDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if got := a.StoreRemoteURL(); got != "" {
		t.Fatalf("StoreRemoteURL for non-git store = %q, want empty", got)
	}

	// A store opened locally inside a git repository reports the origin URL.
	remoteDir := filepath.Join(t.TempDir(), "remote.git")
	if _, err := goGit.PlainInit(remoteDir, true); err != nil {
		t.Fatalf("PlainInit bare: %v", err)
	}
	workDir := filepath.Join(t.TempDir(), "work")
	if _, err := store.Create(workDir, []string{"DEADBEEF"}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	repo, err := goGit.PlainInit(workDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	if _, err := repo.CreateRemote(&goGitConfig.RemoteConfig{Name: "origin", URLs: []string{remoteDir}}); err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}
	if err := gitx.Add(workDir, ".gpg-id"); err != nil {
		t.Fatalf("gitx.Add: %v", err)
	}
	if _, err := gitx.Commit(workDir, "init store", "Tester", "t@example.com"); err != nil {
		t.Fatalf("gitx.Commit: %v", err)
	}
	if err := a.OpenLocalStore(workDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if got := a.StoreRemoteURL(); got != remoteDir {
		t.Fatalf("StoreRemoteURL = %q, want %q", got, remoteDir)
	}
}

func TestUnlockPGPWrongPassphrase(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if err := a.UnlockPGP([]byte("wrong")); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
}

func TestLoadStoredSSHKeyErrors(t *testing.T) {
	a := newTestApp(t)
	if err := a.LoadStoredSSHKey(nil); err == nil {
		t.Fatal("expected LoadStoredSSHKey to fail without stored key")
	}

	// Wrong passphrase for an encrypted key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "unit@example.com", []byte("secret"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if _, err := a.ImportSSHKey(pemBytes, []byte("secret"), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.LoadStoredSSHKey([]byte("wrong")); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
}

func TestUnlockSSHWrongPassphrase(t *testing.T) {
	a := newTestApp(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "unit@example.com", []byte("secret"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if _, err := a.ImportSSHKey(pemBytes, []byte("secret"), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.UnlockSSH([]byte("wrong")); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
}

func TestUnlockSSHFailureDoesNotUnlockPGP(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "unit@example.com", []byte("secret"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if _, err := a.ImportSSHKey(pemBytes, []byte("secret"), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.Unlock([]byte("wrong")); err == nil {
		t.Fatal("expected Unlock to fail with wrong passphrase")
	}
	if a.IsUnlocked() {
		t.Fatal("expected app to remain locked after failed SSH unlock")
	}
}

func TestStartAutoLockWithZeroTimeout(t *testing.T) {
	a := newTestApp(t)
	a.startAutoLockWithTimeout(0)
	// A zero timeout must not panic and must not start a goroutine that races.
	a.Lock()
}

// withShortAutoLockTick shrinks the idle re-evaluation interval for a and
// returns the restore func. Idle timeouts are minute-granular, so the
// goroutine's tick is the only knob a test can turn to observe a drop. It is
// per-App state on purpose: a package global would be written here while a
// timer goroutine from an earlier test may still be reading it.
func withShortAutoLockTick(t *testing.T, a *App) func() {
	t.Helper()
	prev := a.autoLockTick
	a.setAutoLockTick(time.Millisecond)
	return func() { a.setAutoLockTick(prev) }
}

// waitForCondition polls cond until it holds or the test budget runs out.
func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// keyDiskLen reads the retained vault key length under the app lock.
func keyDiskLen(a *App) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.keyDisk)
}

// pgpSecretMaterialResident reports resident OpenPGP material under the app
// lock. The idle auto-lock goroutine mutates the same service fields under that
// lock, so a test may not read them directly.
func pgpSecretMaterialResident(a *App) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pgpSvc.HasSecretMaterial()
}

// timerChan returns the current idle timer stop channel under the app lock.
func timerChan(a *App) chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stopTimer
}

// ImportSSHKey leaves a decrypted signer resident without starting a session,
// so the idle auto-lock has to bound it too.
func TestAutoLockDropsResidentSSHKeyWhileLocked(t *testing.T) {
	a := newTestApp(t)
	defer withShortAutoLockTick(t, a)()
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if a.IsUnlocked() {
		t.Fatal("expected the app to stay locked after import")
	}
	if !a.HasSSHKeyLoaded() {
		t.Fatal("expected the SSH signer to be resident after import")
	}
	a.startAutoLockWithTimeout(time.Millisecond)
	waitForCondition(t, "the idle auto-lock to drop the SSH signer", func() bool {
		return !a.HasSSHKeyLoaded()
	})
}

// LoadStoredSSHKey is reachable from the locked UI, so the signer it loads
// while the session stays locked must not outlive the idle timeout.
func TestAutoLockDropsStoredSSHKeyLoadedWhileLocked(t *testing.T) {
	a := newTestApp(t)
	defer withShortAutoLockTick(t, a)()
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	a.Lock()
	if err := a.LoadStoredSSHKey([]byte(testLockPass)); err != nil {
		t.Fatalf("LoadStoredSSHKey: %v", err)
	}
	if a.IsUnlocked() {
		t.Fatal("expected LoadStoredSSHKey to leave the session locked")
	}
	if !a.HasSSHKeyLoaded() {
		t.Fatal("expected LoadStoredSSHKey to load the signer for transport")
	}
	a.startAutoLockWithTimeout(time.Millisecond)
	waitForCondition(t, "the idle auto-lock to drop the transport signer", func() bool {
		return !a.HasSSHKeyLoaded()
	})
}

// ImportPGPKey leaves decrypted entities and the passphrase resident without
// starting a session, so the idle auto-lock has to drop those too.
func TestAutoLockDropsImportedPGPKeyWhileLocked(t *testing.T) {
	a := newTestApp(t)
	defer withShortAutoLockTick(t, a)()
	if _, err := a.ImportPGPKey(armoredTestKey(t), []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if a.IsUnlocked() {
		t.Fatal("expected the app to stay locked after import")
	}
	if !pgpSecretMaterialResident(a) {
		t.Fatal("expected decrypted OpenPGP entities to be resident after import")
	}
	a.startAutoLockWithTimeout(time.Millisecond)
	waitForCondition(t, "the idle auto-lock to drop the OpenPGP entities", func() bool {
		return !pgpSecretMaterialResident(a)
	})
}

// The vault key is only ever read by ChangeLockPassword, which needs an
// unlocked session, so the key-loading paths must not retain it.
func TestKeyLoadingPathsDoNotRetainKeyDisk(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.ImportPGPKey(armoredTestKey(t), []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if n := keyDiskLen(a); n != 0 {
		t.Fatalf("ImportPGPKey retained %d bytes of the vault key", n)
	}
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if n := keyDiskLen(a); n != 0 {
		t.Fatalf("ImportSSHKey retained %d bytes of the vault key", n)
	}
	if err := a.LoadStoredSSHKey([]byte(testLockPass)); err != nil {
		t.Fatalf("LoadStoredSSHKey: %v", err)
	}
	if n := keyDiskLen(a); n != 0 {
		t.Fatalf("LoadStoredSSHKey retained %d bytes of the vault key", n)
	}
	if !a.HasSSHKeyLoaded() {
		t.Fatal("expected LoadStoredSSHKey to keep the signer for transport")
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if keyDiskLen(a) == 0 {
		t.Fatal("expected an unlocked session to retain the vault key")
	}
}

// Raising the idle timeout while key material is resident must arm the timer;
// otherwise the material it is meant to bound has nothing watching it.
func TestSetAutoLockArmsTimerForResidentKeyMaterial(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.SetAutoLock(0); err != nil {
		t.Fatalf("SetAutoLock(0): %v", err)
	}
	disabled := timerChan(a)
	if err := a.SetAutoLock(1); err != nil {
		t.Fatalf("SetAutoLock(1): %v", err)
	}
	if timerChan(a) == disabled {
		t.Fatal("SetAutoLock must re-arm the idle timer while key material is resident")
	}
	if !a.HasSSHKeyLoaded() {
		t.Fatal("re-arming the timer must not drop key material on its own")
	}
}

func TestStoredStoresReadDirError(t *testing.T) {
	a := newTestApp(t)
	// Remove the stores directory so ReadDir returns an error.
	if err := os.RemoveAll(a.paths.StoresDir); err != nil {
		t.Fatal(err)
	}
	if stores := a.StoredStores(); len(stores) != 0 {
		t.Fatalf("StoredStores = %v", stores)
	}
}

func TestShowPasswordErrors(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Missing password.
	if _, err := a.ShowPassword("missing"); err == nil {
		t.Fatal("expected ShowPassword to fail for missing entry")
	}

	// Locked.
	a.Lock()
	if _, err := a.ShowPassword("x"); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

func TestImportPGPKeyStoreFailure(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	// Replace the keys directory with a regular file so vault.Store fails.
	if err := os.RemoveAll(a.paths.KeysDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.paths.KeysDir, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err == nil {
		t.Fatal("expected ImportPGPKey to fail when the key cannot be stored")
	}
}

func TestImportSSHKeyStoreFailure(t *testing.T) {
	a := newTestApp(t)
	pemBytes := sshTestKey(t)
	if err := os.RemoveAll(a.paths.KeysDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.paths.KeysDir, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ImportSSHKey(pemBytes, nil, []byte(testLockPass)); err == nil {
		t.Fatal("expected ImportSSHKey to fail when the key cannot be stored")
	}
}

func TestValidateStoreLockedNoPGPKey(t *testing.T) {
	a := newTestApp(t)
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{"AABBCCDD"}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err == nil {
		t.Fatal("expected Unlock to fail without a PGP key for the configured store")
	}
}

func TestListPasswordsNoStore(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.ListPasswords(); err == nil {
		t.Fatal("expected ListPasswords to fail without a store")
	}
}

func TestRemovePasswordNoStore(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.RemovePassword("x"); err == nil {
		t.Fatal("expected RemovePassword to fail without a store")
	}
}

func TestCloneHostportBadURL(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.CloneHostport(""); err == nil {
		t.Fatal("expected CloneHostport to fail for empty URL")
	}
}

func TestShowTOTP(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	fp := entityFingerprint(el[0])

	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Entry with an otpauth:// URI in the body.
	otpBody := "mypass\nhttps://example.com\notpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
	if err := a.SavePassword("totp/test", []byte(otpBody)); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	code, err := a.ShowTOTP("totp/test")
	if err != nil {
		t.Fatalf("ShowTOTP: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit TOTP code, got %q", code)
	}

	// Entry without an otpauth:// URI should fail.
	if err := a.SavePassword("no-totp/test", []byte("mypass\nnotes\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	if _, err := a.ShowTOTP("no-totp/test"); err == nil {
		t.Fatal("expected ShowTOTP to fail for an entry without otpauth URI")
	}

	// Locked app should fail.
	a.Lock()
	if _, err := a.ShowTOTP("totp/test"); err == nil {
		t.Fatal("expected ShowTOTP to fail when locked")
	}
}

func TestShowTOTPNotFound(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	fp := entityFingerprint(el[0])

	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := a.ShowTOTP("nonexistent/path"); err == nil {
		t.Fatal("expected ShowTOTP to fail for a non-existent password")
	}
}

// unlockWithStore boots an app with an imported PGP key and an unlocked store.
func unlockWithStore(t *testing.T) *App {
	t.Helper()
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return a
}

func TestNotes(t *testing.T) {
	a := unlockWithStore(t)

	if err := a.SavePassword("site", []byte("secret\nuser: alice\nurl: https://site.com\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	// The two shapes an entry can take: a body, and a password with nothing
	// below it. pass writes a trailing newline, so the second case is a stored
	// file whose only line is the password.
	if err := a.SavePassword("bare", []byte("secret")); err != nil {
		t.Fatalf("SavePassword bare: %v", err)
	}
	if err := a.SavePassword("empty-line", []byte("secret\n")); err != nil {
		t.Fatalf("SavePassword empty line: %v", err)
	}

	cases := map[string]string{
		"site":       "user: alice\nurl: https://site.com\n",
		"bare":       "",
		"empty-line": "",
	}
	for name, want := range cases {
		got, err := a.Notes(name)
		if err != nil {
			t.Fatalf("Notes(%q): %v", name, err)
		}
		if got != want {
			t.Errorf("Notes(%q) = %q, want %q", name, got, want)
		}
		// The password must not survive anywhere in the answer: this is the
		// call that prefills an edit form's notes field.
		if strings.Contains(got, "secret") {
			t.Errorf("Notes(%q) leaked the password: %q", name, got)
		}
	}

	if _, err := a.Notes("missing"); err == nil {
		t.Error("expected Notes on a missing entry to fail")
	}
	if _, err := a.Notes("site"); err != nil {
		t.Errorf("re-reading notes should not be a one-shot: %v", err)
	}

	a.Lock()
	if _, err := a.Notes("site"); err == nil {
		t.Error("expected Notes to fail while locked")
	}
}

func TestUsername(t *testing.T) {
	a := unlockWithStore(t)
	if a.UsernameSource() != "auto" {
		t.Fatalf("UsernameSource = %q", a.UsernameSource())
	}

	if err := a.SavePassword("site", []byte("secret\nusername: alice\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	if err := a.SavePassword("email@example.com", []byte("secret\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	if err := a.SavePassword("example.com/alice", []byte("secret\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	if err := a.SavePassword("example.com", []byte("secret\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}

	// Auto mode: body field when present, file name otherwise.
	if u, err := a.Username("site"); err != nil || u != "alice" {
		t.Fatalf("Username(site) = %q, %v", u, err)
	}
	if u, err := a.Username("email@example.com"); err != nil || u != "email@example.com" {
		t.Fatalf("Username(email@example.com) = %q, %v", u, err)
	}
	if u, err := a.Username("example.com/alice"); err != nil || u != "alice" {
		t.Fatalf("Username(example.com/alice) = %q, %v", u, err)
	}
	if u, err := a.Username("example.com"); err != nil || u != "" {
		t.Fatalf("Username(example.com) = %q, %v", u, err)
	}

	if err := a.SetUsernameSource("body"); err != nil {
		t.Fatalf("SetUsernameSource(body): %v", err)
	}
	if u, err := a.Username("site"); err != nil || u != "alice" {
		t.Fatalf("body mode Username(site) = %q, %v", u, err)
	}
	if u, err := a.Username("email@example.com"); err != nil || u != "" {
		t.Fatalf("body mode Username(email@example.com) = %q, %v", u, err)
	}

	if err := a.SetUsernameSource("filename"); err != nil {
		t.Fatalf("SetUsernameSource(filename): %v", err)
	}
	if u, err := a.Username("email@example.com"); err != nil || u != "email@example.com" {
		t.Fatalf("filename mode Username(email@example.com) = %q, %v", u, err)
	}
	if u, err := a.Username("site"); err != nil || u != "site" {
		t.Fatalf("filename mode Username(site) = %q, %v", u, err)
	}
	if u, err := a.Username("example.com"); err != nil || u != "" {
		t.Fatalf("filename mode Username(example.com) = %q, %v", u, err)
	}

	if err := a.SetUsernameSource("bogus"); err == nil {
		t.Fatal("expected SetUsernameSource to reject an unknown mode")
	}

	if _, err := a.Username("nonexistent/path"); err == nil {
		t.Fatal("expected Username to fail for a non-existent password")
	}

	a.Lock()
	if _, err := a.Username("site"); err == nil {
		t.Fatal("expected Username to fail when locked")
	}
}

func TestHasTOTP(t *testing.T) {
	a := unlockWithStore(t)

	otpBody := "mypass\nhttps://example.com\notpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
	if err := a.SavePassword("totp/test", []byte(otpBody)); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	ok, err := a.HasTOTP("totp/test")
	if err != nil || !ok {
		t.Fatalf("HasTOTP(totp/test) = %v, %v", ok, err)
	}

	if err := a.SavePassword("no-totp/test", []byte("mypass\nnotes\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	ok, err = a.HasTOTP("no-totp/test")
	if err != nil || ok {
		t.Fatalf("HasTOTP(no-totp/test) = %v, %v", ok, err)
	}

	if _, err := a.HasTOTP("nonexistent/path"); err == nil {
		t.Fatal("expected HasTOTP to fail for a non-existent password")
	}

	a.Lock()
	if _, err := a.HasTOTP("totp/test"); err == nil {
		t.Fatal("expected HasTOTP to fail when locked")
	}
}

// TestUpdatedAt pins where a "last updated" date comes from and what it does
// not require: the pass format carries no timestamp of its own, so the answer
// is the .gpg file's mtime, which is metadata like the file list and therefore
// available without unlocking — while still refusing an entry that is not
// there instead of reporting the zero time.
func TestUpdatedAt(t *testing.T) {
	a := unlockWithStore(t)

	if err := a.SavePassword("site", []byte("secret\nnotes\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	before, err := a.UpdatedAt("site")
	if err != nil {
		t.Fatalf("UpdatedAt: %v", err)
	}
	if before.IsZero() {
		t.Fatal("UpdatedAt returned the zero time")
	}

	if _, err := a.UpdatedAt("nonexistent/path"); err == nil {
		t.Fatal("expected UpdatedAt to fail for a non-existent password")
	}

	a.Lock()
	if got, err := a.UpdatedAt("site"); err != nil || got.IsZero() {
		t.Fatalf("UpdatedAt while locked = %v, %v; it reads a file time, not a secret", got, err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// A save replaces the file, so the reported time has to move with it.
	// Backdating makes the assertion exact instead of depending on how fine the
	// filesystem's write clock is.
	past := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	file := filepath.Join(a.storePath().Root(), "site.gpg")
	if err := os.Chtimes(file, past, past); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if err := a.SavePassword("site", []byte("secret\nnotes\nedited\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	after, err := a.UpdatedAt("site")
	if err != nil {
		t.Fatalf("UpdatedAt: %v", err)
	}
	if !after.After(past) {
		t.Fatalf("UpdatedAt = %v after a save; want it to advance past %v", after, past)
	}
}

// TestUpdatedAtNoStore covers the lazy-open path: asking for a date before any
// store has been opened must say so rather than panic or answer zero.
func TestUpdatedAtNoStore(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.UpdatedAt("site"); err == nil {
		t.Fatal("expected UpdatedAt to fail without a store")
	}
}

// TestStorePathConcurrentWithOpenLocalStore exercises the pairing the GUI
// creates: Wails dispatches every binding call on its own goroutine, so a
// config read (StorePath, bound to the settings panel) runs while a store
// switch (OpenLocalStore) writes the same field. Run under -race this pins that
// the read takes a.mu; without it the field is an unsynchronized 2-word string
// access that can tear.
func TestStorePathConcurrentWithOpenLocalStore(t *testing.T) {
	a := newTestApp(t)
	dirs := []string{
		filepath.Join(t.TempDir(), "one"),
		filepath.Join(t.TempDir(), "two"),
	}
	for _, dir := range dirs {
		if _, err := store.Create(dir, []string{"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"}); err != nil {
			t.Fatalf("store.Create: %v", err)
		}
	}

	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; i < 20; i++ {
			if err := a.OpenLocalStore(dirs[i%len(dirs)]); err != nil {
				t.Errorf("OpenLocalStore: %v", err)
				return
			}
		}
	}()

	// The readers deliberately hold no lock: that is the bug under test.
	var readers sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = a.StorePath()
				}
			}
		}()
	}
	writer.Wait()
	close(stop)
	readers.Wait()

	// The last write wins, and the reader reports the same value.
	want := dirs[19%len(dirs)]
	if got := a.StorePath(); got != want {
		t.Fatalf("StorePath = %q, want %q", got, want)
	}
}

// TestGitAuthorConcurrentWithSetGitAuthor pins the invariant behind the commit
// author reads: SetGitAuthor writes a.cfg.GitAuthorName/GitAuthorEmail under
// a.mu, and every reader goes through the locked gitAuthor accessor. The reader
// spins because SetGitAuthor's write is followed within nanoseconds by
// saveConfig's whole-struct copy, which is itself a read of the same words and
// masks the write in the detector's shadow state; a caller that reads at a
// human timescale (a real commit) would let the race through unreported.
func TestGitAuthorConcurrentWithSetGitAuthor(t *testing.T) {
	a := newTestApp(t)

	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; i < 20; i++ {
			if err := a.SetGitAuthor(fmt.Sprintf("Tester %d", i), fmt.Sprintf("t%d@example.com", i)); err != nil {
				t.Errorf("SetGitAuthor: %v", err)
				return
			}
		}
	}()

	var readers sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = a.gitAuthor()
				}
			}
		}()
	}
	writer.Wait()
	close(stop)
	readers.Wait()

	name, email := a.gitAuthor()
	if name != "Tester 19" || email != "t19@example.com" {
		t.Fatalf("gitAuthor = %q, %q", name, email)
	}
}

// TestCommitPathsConcurrentWithSetGitAuthor runs the real commit paths against
// SetGitAuthor: autoCommit is reached from SavePassword/RemovePassword and
// CommitPassword from the entry menu, and Wails dispatches each on its own
// goroutine, so both can read the author while a settings save rewrites it.
func TestCommitPathsConcurrentWithSetGitAuthor(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if _, err := goGit.PlainInit(storeDir, false); err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	if err := gitx.Add(storeDir, ".gpg-id"); err != nil {
		t.Fatalf("gitx.Add: %v", err)
	}
	if _, err := gitx.Commit(storeDir, "init store", "Tester", "t@example.com"); err != nil {
		t.Fatalf("gitx.Commit: %v", err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.SavePassword("race/entry", []byte("secret123\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	if err := a.SetGitAuthor("Race Tester", "race@example.com"); err != nil {
		t.Fatalf("SetGitAuthor: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if err := a.SetGitAuthor(fmt.Sprintf("Tester %d", i), fmt.Sprintf("t%d@example.com", i)); err != nil {
				t.Errorf("SetGitAuthor: %v", err)
				return
			}
		}
	}()

	// The two commit paths are serialized against each other because a go-git
	// worktree admits one operation at a time. That mutex orders the readers
	// only; neither is ordered against the SetGitAuthor writes.
	var gitMu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		gitMu.Lock()
		defer gitMu.Unlock()
		for i := 0; i < 10; i++ {
			a.autoCommit("Save", "race/entry")
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		gitMu.Lock()
		defer gitMu.Unlock()
		for i := 0; i < 10; i++ {
			if err := a.CommitPassword("race/entry"); err != nil && !errors.Is(err, gitx.ErrUpToDate) {
				t.Errorf("CommitPassword: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	name, email := a.gitAuthor()
	if name != "Tester 9" || email != "t9@example.com" {
		t.Fatalf("gitAuthor = %q, %q", name, email)
	}
}

// TestImportPGPKeyConcurrentWithResidentCheck covers the import path against
// the idle auto-lock goroutine, which reads the OpenPGP service's entity list
// on every tick under a.mu. ImportSecret replaces that list in place, so it has
// to run under the same lock; the reader here takes it, exactly as the tick does.
func TestImportPGPKeyConcurrentWithResidentCheck(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)

	var importers sync.WaitGroup
	importers.Add(1)
	go func() {
		defer importers.Done()
		// Each import re-derives the vault key (Argon2id), so a few rounds are
		// enough to keep the writer busy while the reader spins.
		for i := 0; i < 3; i++ {
			if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
				t.Errorf("ImportPGPKey: %v", err)
				return
			}
		}
	}()

	var readers sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 2; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = pgpSecretMaterialResident(a)
				}
			}
		}()
	}
	importers.Wait()
	close(stop)
	readers.Wait()

	if !pgpSecretMaterialResident(a) {
		t.Fatal("expected the imported key to be resident after the last import")
	}
}
