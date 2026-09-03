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
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	goGit "github.com/go-git/go-git/v5"
	goGitConfig "github.com/go-git/go-git/v5/config"
	"github.com/oxcafedead/passone/internal/gitx"
	"github.com/oxcafedead/passone/internal/sshx"
	"github.com/oxcafedead/passone/internal/store"
	"golang.org/x/crypto/ssh"
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

	a.Lock()
	if err := a.Unlock([]byte(testLockPass)); err == nil {
		t.Fatal("old lock password should no longer work after change")
	}
	if err := a.Unlock([]byte("new-lock-pass")); err != nil {
		t.Fatalf("Unlock with new password: %v", err)
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

	cases := map[string]string{
		"git@github.com:user/pass.git":                 "github.com",
		"ssh://git@github.com/user/pass.git":           "github.com",
		"git@git.example.com:2222/user/pass-store.git": "git.example.com",
		"not-a-url": "not-a-url",
	}
	for in, want := range cases {
		if got := gitHostFromURL(in); got != want {
			t.Fatalf("gitHostFromURL(%q) = %q, want %q", in, got, want)
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
	if err == nil {
		t.Fatal("expected error for changed host key")
	}
	if known {
		t.Fatal("expected known=false for changed host key")
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
