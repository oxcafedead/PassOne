package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	goGit "github.com/go-git/go-git/v5"
	"github.com/oxcafedead/passone/internal/gitx"
	"github.com/oxcafedead/passone/internal/store"
	"golang.org/x/crypto/ssh"
)

const testPGPPassphrase = "app-test-pass"

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

	infos, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase))
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
	if err := a.Unlock([]byte(testPGPPassphrase), nil); err != nil {
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
	if err := a.Unlock([]byte("wrong"), nil); err == nil {
		t.Fatal("expected wrong pgp passphrase to fail")
	}
	if err := a.Unlock([]byte(testPGPPassphrase), nil); err != nil {
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

	if err := a.Unlock(nil, nil); err != nil {
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
	if err := a.Unlock(nil, nil); err != nil {
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
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase)); err != nil {
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
	if err := a.Unlock([]byte(testPGPPassphrase), nil); err != nil {
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
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase)); err != nil {
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
	if err := a.Unlock([]byte(testPGPPassphrase), nil); err != nil {
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
	k, err := a.ImportSSHKey(pemBytes, nil)
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

func TestUnlockPGPOnly(t *testing.T) {
	a := newTestApp(t)
	armored := armoredTestKey(t)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fp := entityFingerprint(el[0])
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := a.UnlockPGP([]byte(testPGPPassphrase)); err != nil {
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
	if _, err := a.ImportSSHKey(pemBytes, nil); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.UnlockSSH(nil); err != nil {
		t.Fatalf("UnlockSSH: %v", err)
	}
	if !a.HasSSHKeyLoaded() {
		t.Fatal("expected SSH key loaded")
	}
}

func TestLoadStoredSSHKey(t *testing.T) {
	a := newTestApp(t)
	pemBytes := sshTestKey(t)
	if _, err := a.ImportSSHKey(pemBytes, nil); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.LoadStoredSSHKey(nil); err != nil {
		t.Fatalf("LoadStoredSSHKey: %v", err)
	}
	if !a.HasSSHKeyLoaded() {
		t.Fatal("expected SSH key loaded")
	}
}

func TestSSHPublicKey(t *testing.T) {
	a := newTestApp(t)
	pemBytes := sshTestKey(t)
	if _, err := a.ImportSSHKey(pemBytes, nil); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := a.UnlockSSH(nil); err != nil {
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
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := a.Unlock([]byte(testPGPPassphrase), nil); err != nil {
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
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase)); err != nil {
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
	if err := a.Unlock([]byte(testPGPPassphrase), nil); err != nil {
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
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatal(err)
	}
	if err := a.OpenLocalStore(storeDir); err != nil {
		t.Fatal(err)
	}
	if err := a.Unlock([]byte(testPGPPassphrase), nil); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.RemovePassword("missing"); err == nil {
		t.Fatal("expected RemovePassword of missing entry to fail")
	}
}

func TestKeyNeedsPassphrase(t *testing.T) {
	a := newTestApp(t)

	// No keys stored -> false, nil.
	need, err := a.PGPKeyNeedsPassphrase()
	if err != nil {
		t.Fatalf("PGPKeyNeedsPassphrase: %v", err)
	}
	if need {
		t.Fatal("expected false with no PGP key")
	}
	need, err = a.SSHKeyNeedsPassphrase()
	if err != nil {
		t.Fatalf("SSHKeyNeedsPassphrase: %v", err)
	}
	if need {
		t.Fatal("expected false with no SSH key")
	}

	// Import an unencrypted SSH key -> false.
	pemBytes := sshTestKey(t)
	if _, err := a.ImportSSHKey(pemBytes, nil); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	need, err = a.SSHKeyNeedsPassphrase()
	if err != nil {
		t.Fatalf("SSHKeyNeedsPassphrase: %v", err)
	}
	if need {
		t.Fatal("expected unencrypted SSH key not to require passphrase")
	}

	// Import a passphrase-protected PGP key -> true.
	armored := armoredTestKey(t)
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	need, err = a.PGPKeyNeedsPassphrase()
	if err != nil {
		t.Fatalf("PGPKeyNeedsPassphrase: %v", err)
	}
	if !need {
		t.Fatal("expected passphrase-protected PGP key to require passphrase")
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
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase)); err != nil {
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
