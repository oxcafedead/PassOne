package app

import (
	"bytes"
	"encoding/hex"
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
