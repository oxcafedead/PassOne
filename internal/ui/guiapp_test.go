// Package ui tests exercise the Wails facade over the core application.
// Methods that require a live Wails runtime context (file dialogs, event emit)
// are intentionally skipped or exercised only through their nil-context paths.
package ui

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/oxcafedead/passone/internal/sshx"
	"golang.org/x/crypto/ssh"
)

const testPassphrase = "ui-test-pass"
const testLockPass = "ui-test-lock"

func newTestGUI(t *testing.T) *GUI {
	t.Helper()
	t.Setenv("PASSONE_DIR", t.TempDir())
	g, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func armoredPGPKey(t *testing.T) []byte {
	t.Helper()
	cfg := &packet.Config{}
	e, err := openpgp.NewEntity("UI Tester", "", "ui@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	if err := e.EncryptPrivateKeys([]byte(testPassphrase), cfg); err != nil {
		t.Fatalf("EncryptPrivateKeys: %v", err)
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

func pgpFingerprint(block []byte) string {
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(block))
	if err != nil {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(el[0].PrimaryKey.Fingerprint))
}

func sshPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "ui@example.com")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func TestNewAndContext(t *testing.T) {
	g := newTestGUI(t)
	if g.ctxOrNil() != nil {
		t.Fatal("expected nil context before SetContext")
	}
	g.SetContext(context.TODO())
	if g.ctxOrNil() == nil {
		t.Fatal("expected non-nil context after SetContext")
	}
}

func TestSimpleGetters(t *testing.T) {
	g := newTestGUI(t)
	if g.DataDir() == "" {
		t.Fatal("expected DataDir")
	}
	if g.IsUnlocked() {
		t.Fatal("expected locked")
	}
	if g.HasSSHKeyLoaded() {
		t.Fatal("expected no SSH key loaded")
	}
	if g.HasStoredPGPKey() {
		t.Fatal("expected no stored PGP key")
	}
	if g.HasStoredSSHKey() {
		t.Fatal("expected no stored SSH key")
	}
	if g.StorePath() != "" {
		t.Fatal("expected empty store path")
	}
	if g.AutoLockMinutes() != 5 {
		t.Fatalf("AutoLockMinutes = %d", g.AutoLockMinutes())
	}
	if g.ClipboardClearSeconds() != 30 {
		t.Fatalf("ClipboardClearSeconds = %d", g.ClipboardClearSeconds())
	}
}

func TestLockUnlock(t *testing.T) {
	g := newTestGUI(t)
	block := armoredPGPKey(t)
	fp := pgpFingerprint(block)
	path := filepath.Join(g.DataDir(), "pgp.asc")
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := g.core.ImportPGPKey(block, []byte(testPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, ".gpg-id"), []byte(fp), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := g.Unlock(testLockPass); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !g.IsUnlocked() {
		t.Fatal("expected unlocked")
	}
	g.Lock()
	if g.IsUnlocked() {
		t.Fatal("expected locked after Lock")
	}
}

func TestLoadSSHKey(t *testing.T) {
	g := newTestGUI(t)
	if _, err := g.core.ImportSSHKey(sshPEM(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := g.LoadSSHKey(testLockPass); err != nil {
		t.Fatalf("LoadSSHKey: %v", err)
	}
	if !g.HasSSHKeyLoaded() {
		t.Fatal("expected SSH key loaded")
	}
}

func TestCurrentSettings(t *testing.T) {
	g := newTestGUI(t)
	if err := g.SetAutoLock(7); err != nil {
		t.Fatalf("SetAutoLock: %v", err)
	}
	if err := g.SetClipboardClear(45); err != nil {
		t.Fatalf("SetClipboardClear: %v", err)
	}
	if err := g.SetGitAuthor("UI Tester", "ui@example.com"); err != nil {
		t.Fatalf("SetGitAuthor: %v", err)
	}
	s := g.CurrentSettings()
	if s.AutoLockMinutes != 7 {
		t.Fatalf("AutoLockMinutes = %d", s.AutoLockMinutes)
	}
	if s.ClipboardClearSeconds != 45 {
		t.Fatalf("ClipboardClearSeconds = %d", s.ClipboardClearSeconds)
	}
	if s.GitAuthorName != "UI Tester" || s.GitAuthorEmail != "ui@example.com" {
		t.Fatalf("git author = %+v", s)
	}
}

func TestCreatePasswordValidation(t *testing.T) {
	g := newTestGUI(t)
	if _, err := g.CreatePassword("", "pass", "pass", ""); err == nil {
		t.Fatal("expected empty name to fail")
	}
	if _, err := g.CreatePassword("site", "", "", ""); err == nil {
		t.Fatal("expected empty password to fail")
	}
	if _, err := g.CreatePassword("site", "pass", "different", ""); err == nil {
		t.Fatal("expected mismatched passwords to fail")
	}
	if _, err := g.CreatePassword("site/", "pass", "pass", ""); err == nil {
		t.Fatal("expected trailing slash to fail")
	}
	if _, err := g.CreatePassword("site", "pass\nline", "pass\nline", ""); err == nil {
		t.Fatal("expected newline in password to fail")
	}
}

func TestUpdatePasswordValidation(t *testing.T) {
	g := newTestGUI(t)
	if _, err := g.UpdatePassword("", "pass", "", false); err == nil {
		t.Fatal("expected empty name to fail")
	}
	if _, err := g.UpdatePassword("site", "", "", false); err == nil {
		t.Fatal("expected empty new password to fail")
	}
	if _, err := g.UpdatePassword("site", "new\nline", "", false); err == nil {
		t.Fatal("expected newline in password to fail")
	}
}

func TestImportKeyFiles(t *testing.T) {
	g := newTestGUI(t)

	pgpPath := filepath.Join(t.TempDir(), "key.asc")
	block := armoredPGPKey(t)
	if err := os.WriteFile(pgpPath, block, 0o600); err != nil {
		t.Fatal(err)
	}
	msg, err := g.ImportPGPKeyFile(pgpPath, testPassphrase, testLockPass)
	if err != nil {
		t.Fatalf("ImportPGPKeyFile: %v", err)
	}
	if !strings.Contains(msg, "Imported OpenPGP key") {
		t.Fatalf("message = %q", msg)
	}

	sshPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(sshPath, sshPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	msg, err = g.ImportSSHKeyFile(sshPath, "", testLockPass)
	if err != nil {
		t.Fatalf("ImportSSHKeyFile: %v", err)
	}
	if !strings.Contains(msg, "Imported SSH key") {
		t.Fatalf("message = %q", msg)
	}
}

func TestKnownHosts(t *testing.T) {
	g := newTestGUI(t)
	if hosts := g.KnownHosts(); len(hosts) != 0 {
		t.Fatalf("KnownHosts = %v", hosts)
	}
}

// TestTrustHostStoresTheProbedKey covers the time-of-check/time-of-use hole:
// the key written to known_hosts has to be the one PrepareClone showed the
// user, so TrustHost must not ask the server a second time. The host here is
// unreachable, so any second probe fails the test.
func TestTrustHostStoresTheProbedKey(t *testing.T) {
	g := newTestGUI(t)
	const hostport = "127.0.0.1:1"

	key := testHostKey(t)
	g.rememberProbed(hostport, key)
	if err := g.TrustHost(hostport); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}
	hosts := g.KnownHosts()
	if len(hosts) != 1 {
		t.Fatalf("KnownHosts = %v", hosts)
	}
	if !strings.Contains(hosts[0], ssh.FingerprintSHA256(key)) {
		t.Fatalf("KnownHosts = %v, want the probed key %s", hosts[0], ssh.FingerprintSHA256(key))
	}

	// A later probe replaces the pending key: what gets stored is the key on
	// screen, not the first one ever seen for the host.
	other := testHostKey(t)
	g.rememberProbed(hostport, other)
	if err := g.TrustHost(hostport); !errors.Is(err, sshx.ErrHostKeyChanged) {
		t.Fatalf("expected ErrHostKeyChanged when a probed key differs, got %v", err)
	}
	hosts = g.KnownHosts()
	if len(hosts) != 1 || !strings.Contains(hosts[0], ssh.FingerprintSHA256(key)) {
		t.Fatalf("KnownHosts = %v, want only the first confirmed key", hosts)
	}
}

// TestTrustHostNeedsAConfirmation guards against a silent fallback to a fresh
// probe: with nothing on screen, trusting must fail instead of connecting.
func TestTrustHostNeedsAConfirmation(t *testing.T) {
	g := newTestGUI(t)
	err := g.TrustHost("127.0.0.1:1")
	if err == nil {
		t.Fatal("expected TrustHost without a probed key to fail")
	}
	if !strings.Contains(err.Error(), "no host key confirmed") {
		t.Fatalf("error = %v, want a missing-confirmation error", err)
	}
	if hosts := g.KnownHosts(); len(hosts) != 0 {
		t.Fatalf("KnownHosts = %v", hosts)
	}
}

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

func TestStoredStores(t *testing.T) {
	g := newTestGUI(t)
	storeDir := filepath.Join(g.core.DataDir(), "stores", "found")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, ".gpg-id"), []byte("AABB"), 0o600); err != nil {
		t.Fatal(err)
	}
	stores := g.StoredStores()
	if len(stores) != 1 || stores[0] != storeDir {
		t.Fatalf("StoredStores = %v", stores)
	}
}

func setupUnlockedStore(t *testing.T) (*GUI, string) {
	t.Helper()
	g := newTestGUI(t)
	block := armoredPGPKey(t)
	fp := pgpFingerprint(block)
	if _, err := g.core.ImportPGPKey(block, []byte(testPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, ".gpg-id"), []byte(fp), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := g.Unlock(testLockPass); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return g, storeDir
}

func TestCreatePasswordHappyPath(t *testing.T) {
	g, _ := setupUnlockedStore(t)
	msg, err := g.CreatePassword("site.com", "secret", "secret", "user: alice")
	if err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}
	if !strings.Contains(msg, "Created site.com") {
		t.Fatalf("message = %q", msg)
	}

	// Duplicate name should fail.
	if _, err := g.CreatePassword("site.com", "other", "other", ""); err == nil {
		t.Fatal("expected duplicate name to fail")
	}
}

func TestUpdatePasswordHappyPath(t *testing.T) {
	g, _ := setupUnlockedStore(t)
	if _, err := g.CreatePassword("site.com", "old", "old", "notes"); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}

	msg, err := g.UpdatePassword("site.com", "new", "more notes", false)
	if err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	if !strings.Contains(msg, "Saved site.com") {
		t.Fatalf("message = %q", msg)
	}

	// keepPassword with no body should report no changes.
	msg, err = g.UpdatePassword("site.com", "", "", true)
	if err != nil {
		t.Fatalf("UpdatePassword keep: %v", err)
	}
	if !strings.Contains(msg, "No changes") {
		t.Fatalf("message = %q", msg)
	}

	// Missing entry should fail.
	if _, err := g.UpdatePassword("missing", "x", "", false); err == nil {
		t.Fatal("expected missing entry to fail")
	}
}

func TestRemovePassword(t *testing.T) {
	g, _ := setupUnlockedStore(t)
	if _, err := g.CreatePassword("site.com", "secret", "secret", ""); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}
	if err := g.RemovePassword("site.com"); err != nil {
		t.Fatalf("RemovePassword: %v", err)
	}
	if err := g.RemovePassword("site.com"); err == nil {
		t.Fatal("expected removing missing entry to fail")
	}
}

func TestListShowCopyPassword(t *testing.T) {
	g, _ := setupUnlockedStore(t)
	if _, err := g.CreatePassword("a/b", "line1", "line1", "body\nmore"); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}

	list, err := g.ListPasswords()
	if err != nil {
		t.Fatalf("ListPasswords: %v", err)
	}
	if len(list) != 1 || list[0] != "a/b" {
		t.Fatalf("ListPasswords = %v", list)
	}

	plain, err := g.ShowPassword("a/b")
	if err != nil {
		t.Fatalf("ShowPassword: %v", err)
	}
	if !strings.Contains(plain, "line1") {
		t.Fatalf("ShowPassword = %q", plain)
	}

	if err := g.CopyPassword("a/b"); err != nil {
		t.Fatalf("CopyPassword: %v", err)
	}

	if _, err := g.ShowPassword("missing"); err == nil {
		t.Fatal("expected ShowPassword missing to fail")
	}
	if err := g.CopyPassword("missing"); err == nil {
		t.Fatal("expected CopyPassword missing to fail")
	}
}

func TestDialogNilContext(t *testing.T) {
	g := newTestGUI(t)
	if _, err := g.PickPrivateKey(""); err == nil {
		t.Fatal("expected PickPrivateKey without context to fail")
	}
	if _, err := g.PickStoreDir(); err == nil {
		t.Fatal("expected PickStoreDir without context to fail")
	}
}

func TestCloneHelpers(t *testing.T) {
	g := newTestGUI(t)

	if _, err := g.PrepareClone("not-a-url"); err == nil {
		t.Fatal("expected PrepareClone invalid URL to fail")
	}
	if err := g.TrustHost("bad"); err == nil {
		t.Fatal("expected TrustHost bad hostport to fail")
	}
	if err := g.CloneStore("not-a-url", ""); err == nil {
		t.Fatal("expected CloneStore invalid URL to fail")
	}
}

func TestStatusAndSyncLocalRepo(t *testing.T) {
	g, _ := setupUnlockedStore(t)
	if _, err := g.CreatePassword("x", "p", "p", ""); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}

	status, err := g.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status == "" {
		t.Fatal("expected non-empty status")
	}

	// Sync without a loaded SSH key should fail.
	if _, err := g.Sync(); err == nil {
		t.Fatal("expected Sync without SSH key to fail")
	}

	// Status/Sync without a configured store should fail.
	g2 := newTestGUI(t)
	if _, err := g2.Status(); err == nil {
		t.Fatal("expected Status without store to fail")
	}
	if _, err := g2.Sync(); err == nil {
		t.Fatal("expected Sync without store to fail")
	}
}
