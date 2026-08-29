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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

const testPassphrase = "ui-test-pass"

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
	if _, err := g.core.ImportPGPKey(block, []byte(testPassphrase)); err != nil {
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
	if err := g.Unlock(testPassphrase, ""); err != nil {
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
	if _, err := g.core.ImportSSHKey(sshPEM(t), nil); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := g.LoadSSHKey(""); err != nil {
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
	msg, err := g.ImportPGPKeyFile(pgpPath, testPassphrase)
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
	msg, err = g.ImportSSHKeyFile(sshPath, "")
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
