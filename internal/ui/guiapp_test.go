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
	"github.com/oxcafedead/passone/internal/cliputil"
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

// The frontend shows a clipboard-history caveat only when this says the history
// is on, so a detection failure has to read as "on": the user is then told about
// a risk that may not exist, which is the recoverable direction.
func TestClipboardHistoryEnabledFailsOpen(t *testing.T) {
	g := newTestGUI(t)
	want, err := cliputil.HistoryEnabled()
	if err != nil {
		t.Skipf("clipboard history detection unavailable: %v", err)
	}
	if got := g.ClipboardHistoryEnabled(); got != want {
		t.Fatalf("ClipboardHistoryEnabled = %v, want %v", got, want)
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

	// An empty body with keepPassword clears the notes. The dialog is always
	// opened with the entry's current notes in the field, so empty is a decision
	// to delete rather than a request to leave them alone.
	msg, err = g.UpdatePassword("site.com", "", "", true)
	if err != nil {
		t.Fatalf("UpdatePassword keep: %v", err)
	}
	if !strings.Contains(msg, "Saved site.com") {
		t.Fatalf("message = %q", msg)
	}
	plain, err := g.ShowPassword("site.com")
	if err != nil {
		t.Fatalf("ShowPassword: %v", err)
	}
	if plain != "new\n" {
		t.Fatalf("entry = %q, want the password with no notes", plain)
	}

	// Missing entry should fail.
	if _, err := g.UpdatePassword("missing", "x", "", false); err == nil {
		t.Fatal("expected missing entry to fail")
	}
}

func TestShowNotesReturnsTheBodyWithoutThePassword(t *testing.T) {
	g, _ := setupUnlockedStore(t)
	if _, err := g.CreatePassword("site.com", "secret", "secret", "user: alice\nurl: https://site.com\n"); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}
	if _, err := g.CreatePassword("bare.com", "secret", "secret", ""); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}

	notes, err := g.ShowNotes("site.com")
	if err != nil {
		t.Fatalf("ShowNotes: %v", err)
	}
	if notes != "user: alice\nurl: https://site.com\n" {
		t.Fatalf("ShowNotes = %q", notes)
	}
	// The password must not be anywhere in the answer: this is the call that
	// prefills the edit form, whose password field has to stay empty.
	if strings.Contains(notes, "secret") {
		t.Fatalf("ShowNotes leaked the password: %q", notes)
	}

	// An entry with no body has no notes, which is not an error.
	notes, err = g.ShowNotes("bare.com")
	if err != nil {
		t.Fatalf("ShowNotes bare: %v", err)
	}
	if notes != "" {
		t.Fatalf("ShowNotes on a bodyless entry = %q", notes)
	}

	if _, err := g.ShowNotes("missing"); err == nil {
		t.Error("expected ShowNotes on a missing entry to fail")
	}
}

func TestMovePasswordHappyPath(t *testing.T) {
	g, _ := setupUnlockedStore(t)
	if _, err := g.CreatePassword("site.com", "secret", "secret", "user: alice"); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}
	if _, err := g.CreatePassword("other.com", "other", "other", ""); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}

	msg, err := g.MovePassword(" site.com ", "work/site.com ")
	if err != nil {
		t.Fatalf("MovePassword: %v", err)
	}
	if !strings.Contains(msg, "site.com") || !strings.Contains(msg, "work/site.com") {
		t.Fatalf("message = %q", msg)
	}
	// The entry kept its content: a move renames the stored file, so the
	// secret is never decrypted on the way and cannot have changed.
	plain, err := g.ShowPassword("work/site.com")
	if err != nil {
		t.Fatalf("ShowPassword: %v", err)
	}
	if plain != "secret\nuser: alice" {
		t.Fatalf("moved entry = %q", plain)
	}
	listed, err := g.ListPasswords()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0] != "other.com" || listed[1] != "work/site.com" {
		t.Fatalf("ListPasswords = %v", listed)
	}
}

func TestMovePasswordValidation(t *testing.T) {
	g, _ := setupUnlockedStore(t)
	if _, err := g.CreatePassword("site.com", "secret", "secret", ""); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}
	if _, err := g.CreatePassword("taken.com", "secret", "secret", ""); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}

	cases := []struct {
		name     string
		from, to string
	}{
		{"empty source", "", "work/site.com"},
		{"empty target", "site.com", ""},
		{"blank target", "site.com", "   "},
		{"trailing slash", "site.com", "work/"},
		{"missing source", "missing.com", "work/site.com"},
		{"target exists", "site.com", "taken.com"},
		{"same name", "site.com", "site.com"},
	}
	for _, tc := range cases {
		if _, err := g.MovePassword(tc.from, tc.to); err == nil {
			t.Errorf("%s: expected MovePassword(%q, %q) to fail", tc.name, tc.from, tc.to)
		}
	}
	// A case-only rename is a real request on a case-insensitive filesystem,
	// not a no-op, so it has to go through rather than be refused as "target
	// exists" or "same name".
	if _, err := g.MovePassword("site.com", "Site.com"); err != nil {
		t.Fatalf("MovePassword (case only): %v", err)
	}
	if exists, err := g.core.PasswordExists("Site.com"); err != nil || !exists {
		t.Fatalf("PasswordExists(Site.com) = %v, %v", exists, err)
	}
	// A refused move leaves the vault exactly as it was.
	if _, err := g.ShowPassword("taken.com"); err != nil {
		t.Fatalf("a refused move destroyed an entry: %v", err)
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

// recordCopies swaps the clipboard sink for a recorder, so a test can pin the
// exact text a copy action hands over without that text ever reaching the real
// clipboard of the machine running the tests.
func recordCopies(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := copyClipboard
	copyClipboard = func(_ *GUI, text string) error {
		got = append(got, text)
		return nil
	}
	t.Cleanup(func() { copyClipboard = prev })
	return &got
}

func TestCopyUsernameCopiesTheWholeLogin(t *testing.T) {
	g, _ := setupUnlockedStore(t)
	copied := recordCopies(t)

	// An entry named after an email address carries the address as its login:
	// the domain says which account it is, so the copy has to keep it. It used
	// to stop at the "@" and hand over "alice", which signs in nowhere
	// (GH #37).
	if _, err := g.CreatePassword("mail/alice@example.com", "secret", "secret", "url: https://example.com"); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}
	if _, err := g.CreatePassword("site.com/bob", "secret", "secret", "user: bob"); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}
	if _, err := g.CreatePassword("example.com", "secret", "secret", ""); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}

	if err := g.CopyUsername("mail/alice@example.com"); err != nil {
		t.Fatalf("CopyUsername: %v", err)
	}
	if len(*copied) != 1 || (*copied)[0] != "alice@example.com" {
		t.Fatalf("clipboard = %q, want [alice@example.com]", *copied)
	}

	// A login field in the body still wins in auto mode, and it is copied
	// verbatim rather than being read back out of the entry name.
	if err := g.CopyUsername("site.com/bob"); err != nil {
		t.Fatalf("CopyUsername: %v", err)
	}
	if len(*copied) != 2 || (*copied)[1] != "bob" {
		t.Fatalf("clipboard = %q, want bob", *copied)
	}

	// A file name that is only a site encodes no login, so nothing is copied
	// and the user is told why rather than being handed an empty clipboard.
	*copied = nil
	if err := g.CopyUsername("example.com"); err == nil {
		t.Fatal("expected CopyUsername to fail for an entry with no login")
	}
	if len(*copied) != 0 {
		t.Fatalf("clipboard = %q, want nothing written", *copied)
	}
	if err := g.CopyUsername("missing/entry"); err == nil {
		t.Fatal("expected CopyUsername to fail for a missing entry")
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

// recordExplorer swaps the Explorer launcher for a recorder, so a test can pin
// the exact argument without a window appearing on the machine running it.
func recordExplorer(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := openExplorer
	openExplorer = func(arg string) error {
		got = append(got, arg)
		return nil
	}
	t.Cleanup(func() { openExplorer = prev })
	return &got
}

func TestRevealPathOpensADirectory(t *testing.T) {
	g := newTestGUI(t)
	calls := recordExplorer(t)

	// A directory is opened in place, with no /select and no quoting: the
	// argument is a bare path, because explorer.exe is not run through a shell.
	if err := g.RevealPath(g.DataDir()); err != nil {
		t.Fatalf("RevealPath(data dir): %v", err)
	}
	if len(*calls) != 1 || (*calls)[0] != g.DataDir() {
		t.Fatalf("explorer args = %v, want [%s]", *calls, g.DataDir())
	}
}

func TestRevealPathRefusesAFileOrSomethingMissing(t *testing.T) {
	g := newTestGUI(t)
	calls := recordExplorer(t)

	// Both rows that call RevealPath hold directories, so a file is a mistake and
	// a path that is not there is nothing to open. Neither may reach Explorer --
	// the /select, and the "open the folder a missing key would be created in",
	// cases went away with the key-file rows.
	if err := os.WriteFile(filepath.Join(g.DataDir(), "notadir"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(g.DataDir(), "notadir"),
		filepath.Join(g.DataDir(), "keys", "pgp.dat"),
		filepath.Join(g.DataDir(), "no-such-folder"),
	} {
		if err := g.RevealPath(path); err == nil {
			t.Errorf("RevealPath(%q) = nil, want a refusal", path)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("a refused path reached Explorer: %v", *calls)
	}
}

func TestRevealPathRefusesPathsOutsideTheApp(t *testing.T) {
	g := newTestGUI(t)
	calls := recordExplorer(t)
	dir := g.DataDir()

	// The store is in the allowlist too: OpenLocalStore and CloneStore accept
	// a directory anywhere, so a vault that is not under the data dir is still
	// a path the user is shown.
	elsewhere := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, ".gpg-id"), []byte("AABB"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.OpenLocalStore(elsewhere); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := g.RevealPath(g.StorePath()); err != nil {
		t.Errorf("RevealPath(configured store): %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("explorer args = %v, want the store to be revealed", *calls)
	}

	// A sibling directory that merely shares a prefix is not inside: appending
	// the separator is what stops C:\PassOne-2 passing as C:\PassOne.
	for _, path := range []string{
		"",
		"\t ",
		dir + "-other",
		filepath.Join(dir, "..", ".."),
		filepath.Join(elsewhere, "..", "elsewhere2"),
	} {
		if err := g.RevealPath(path); err == nil {
			t.Errorf("RevealPath(%q) = nil, want a refusal", path)
		}
	}
	if len(*calls) != 1 {
		t.Fatalf("a refused path reached Explorer: %v", *calls)
	}
}

func TestCopyKeyIDTakesTheAppsOwnIdentifier(t *testing.T) {
	g := newTestGUI(t)

	// The renderer picks which key to copy, never what to copy: the text comes
	// out of the app's own config or not at all. Every unknown name is refused.
	for _, kind := range []string{"", "gpg", "PGP", "id", "pgp; echo", "..", "ssh "} {
		if err := g.CopyKeyID(kind); err == nil {
			t.Errorf("CopyKeyID(%q) = nil, want a refusal", kind)
		}
	}
	// Nothing is imported in this environment, so both keys are empty and there
	// is nothing to put on the clipboard.
	for _, kind := range []string{"pgp", "ssh"} {
		if err := g.CopyKeyID(kind); err == nil {
			t.Errorf("CopyKeyID(%q) = nil, want a refusal with no key imported", kind)
		}
	}
}

func TestContainsPath(t *testing.T) {
	cases := []struct {
		root, path string
		want       bool
	}{
		{`C:\PassOne`, `C:\PassOne`, true},
		{`C:\PassOne`, `c:\passone`, true},
		{`C:\PassOne`, `C:\PassOne\keys\pgp.dat`, true},
		{`C:\PassOne`, `C:\PassOne-2`, false},
		{`C:\PassOne`, `C:\PassOne2\keys`, false},
		{`C:\PassOne`, `C:\`, false},
		{`C:\PassOne`, `C:\Other`, false},
	}
	for _, tc := range cases {
		if got := containsPath(tc.root, tc.path); got != tc.want {
			t.Errorf("containsPath(%q, %q) = %v, want %v", tc.root, tc.path, got, tc.want)
		}
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
