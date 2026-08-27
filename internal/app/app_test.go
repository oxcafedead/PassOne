package app

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/oxcafedead/gopass-desktop/internal/store"
)

const testPGPPassphrase = "app-test-pass"

// newTestApp returns an App bound to an isolated data directory; the
// GOPASS_DESKTOP_DIR env override is restored after the test.
func newTestApp(t *testing.T) *App {
	t.Helper()
	prev, hadPrev := os.LookupEnv("GOPASS_DESKTOP_DIR")
	if err := os.Setenv("GOPASS_DESKTOP_DIR", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadPrev {
			os.Setenv("GOPASS_DESKTOP_DIR", prev)
		} else {
			os.Unsetenv("GOPASS_DESKTOP_DIR")
		}
	})
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
	if !a.IsUnlocked() {
		t.Fatal("expected to be unlocked after import")
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
