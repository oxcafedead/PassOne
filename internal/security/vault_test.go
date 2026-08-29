package security

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oxcafedead/passone/internal/config"
)

func TestDPAPIRoundtrip(t *testing.T) {
	p := &DPAPIKeyProtector{}
	secret := []byte("app-key-material-that-is-not-a-passphrase")
	enc, err := p.Protect(secret)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	if bytes.Equal(enc, secret) {
		t.Fatal("protected blob must not equal the plaintext")
	}
	dec, err := p.Unprotect(enc)
	if err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(dec, secret) {
		t.Fatalf("roundtrip mismatch: %x != %x", dec, secret)
	}
	if _, err := p.Unprotect(nil); err == nil {
		t.Fatal("expected empty unprotect to fail")
	}
}

func TestVaultPersistsAppKey(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v1, err := OpenVault(paths)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	defer v1.Wipe()

	secret := []byte("sealed-payload")
	sealed, err := v1.Seal(secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Reopening the same base dir must produce the same application key.
	v2, err := OpenVault(paths)
	if err != nil {
		t.Fatalf("OpenVault again: %v", err)
	}
	defer v2.Wipe()

	got, err := v2.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("vault did not survive reopen (app key changed?)")
	}
}

func TestVaultTamperDetection(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, err := OpenVault(paths)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	defer v.Wipe()

	sealed, err := v.Seal([]byte("do-not-corrupt"))
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), sealed...)
	corrupt[len(corrupt)/2] ^= 0xFF
	if _, err := v.Open(corrupt); err == nil {
		t.Fatal("expected tampered sealed data to be rejected")
	} else if !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("expected integrity error, got: %v", err)
	}
}

func TestVaultStoreLoad(t *testing.T) {
	dir := t.TempDir()
	paths := config.PathsFromBase(dir)
	v, err := OpenVault(paths)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	defer v.Wipe()

	payload := []byte("original armored key block (passphrase still required)")
	file := filepath.Join(paths.KeysDir, "pgp.dat")
	if err := v.Store(file, payload); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := v.LoadSealed(file)
	if err != nil {
		t.Fatalf("LoadSealed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("Store/LoadSealed roundtrip mismatch")
	}
	// The sealed file itself must not contain the plaintext payload.
	raw, err := readWhole(file)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Contains(raw, payload) {
		t.Fatal("sealed file leaks plaintext")
	}
}

func readWhole(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func TestVaultKeyPath(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, err := OpenVault(paths)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	defer v.Wipe()
	if v.KeyPath() != paths.AppKeyFile {
		t.Fatalf("KeyPath = %q", v.KeyPath())
	}
}

func TestVaultOpenRejectsBadKeyLength(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	p := &DPAPIKeyProtector{}
	bad := []byte("short") // 5 bytes, not 32
	sealed, err := p.Protect(bad)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.AppKeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.AppKeyFile, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVault(paths); err == nil {
		t.Fatal("expected OpenVault to reject a key of the wrong length")
	}
}

func TestNilVault(t *testing.T) {
	var v *Vault
	v.Wipe() // should not panic
	if _, err := v.Seal([]byte("x")); err == nil {
		t.Fatal("expected Seal on nil vault to fail")
	}
	if _, err := v.Open([]byte("x")); err == nil {
		t.Fatal("expected Open on nil vault to fail")
	}
}

func TestVaultSealOpenEdgeCases(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, err := OpenVault(paths)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	defer v.Wipe()

	// Empty plaintext roundtrip.
	sealed, err := v.Seal(nil)
	if err != nil {
		t.Fatalf("Seal nil: %v", err)
	}
	got, err := v.Open(sealed)
	if err != nil {
		t.Fatalf("Open nil: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("opened nil = %q", got)
	}

	// Blob too short to contain a nonce.
	if _, err := v.Open([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected opening a too-short blob to fail")
	}
}

func TestZero(t *testing.T) {
	// Empty slice should be a no-op.
	Zero(nil)
	Zero([]byte{})

	// Non-empty slice must be overwritten.
	b := []byte("secret")
	Zero(b)
	if bytes.Equal(b, []byte("secret")) {
		t.Fatal("Zero did not overwrite the buffer")
	}
}

func TestDataBlobHelpers(t *testing.T) {
	if emptyBlob().cbData != 0 || emptyBlob().pbData != nil {
		t.Fatal("emptyBlob fields should be zero/nil")
	}
	bNil := bytesToBlob(nil)
	bEmpty := bytesToBlob([]byte{})
	if bNil.cbData != 0 || bNil.pbData != nil {
		t.Fatal("bytesToBlob(nil) should have zero/nil fields")
	}
	if bEmpty.cbData != 0 || bEmpty.pbData != nil {
		t.Fatal("bytesToBlob(empty) should have zero/nil fields")
	}
	var nilBlob *dataBlob
	if nilBlob.toBytes() != nil {
		t.Fatal("toBytes on nil blob should return nil")
	}
	if emptyBlob().toBytes() != nil {
		t.Fatal("toBytes on empty blob should return nil")
	}
}
