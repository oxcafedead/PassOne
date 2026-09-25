package security

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oxcafedead/passone/internal/config"
)

func TestDeriveKeyDeterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	k1 := DeriveKey([]byte("correct horse"), salt)
	k2 := DeriveKey([]byte("correct horse"), salt)
	defer Zero(k1)
	defer Zero(k2)
	if len(k1) != keyLen {
		t.Fatalf("DeriveKey length = %d", len(k1))
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("DeriveKey must be deterministic for equal inputs")
	}
	// A different passphrase must yield a different key.
	k3 := DeriveKey([]byte("different"), salt)
	defer Zero(k3)
	if bytes.Equal(k1, k3) {
		t.Fatal("DeriveKey must differ across passphrases")
	}
	// A different salt must yield a different key.
	k4 := DeriveKey([]byte("correct horse"), []byte("hgfedcba98765432"))
	defer Zero(k4)
	if bytes.Equal(k1, k4) {
		t.Fatal("DeriveKey must differ across salts")
	}
}

func TestVaultSealOpenRoundtrip(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, err := OpenVault(paths)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	salt, err := v.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	defer Zero(salt)
	key := DeriveKey([]byte("master-pass"), salt)
	defer Zero(key)

	secret := []byte("sealed-payload")
	sealed, err := v.Seal(key, secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := v.Open(key, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestVaultWrongKeyFails(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, _ := OpenVault(paths)
	salt, _ := v.LoadOrCreateSalt()
	defer Zero(salt)
	key := DeriveKey([]byte("master-a"), salt)
	wrong := DeriveKey([]byte("master-b"), salt)
	defer Zero(key)
	defer Zero(wrong)

	sealed, err := v.Seal(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Open(wrong, sealed); err == nil {
		t.Fatal("expected wrong key to fail to open")
	}
}

func TestVaultTamperDetection(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, _ := OpenVault(paths)
	salt, _ := v.LoadOrCreateSalt()
	defer Zero(salt)
	key := DeriveKey([]byte("master-pass"), salt)
	defer Zero(key)

	sealed, err := v.Seal(key, []byte("do-not-corrupt"))
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), sealed...)
	corrupt[len(corrupt)/2] ^= 0xFF
	if _, err := v.Open(key, corrupt); err == nil {
		t.Fatal("expected tampered sealed data to be rejected")
	} else if !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("expected integrity error, got: %v", err)
	}
}

func TestVaultStoreLoad(t *testing.T) {
	dir := t.TempDir()
	paths := config.PathsFromBase(dir)
	v, _ := OpenVault(paths)
	salt, _ := v.LoadOrCreateSalt()
	defer Zero(salt)
	key := DeriveKey([]byte("master-pass"), salt)
	defer Zero(key)

	payload := []byte("original armored key block (passphrase still required)")
	file := filepath.Join(paths.KeysDir, "pgp.dat")
	if err := v.Store(key, file, payload); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := v.LoadSealed(key, file)
	if err != nil {
		t.Fatalf("LoadSealed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("Store/LoadSealed roundtrip mismatch")
	}
	// The sealed file itself must not contain the plaintext payload.
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Contains(raw, payload) {
		t.Fatal("sealed file leaks plaintext")
	}
}

func TestVaultStoreErrors(t *testing.T) {
	t.Run("bad key length", func(t *testing.T) {
		paths := config.PathsFromBase(t.TempDir())
		v, _ := OpenVault(paths)
		if err := v.Store([]byte("short"), filepath.Join(t.TempDir(), "x"), []byte("p")); err == nil {
			t.Fatal("expected Store with a bad key length to fail")
		}
	})
	t.Run("mkdir fails", func(t *testing.T) {
		paths := config.PathsFromBase(t.TempDir())
		v, _ := OpenVault(paths)
		salt, _ := v.LoadOrCreateSalt()
		defer Zero(salt)
		key := DeriveKey([]byte("master"), salt)
		defer Zero(key)
		parent := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := v.Store(key, filepath.Join(parent, "x"), []byte("p")); err == nil {
			t.Fatal("expected MkdirAll error")
		}
	})
	t.Run("write temp fails", func(t *testing.T) {
		paths := config.PathsFromBase(t.TempDir())
		v, _ := OpenVault(paths)
		salt, _ := v.LoadOrCreateSalt()
		defer Zero(salt)
		key := DeriveKey([]byte("master"), salt)
		defer Zero(key)
		base := t.TempDir()
		if err := v.Store(key, filepath.Join(base, "bad:name"), []byte("p")); err == nil {
			t.Fatal("expected WriteFile error")
		}
	})
	t.Run("atomic move fails", func(t *testing.T) {
		paths := config.PathsFromBase(t.TempDir())
		v, _ := OpenVault(paths)
		salt, _ := v.LoadOrCreateSalt()
		defer Zero(salt)
		key := DeriveKey([]byte("master"), salt)
		defer Zero(key)
		base := t.TempDir()
		dst := filepath.Join(base, "dst")
		if err := os.Mkdir(dst, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := v.Store(key, dst, []byte("p")); err == nil {
			t.Fatal("expected atomicMove error")
		}
	})
}

func TestVaultLoadSealedMissingFile(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, _ := OpenVault(paths)
	salt, _ := v.LoadOrCreateSalt()
	defer Zero(salt)
	key := DeriveKey([]byte("master"), salt)
	defer Zero(key)
	if _, err := v.LoadSealed(key, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected LoadSealed to fail on a missing file")
	}
}

func TestStageDoesNotTouchDestination(t *testing.T) {
	dir := t.TempDir()
	paths := config.PathsFromBase(dir)
	v, _ := OpenVault(paths)
	salt, _ := v.LoadOrCreateSalt()
	defer Zero(salt)
	key := DeriveKey([]byte("master"), salt)
	defer Zero(key)

	file := filepath.Join(paths.KeysDir, "pgp.dat")
	if err := v.Store(key, file, []byte("old-blob")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	staged, err := v.Stage(key, file, []byte("new-blob"))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	got, err := v.LoadSealed(key, file)
	if err != nil {
		t.Fatalf("LoadSealed after Stage: %v", err)
	}
	if string(got) != "old-blob" {
		t.Fatalf("destination changed before Commit: %q", got)
	}
	if _, err := os.Stat(file + ".tmp"); err != nil {
		t.Fatalf("staging file should exist: %v", err)
	}

	if err := staged.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	got, err = v.LoadSealed(key, file)
	if err != nil {
		t.Fatalf("LoadSealed after Commit: %v", err)
	}
	if string(got) != "new-blob" {
		t.Fatalf("after Commit = %q", got)
	}
	if _, err := os.Stat(file + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("staging file should be gone after Commit")
	}
}

func TestStageDiscardKeepsDestination(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, _ := OpenVault(paths)
	salt, _ := v.LoadOrCreateSalt()
	defer Zero(salt)
	key := DeriveKey([]byte("master"), salt)
	defer Zero(key)

	file := filepath.Join(paths.KeysDir, "pgp.dat")
	if err := v.Store(key, file, []byte("old-blob")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	staged, err := v.Stage(key, file, []byte("new-blob"))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	staged.Discard()

	got, err := v.LoadSealed(key, file)
	if err != nil {
		t.Fatalf("LoadSealed after Discard: %v", err)
	}
	if string(got) != "old-blob" {
		t.Fatalf("Discard changed the destination: %q", got)
	}
	if _, err := os.Stat(file + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("staging file should be gone after Discard")
	}
	// Discard after a successful Commit must not delete the published blob.
	restaged, err := v.Stage(key, file, []byte("second-blob"))
	if err != nil {
		t.Fatalf("Stage again: %v", err)
	}
	if err := restaged.Commit(); err != nil {
		t.Fatalf("Commit again: %v", err)
	}
	restaged.Discard()
	got, err = v.LoadSealed(key, file)
	if err != nil {
		t.Fatalf("LoadSealed after Commit+Discard: %v", err)
	}
	if string(got) != "second-blob" {
		t.Fatalf("Discard after Commit removed the blob: %q", got)
	}
}

func TestStageCommitFailureKeepsDestination(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, _ := OpenVault(paths)
	salt, _ := v.LoadOrCreateSalt()
	defer Zero(salt)
	key := DeriveKey([]byte("master"), salt)
	defer Zero(key)

	base := t.TempDir()
	dst := filepath.Join(base, "dst")
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	staged, err := v.Stage(key, dst, []byte("blob"))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := staged.Commit(); err == nil {
		t.Fatal("expected Commit onto a directory to fail")
	}
	if fi, err := os.Stat(dst); err != nil || !fi.IsDir() {
		t.Fatal("a failed Commit must leave the destination alone")
	}
}

func TestStagedSealDoubleCommitFails(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, _ := OpenVault(paths)
	salt, _ := v.LoadOrCreateSalt()
	defer Zero(salt)
	key := DeriveKey([]byte("master"), salt)
	defer Zero(key)

	file := filepath.Join(paths.KeysDir, "pgp.dat")
	staged, err := v.Stage(key, file, []byte("blob"))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := staged.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := staged.Commit(); err == nil {
		t.Fatal("expected the second Commit to fail")
	}
}

func TestVaultSaltPersists(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v1, _ := OpenVault(paths)
	salt1, err := v1.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	defer Zero(salt1)

	v2, _ := OpenVault(paths)
	salt2, err := v2.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("LoadOrCreateSalt again: %v", err)
	}
	defer Zero(salt2)

	if !bytes.Equal(salt1, salt2) {
		t.Fatal("salt did not persist across vault reopen")
	}
}

func TestVaultOpenRejectsBadKeyLength(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	v, _ := OpenVault(paths)
	if _, err := v.Seal([]byte("short"), []byte("x")); err == nil {
		t.Fatal("expected Seal with a bad key length to fail")
	}
	if _, err := v.Open([]byte("short"), []byte("x")); err == nil {
		t.Fatal("expected Open with a bad key length to fail")
	}
}

func TestZero(t *testing.T) {
	Zero(nil)
	Zero([]byte{})
	b := []byte("secret")
	Zero(b)
	if bytes.Equal(b, []byte("secret")) {
		t.Fatal("Zero did not overwrite the buffer")
	}
}

func TestMigratedVault(t *testing.T) {
	// Simulate a legacy DPAPI vault by writing an app.key, then migrate by
	// re-reading it and re-sealing under a derived key, then assert the old
	// key is gone and the new layout opens with the derived key.
	paths := config.PathsFromBase(t.TempDir())
	v, err := OpenVault(paths)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}

	// Create a salt and a derived key as the "new" master key.
	salt, err := v.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	defer Zero(salt)
	newKey := DeriveKey([]byte("new-master"), salt)
	defer Zero(newKey)

	// Seed a legacy app.key with a DPAPI-protected 32-byte key.
	legacyKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	if len(legacyKey) != keyLen {
		t.Fatalf("legacy key length = %d", len(legacyKey))
	}
	if err := v.StoreSalt(paths.AppKeyFile, legacyKey); err != nil {
		t.Fatalf("StoreSalt(app.key): %v", err)
	}
	if !LegacyAppKeyExists(paths) {
		t.Fatal("expected legacy app.key to exist")
	}

	// Migration: the master passphrase 'new-master' corresponds to the same
	// content the user provides; here we simulate re-sealing the stored key
	// files (pgp.dat, ssh.dat) under the derived key.
	payload := []byte("re-sealed key material")
	if err := v.Store(newKey, paths.PGPKeyFile, payload); err != nil {
		t.Fatalf("Store under new key: %v", err)
	}

	// After migration the legacy app.key is removed.
	if err := RemoveLegacyAppKey(paths.AppKeyFile); err != nil {
		t.Fatalf("RemoveLegacyAppKey: %v", err)
	}
	if LegacyAppKeyExists(paths) {
		t.Fatal("expected app.key to be removed after migration")
	}

	// The new layout must open with the derived key.
	got, err := v.LoadSealed(newKey, paths.PGPKeyFile)
	if err != nil {
		t.Fatalf("LoadSealed after migration: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("migrated file did not open with the derived key")
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

func TestDPAPIUnprotectInvalidBlob(t *testing.T) {
	if _, err := DPAPIUnprotect([]byte("not a valid dpapi blob")); err == nil {
		t.Fatal("expected DPAPIUnprotect to fail on an invalid blob")
	}
}

func TestDPAPIUnprotectEmpty(t *testing.T) {
	if _, err := DPAPIUnprotect(nil); err == nil {
		t.Fatal("expected DPAPIUnprotect(nil) to fail")
	}
}
