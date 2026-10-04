package security

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oxcafedead/passone/internal/config"
)

// DPAPI sealing and the legacy app.key are the same subject: DPAPI is kept only
// so a vault written by an older build can still be opened, and both are
// therefore a compatibility path with no other caller and no coverage from any
// other test. A regression here does not break the current vault — it breaks the
// upgrade, and the upgrade runs once per user.

func TestDPAPIRoundTrip(t *testing.T) {
	secret := []byte("the legacy application key material")
	sealed, err := DPAPIProtect(secret)
	if err != nil {
		t.Fatalf("DPAPIProtect: %v", err)
	}
	defer Zero(sealed)
	if len(sealed) == 0 {
		t.Fatal("DPAPIProtect returned no data")
	}
	// DPAPI encrypts, it does not encode: the plaintext must not survive in it.
	if bytes.Contains(sealed, secret) {
		t.Fatal("the protected blob contains the plaintext")
	}

	opened, err := DPAPIUnprotect(sealed)
	if err != nil {
		t.Fatalf("DPAPIUnprotect: %v", err)
	}
	defer Zero(opened)
	if !bytes.Equal(opened, secret) {
		t.Errorf("round trip returned %q, want %q", opened, secret)
	}
}

// TestDPAPIProtectRejectsEmptyInput: bytesToBlob turns a zero-length input into
// an empty DATA_BLOB, and CryptProtectData rejects that. The requirement is an
// error rather than a panic on the nil pbData, and the r0 == 0 arm has to be
// reached for that to be worth anything.
func TestDPAPIProtectRejectsEmptyInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{name: "nil", in: nil},
		{name: "zero length", in: []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed, err := DPAPIProtect(tc.in)
			if err == nil {
				Zero(sealed)
				t.Fatal("expected CryptProtectData to reject an empty blob")
			}
			if sealed != nil {
				t.Errorf("got %d bytes alongside the error, want none", len(sealed))
			}
		})
	}
}

// TestDataBlobFreeIgnoresUnallocatedBlobs: the DPAPI calls are the only ones that
// hand back a LocalAlloc'd pointer, so free() has to be a no-op for anything
// else. LocalFree on Go-managed memory would corrupt the heap, and this is the
// only place that can catch a caller passing the wrong blob.
func TestDataBlobFreeIgnoresUnallocatedBlobs(t *testing.T) {
	emptyBlob().free()
	var nilBlob *dataBlob
	nilBlob.free()
	// A blob whose cbData is zero but whose pointer is Go-managed: bytesToBlob
	// never produces this, but free() must not act on the pointer alone.
	goOwned := bytesToBlob([]byte("short-lived"))
	goOwned.free()
	if string(goOwned.toBytes()) != "short-lived" {
		t.Error("free() disturbed memory it does not own")
	}
}

// legacyKeyFile writes a DPAPI-protected key of the requested length to a
// temporary app.key and returns its path and the plaintext behind it.
func legacyKeyFile(t *testing.T, length int) (path string, plain []byte) {
	t.Helper()
	plain = bytes.Repeat([]byte{0xA5}, length)
	sealed, err := DPAPIProtect(plain)
	if err != nil {
		t.Fatalf("DPAPIProtect: %v", err)
	}
	path = filepath.Join(t.TempDir(), "app.key")
	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		t.Fatalf("writing app.key: %v", err)
	}
	Zero(sealed)
	return path, plain
}

func TestLegacyAppKeyExists(t *testing.T) {
	paths := config.PathsFromBase(t.TempDir())
	if LegacyAppKeyExists(paths) {
		t.Fatal("reported a legacy app.key in a fresh directory")
	}

	key, _ := legacyKeyFile(t, keyLen)
	paths.AppKeyFile = key
	if !LegacyAppKeyExists(paths) {
		t.Error("reported no legacy app.key for a file that exists")
	}

	if err := os.Remove(key); err != nil {
		t.Fatalf("removing app.key: %v", err)
	}
	if LegacyAppKeyExists(paths) {
		t.Error("reported a legacy app.key after it was removed")
	}
}

func TestReadLegacyAppKey(t *testing.T) {
	path, plain := legacyKeyFile(t, keyLen)
	key, err := ReadLegacyAppKey(path)
	if err != nil {
		t.Fatalf("ReadLegacyAppKey: %v", err)
	}
	defer Zero(key)
	if len(key) != keyLen {
		t.Fatalf("got %d bytes, want %d", len(key), keyLen)
	}
	if !bytes.Equal(key, plain) {
		t.Error("the recovered key does not match what was sealed")
	}
}

// TestReadLegacyAppKeyRejectsWrongLength: a blob DPAPI can open but that holds
// the wrong number of bytes would otherwise become a vault key of the wrong size,
// and the failure would surface much later as an opaque store error. The length
// check is the only place that can catch it. Zero bytes is absent on purpose —
// CryptProtectData cannot produce it, so there is no such file to read.
func TestReadLegacyAppKeyRejectsWrongLength(t *testing.T) {
	for _, length := range []int{1, keyLen - 1, keyLen + 1} {
		path, _ := legacyKeyFile(t, length)
		key, err := ReadLegacyAppKey(path)
		if err == nil {
			Zero(key)
			t.Errorf("a %d-byte legacy key was accepted", length)
			continue
		}
		if key != nil {
			t.Errorf("a %d-byte legacy key returned %d bytes alongside the error", length, len(key))
		}
		if !strings.Contains(err.Error(), "unexpected length") {
			t.Errorf("a %d-byte legacy key: got %q, want it to mention the length", length, err)
		}
	}
}

func TestReadLegacyAppKeyRejectsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.key")
	key, err := ReadLegacyAppKey(path)
	if err == nil {
		Zero(key)
		t.Fatal("expected an error for a missing app.key")
	}
	if !os.IsNotExist(err) {
		t.Errorf("got %v, want a not-exist error", err)
	}
}

// TestReadLegacyAppKeyRejectsUnprotectableFile: a file that exists but is not a
// DPAPI blob must fail with a message naming the unprotect step, because that is
// the difference between "this install is corrupt" and "the passphrase was
// wrong" for whoever reads the log.
func TestReadLegacyAppKeyRejectsUnprotectableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.key")
	if err := os.WriteFile(path, []byte("this was never sealed with DPAPI"), 0o600); err != nil {
		t.Fatalf("writing app.key: %v", err)
	}
	key, err := ReadLegacyAppKey(path)
	if err == nil {
		Zero(key)
		t.Fatal("expected an error for a file DPAPI never protected")
	}
	if !strings.Contains(err.Error(), "unable to unprotect legacy application key") {
		t.Errorf("got %q, want it to name the unprotect step", err)
	}
}

func TestRemoveLegacyAppKey(t *testing.T) {
	path, _ := legacyKeyFile(t, keyLen)
	if err := RemoveLegacyAppKey(path); err != nil {
		t.Fatalf("RemoveLegacyAppKey: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("app.key still present after removal: %v", err)
	}
	if err := RemoveLegacyAppKey(path); err == nil {
		t.Error("removing an already-removed app.key should report an error")
	}
}
