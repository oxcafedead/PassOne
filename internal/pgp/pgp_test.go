package pgp

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// newTestEntity creates a passphrase-protected Ed25519 entity tests can use.
func newTestEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	cfg := &packet.Config{DefaultCipher: packet.CipherAES256}
	e, err := openpgp.NewEntity("Unit Tester", "", "unit@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	if err := e.EncryptPrivateKeys([]byte("test-pass"), cfg); err != nil {
		t.Fatalf("EncryptPrivateKeys: %v", err)
	}
	return e
}

// armorSecret serializes an entity into an ASCII-armored private key block.
// The private key is encrypted; the existing self-signatures are preserved
// (SerializePrivateWithoutSigning, since re-signing needs an unlocked key).
func armorSecret(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if err := e.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatalf("SerializePrivateWithoutSigning: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}
	return buf.Bytes()
}

func fingerprintOf(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}

func TestBlockRequiresPassphrase(t *testing.T) {
	block := armorSecret(t, newTestEntity(t))
	need, err := BlockRequiresPassphrase(block)
	if err != nil {
		t.Fatalf("BlockRequiresPassphrase: %v", err)
	}
	if !need {
		t.Fatal("expected the test block to require a passphrase")
	}
}

func TestImportValidation(t *testing.T) {
	e := newTestEntity(t)
	block := armorSecret(t, e)

	if _, err := (&Service{}).ImportSecret(block, []byte("wrong-pass")); err == nil {
		t.Fatal("expected wrong passphrase to be rejected")
	}

	svc := &Service{}
	infos, err := svc.ImportSecret(block, []byte("test-pass"))
	if err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 key, got %d", len(infos))
	}
	if infos[0].Fingerprint != fingerprintOf(e) {
		t.Fatalf("fingerprint mismatch: %s != %s", infos[0].Fingerprint, fingerprintOf(e))
	}
	if !infos[0].HasSecret {
		t.Fatal("expected HasSecret to be true for a private key block")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	e := newTestEntity(t)
	block := armorSecret(t, e)

	svc := &Service{}
	if _, err := svc.ImportSecret(block, []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}

	plaintext := []byte("correct horse battery staple\nurl: https://example.com\n")
	ciphertext, err := Encrypt(plaintext, []*openpgp.Entity{e})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := svc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: %q != %q", got, plaintext)
	}
}

func TestDecryptTamperDetected(t *testing.T) {
	e := newTestEntity(t)
	svc := &Service{}
	if _, err := svc.ImportSecret(armorSecret(t, e), []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	ciphertext, err := Encrypt([]byte("secret"), []*openpgp.Entity{e})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	mid := len(ciphertext) / 2
	corrupt := append([]byte(nil), ciphertext...)
	corrupt[mid] ^= 0xFF
	if _, err := svc.Decrypt(corrupt); err == nil {
		t.Fatal("expected tampered ciphertext to be rejected")
	}
}

func TestResolveRecipients(t *testing.T) {
	e := newTestEntity(t)
	svc := &Service{}
	if _, err := svc.ImportSecret(armorSecret(t, e), []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	fp := fingerprintOf(e)

	if _, err := svc.ResolveRecipients([]string{fp}); err != nil {
		t.Fatalf("resolve by fingerprint: %v", err)
	}
	// suffix (long key id) also resolves.
	if _, err := svc.ResolveRecipients([]string{fp[len(fp)-16:]}); err != nil {
		t.Fatalf("resolve by key id: %v", err)
	}
	if _, err := svc.ResolveRecipients([]string{"unit@example.com"}); err != nil {
		t.Fatalf("resolve by user id: %v", err)
	}
	if _, err := svc.ResolveRecipients([]string{"definitely-missing-key"}); err == nil {
		t.Fatal("expected missing recipient to be reported")
	}
}

func TestLockDropsKeyMaterial(t *testing.T) {
	svc := &Service{}
	e := newTestEntity(t)
	if _, err := svc.ImportSecret(armorSecret(t, e), []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	ciphertext, err := Encrypt([]byte("secret"), []*openpgp.Entity{e})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	svc.Lock()
	if _, err := svc.Decrypt(ciphertext); err == nil {
		t.Fatal("expected Decrypt to fail after Lock")
	}
}

func TestDoubleUnlockFailsCleanly(t *testing.T) {
	svc := &Service{}
	if _, err := svc.ImportSecret(armorSecret(t, newTestEntity(t)), []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	if err := svc.Unlock(armorSecret(t, newTestEntity(t)), []byte("nope")); err == nil {
		t.Fatal("expected Unlock with a wrong passphrase to fail")
	}
}

func TestBadArmorRejected(t *testing.T) {
	if _, err := (&Service{}).ImportSecret([]byte("not an openpgp block"), []byte("x")); err == nil {
		t.Fatal("expected garbage armor to be rejected")
	}
}

func TestImportPersistedArmor(t *testing.T) {
	// Simulate the app reload path: store the original block, reload from disk.
	e := newTestEntity(t)
	block := armorSecret(t, e)
	dir := t.TempDir()
	path := dir + "/pgp.asc"
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	loaded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	svc := &Service{}
	if _, err := svc.ImportSecret(loaded, []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret after reload: %v", err)
	}
	svc.Lock()
}
