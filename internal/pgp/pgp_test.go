package pgp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	gperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
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

// armorPublic serializes only the public parts of an entity, mimicking a GnuPG
// "export the public key" (`gpg --export --armor`) block.
func armorPublic(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	var out bytes.Buffer
	w, err := armor.Encode(&out, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		t.Fatalf("armor write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}
	return out.Bytes()
}

// TestImportRejectsPublicOnlyKey guards against importing a public key export
// (which parses but contains no private material) as if it were a secret key.
func TestImportRejectsPublicOnlyKey(t *testing.T) {
	e := noPassEntity(t)
	pub := armorPublic(t, e)
	if _, err := (&Service{}).ImportSecret(pub, []byte("")); err == nil {
		t.Fatal("expected ImportSecret to reject a public-only key block")
	} else if !strings.Contains(err.Error(), "private key material") {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := (&Service{}).ImportSecret(armorSecret(t, e), []byte("")); err != nil {
		t.Fatalf("secret key should still import: %v", err)
	}
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

func TestNewService(t *testing.T) {
	svc := New()
	if svc == nil {
		t.Fatal("New returned nil")
	}
	if len(svc.DescribeOwn()) != 0 {
		t.Fatal("new service should have no keys")
	}
}

func TestDescribeOwn(t *testing.T) {
	e := newTestEntity(t)
	svc := &Service{}
	if _, err := svc.ImportSecret(armorSecret(t, e), []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	infos := svc.DescribeOwn()
	if len(infos) != 1 {
		t.Fatalf("DescribeOwn = %d infos", len(infos))
	}
	if infos[0].Fingerprint != fingerprintOf(e) {
		t.Fatalf("fingerprint mismatch: %s", infos[0].Fingerprint)
	}
	if infos[0].KeyID != KeyIDOf(e) {
		t.Fatalf("key id mismatch: %s", infos[0].KeyID)
	}
	if infos[0].Algorithm != "RSA" {
		t.Fatalf("algorithm = %q", infos[0].Algorithm)
	}
}

func TestArmoredSecretRoundtrip(t *testing.T) {
	e := newTestEntity(t)
	svc := &Service{}
	if _, err := svc.ImportSecret(armorSecret(t, e), []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	armored, err := svc.ArmoredSecret()
	if err != nil {
		t.Fatalf("ArmoredSecret: %v", err)
	}
	if len(armored) == 0 {
		t.Fatal("ArmoredSecret returned empty")
	}
	// The re-serialized block must still be unlockable.
	svc.Lock()
	if err := svc.Unlock(armored, []byte("test-pass")); err != nil {
		t.Fatalf("Unlock from ArmoredSecret: %v", err)
	}
}

func TestArmoredSecretNoKeys(t *testing.T) {
	if _, err := (&Service{}).ArmoredSecret(); err == nil {
		t.Fatal("expected ArmoredSecret to fail with no keys")
	}
}

func TestBlockRequiresNoPassphrase(t *testing.T) {
	// An entity whose private key is not encrypted.
	e, err := openpgp.NewEntity("Plain Tester", "", "plain@example.com", &packet.Config{})
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	need, err := BlockRequiresPassphrase(buf.Bytes())
	if err != nil {
		t.Fatalf("BlockRequiresPassphrase: %v", err)
	}
	if need {
		t.Fatal("expected unencrypted block not to require a passphrase")
	}
}

func TestSinglePrimaryFingerprint(t *testing.T) {
	svc := &Service{}
	if _, err := svc.SinglePrimaryFingerprint(); err == nil {
		t.Fatal("expected error with no keys")
	}
	e := newTestEntity(t)
	if _, err := svc.ImportSecret(armorSecret(t, e), []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	fp, err := svc.SinglePrimaryFingerprint()
	if err != nil {
		t.Fatalf("SinglePrimaryFingerprint: %v", err)
	}
	if fp != fingerprintOf(e) {
		t.Fatalf("fingerprint = %s", fp)
	}
}

func TestSinglePrimaryFingerprintMultiple(t *testing.T) {
	cfg := &packet.Config{}
	e1, err := openpgp.NewEntity("One", "", "one@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	e2, err := openpgp.NewEntity("Two", "", "two@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	svc := &Service{entities: []*openpgp.Entity{e1, e2}}
	if _, err := svc.SinglePrimaryFingerprint(); err == nil {
		t.Fatal("expected error with multiple keys")
	}
}

func TestUserErrorMapping(t *testing.T) {
	cases := []struct {
		in   error
		want string
	}{
		{errors.New("no valid pgp data"), "does not contain a valid OpenPGP message"},
		{errors.New("unable to decrypt session key"), "unable to decrypt with the configured key"},
		{errors.New("openpgp: invalid data: modification detected"), "integrity check"},
		{errors.New("unknown packet type"), "malformed or unsupported OpenPGP packets"},
		{errors.New("something else entirely"), "unable to decrypt the password"},
		{gperrors.ErrKeyIncorrect, "was not encrypted for the imported key"},
		{errLocked, "run unlock first"},
	}
	for _, tc := range cases {
		err := userError(tc.in)
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("userError(%q) = %q, want substring %q", tc.in, err.Error(), tc.want)
		}
	}
}

func TestUnlockSuccess(t *testing.T) {
	e := newTestEntity(t)
	block := armorSecret(t, e)
	svc := &Service{}
	if err := svc.Unlock(block, []byte("test-pass")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if len(svc.entities) != 1 {
		t.Fatal("expected unlocked entity")
	}
}

func TestUnlockBadArmor(t *testing.T) {
	svc := &Service{}
	if err := svc.Unlock([]byte("not an openpgp block"), []byte("x")); err == nil {
		t.Fatal("expected bad armor to be rejected")
	}
}

func TestSetPassphraseNil(t *testing.T) {
	svc := &Service{passphrase: []byte("old")}
	svc.setPassphrase(nil)
	if svc.passphrase != nil {
		t.Fatal("expected nil passphrase")
	}
}

func TestHasSecretMaterialTracksResidency(t *testing.T) {
	svc := New()
	if svc.HasSecretMaterial() {
		t.Fatal("a fresh service must not report resident key material")
	}
	// A retained passphrase alone is enough to keep the service "resident":
	// Lock is the only thing that wipes it.
	svc.setPassphrase([]byte("pass"))
	if !svc.HasSecretMaterial() {
		t.Fatal("a retained passphrase must count as resident key material")
	}
	svc.Lock()
	if svc.HasSecretMaterial() {
		t.Fatal("Lock must clear the resident flag")
	}
}

func TestPubKeyAlgoName(t *testing.T) {
	cases := []struct {
		algo packet.PublicKeyAlgorithm
		want string
	}{
		{packet.PubKeyAlgoRSA, "RSA"},
		{packet.PubKeyAlgoRSAEncryptOnly, "RSA"},
		{packet.PubKeyAlgoRSASignOnly, "RSA"},
		{packet.PubKeyAlgoEdDSA, "Ed25519"},
		{packet.PubKeyAlgoECDSA, "ECDSA"},
		{packet.PubKeyAlgoECDH, "ECDH"},
		{packet.PubKeyAlgoDSA, "DSA"},
		{packet.PubKeyAlgoElGamal, "ElGamal"},
		{packet.PublicKeyAlgorithm(99), "unknown"},
	}
	for _, tc := range cases {
		if got := pubKeyAlgoName(tc.algo); got != tc.want {
			t.Fatalf("pubKeyAlgoName(%v) = %q, want %q", tc.algo, got, tc.want)
		}
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	if _, err := Encrypt([]byte("secret"), nil); err == nil {
		t.Fatal("expected error with no recipients")
	}
}

func TestDecryptWhenLocked(t *testing.T) {
	svc := &Service{}
	if _, err := svc.Decrypt([]byte("anything")); err == nil {
		t.Fatal("expected error when locked")
	}
}

func TestDecryptUnencryptedMessage(t *testing.T) {
	e := newTestEntity(t)
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}

	svc := &Service{}
	if _, err := svc.ImportSecret(armorSecret(t, newTestEntity(t)), []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	if _, err := svc.Decrypt(buf.Bytes()); err == nil {
		t.Fatal("expected error for unencrypted public-key block")
	}
}

func TestResolveRecipientsEmptyAndMultipleMissing(t *testing.T) {
	e := newTestEntity(t)
	svc := &Service{}
	if _, err := svc.ImportSecret(armorSecret(t, e), []byte("test-pass")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}

	// Empty identifiers are skipped; the valid fingerprint still resolves.
	resolved, err := svc.ResolveRecipients([]string{"", fingerprintOf(e)})
	if err != nil {
		t.Fatalf("ResolveRecipients: %v", err)
	}
	if len(resolved) != 1 {
		t.Fatalf("got %d recipients, want 1", len(resolved))
	}

	if _, err := svc.ResolveRecipients([]string{"missing-one", "missing-two"}); err == nil {
		t.Fatal("expected error for missing recipients")
	}
}

func TestEntityMatchesVariants(t *testing.T) {
	e := newTestEntity(t)
	fp := fingerprintOf(e)

	if !entityMatches(e, fp, fp) {
		t.Fatal("full fingerprint should match")
	}
	if !entityMatches(e, fp[len(fp)-16:], fp[len(fp)-16:]) {
		t.Fatal("long key id suffix should match")
	}
	if !entityMatches(e, "UNIT@EXAMPLE.COM", "unit@example.com") {
		t.Fatal("exact user id match should work")
	}
	if !entityMatches(e, "UNIT", "unit") {
		t.Fatal("substring user id match should work")
	}
	if entityMatches(e, "NOPE", "nope") {
		t.Fatal("non-matching id should not match")
	}
}

func TestEntityMatchesScansIdentities(t *testing.T) {
	cfg := &packet.Config{}
	e, err := openpgp.NewEntity("First", "", "first@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	e.Identities["second@example.com"] = &openpgp.Identity{Name: "second@example.com"}

	if !entityMatches(e, "SECOND", "second") {
		t.Fatal("should match a later identity when earlier ones do not")
	}
}

func TestBlockRequiresPassphraseBadArmor(t *testing.T) {
	if _, err := BlockRequiresPassphrase([]byte("not an openpgp block")); err == nil {
		t.Fatal("expected bad armor to error")
	}
}

func TestBlockRequiresPassphraseSubkeyEncrypted(t *testing.T) {
	cfg := &packet.Config{}
	e, err := openpgp.NewEntity("Subkey Tester", "", "subkey@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	if err := e.EncryptPrivateKeys([]byte("sub-pass"), cfg); err != nil {
		t.Fatalf("EncryptPrivateKeys: %v", err)
	}
	// Decrypt the primary key but keep the subkey encrypted.
	if err := e.PrivateKey.Decrypt([]byte("sub-pass")); err != nil {
		t.Fatalf("Decrypt primary: %v", err)
	}
	if len(e.Subkeys) == 0 {
		t.Fatal("expected at least one subkey")
	}

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if err := e.SerializePrivate(w, nil); err != nil {
		t.Fatalf("SerializePrivate: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}

	need, err := BlockRequiresPassphrase(buf.Bytes())
	if err != nil {
		t.Fatalf("BlockRequiresPassphrase: %v", err)
	}
	if !need {
		t.Fatal("expected subkey-encrypted block to require a passphrase")
	}
}

func TestUnlockEntitiesDebugMessage(t *testing.T) {
	t.Setenv("PASSONE_DEBUG", "1")
	e := newTestEntity(t)
	block := armorSecret(t, e)
	entities, err := readArmoredKeyRing(block)
	if err != nil {
		t.Fatalf("readArmoredKeyRing: %v", err)
	}
	err = unlockEntities(entities, []byte("wrong-pass"))
	if err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
	if !strings.Contains(err.Error(), "passphrase len=") {
		t.Fatalf("expected debug detail, got %q", err.Error())
	}
}

func TestDescribeSortsUserIDs(t *testing.T) {
	cfg := &packet.Config{}
	e, err := openpgp.NewEntity("Sort Tester", "", "zebra@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	e.Identities["alpha@example.com"] = &openpgp.Identity{Name: "Alpha@example.com"}

	infos := Describe([]*openpgp.Entity{e})
	if len(infos) != 1 {
		t.Fatalf("Describe = %d infos", len(infos))
	}
	ids := infos[0].UserIDs
	// Uppercase 'A' (ASCII 65) sorts before uppercase 'S' (83).
	want := []string{"Alpha@example.com", "Sort Tester <zebra@example.com>"}
	if len(ids) != 2 || ids[0] != want[0] || ids[1] != want[1] {
		t.Fatalf("UserIDs = %v, want %v", ids, want)
	}
	if !infos[0].HasSecret {
		t.Fatal("expected HasSecret true")
	}
}

// noPassEntity builds an entity whose private key is NOT passphrase-protected,
// mirroring a GnuPG key generated with "no passphrase" (%no-protection).
func noPassEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("No Pass", "", "nopass@example.com", &packet.Config{DefaultCipher: packet.CipherAES256})
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	return e
}

// TestNoPassphraseRoundtrip verifies that a key without a passphrase can be
// imported, its data encrypted and decrypted. This is the regression for the
// "keys cannot be decoded if GPG has no passphrase" bug.
func TestNoPassphraseRoundtrip(t *testing.T) {
	e := noPassEntity(t)
	block := armorSecret(t, e)

	svc := &Service{}
	if _, err := svc.ImportSecret(block, []byte("")); err != nil {
		t.Fatalf("ImportSecret with empty passphrase: %v", err)
	}
	plaintext := []byte("no-passphrase-secret\nurl: https://example.com\n")
	ciphertext, err := Encrypt(plaintext, []*openpgp.Entity{e})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := svc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: %q != %q", got, plaintext)
	}
}

// TestEncryptedEmptyPassphraseRoundtrip covers a key whose secret packets are
// encrypted but the passphrase is the empty string. Import and decrypt must
// still succeed with the empty (non-nil) passphrase.
func TestEncryptedEmptyPassphraseRoundtrip(t *testing.T) {
	cfg := &packet.Config{DefaultCipher: packet.CipherAES256}
	e, err := openpgp.NewEntity("Empty Pass", "", "emptypass@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	if err := e.EncryptPrivateKeys([]byte(""), cfg); err != nil {
		t.Fatalf("EncryptPrivateKeys(empty): %v", err)
	}
	block := armorSecret(t, e)

	svc := &Service{}
	if _, err := svc.ImportSecret(block, []byte("")); err != nil {
		t.Fatalf("ImportSecret with empty passphrase: %v", err)
	}
	plaintext := []byte("encrypted-empty-pass-secret\n")
	ciphertext, err := Encrypt(plaintext, []*openpgp.Entity{e})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := svc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: %q != %q", got, plaintext)
	}
}

// TestNoPassphraseUnlockRepeated verifies that a no-passphrase key survives
// lock/unlock cycles (the path taken on app restart from the sealed vault).
func TestNoPassphraseUnlockRepeated(t *testing.T) {
	e := noPassEntity(t)
	block := armorSecret(t, e)
	plaintext := []byte("restart-secret\n")

	svc := &Service{}
	if _, err := svc.ImportSecret(block, []byte("")); err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	ciphertext, err := Encrypt(plaintext, []*openpgp.Entity{e})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	for i := 0; i < 2; i++ {
		svc.Lock()
		if err := svc.Unlock(block, []byte("")); err != nil {
			t.Fatalf("Unlock(empty) cycle %d: %v", i, err)
		}
		got, err := svc.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt cycle %d: %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("cycle %d mismatch", i)
		}
	}
}
