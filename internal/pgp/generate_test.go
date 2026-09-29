package pgp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestGenerateProducesAnImportableKey(t *testing.T) {
	const pass = "generate-pass"
	armored, err := Generate(GenerateOptions{
		Name:       "Setup Wizard",
		Email:      "wizard@example.com",
		Passphrase: []byte(pass),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !bytes.HasPrefix(armored, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
		t.Fatalf("Generate did not return an armored private key: %q", firstLine(armored))
	}

	svc := New()
	infos, err := svc.ImportSecret(armored, []byte(pass))
	if err != nil {
		t.Fatalf("ImportSecret: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("infos = %+v, want exactly one key", infos)
	}
	info := infos[0]
	if info.Algorithm != "Ed25519" {
		t.Errorf("Algorithm = %q, want Ed25519", info.Algorithm)
	}
	if !info.HasSecret {
		t.Error("HasSecret = false for a generated key")
	}
	if len(info.Fingerprint) != 40 {
		t.Errorf("Fingerprint = %q, want 40 hex chars", info.Fingerprint)
	}

	// The user id has to survive, because it is what GnuPG shows for the key.
	el, err := readArmoredKeyRing(armored)
	if err != nil {
		t.Fatalf("readArmoredKeyRing: %v", err)
	}
	var ids []string
	for _, ident := range el[0].Identities {
		ids = append(ids, ident.Name)
	}
	joined := strings.Join(ids, " ")
	if !strings.Contains(joined, "wizard@example.com") {
		t.Errorf("user ids = %v, want the email address", ids)
	}

	// The whole point of generating a key is that the store can then be
	// encrypted to it and read back, so prove the round trip the app relies on.
	plain := []byte("hunter2\nurl: https://example.com\n")
	cipher, err := Encrypt(plain, el)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := svc.Decrypt(cipher)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("Decrypt = %q, want %q", got, plain)
	}
	svc.Lock()
}

func TestGenerateEncryptsThePrivateKey(t *testing.T) {
	const pass = "generate-pass"
	armored, err := Generate(GenerateOptions{Name: "T", Email: "t@example.com", Passphrase: []byte(pass)})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	needs, err := BlockRequiresPassphrase(armored)
	if err != nil {
		t.Fatalf("BlockRequiresPassphrase: %v", err)
	}
	if !needs {
		t.Error("BlockRequiresPassphrase = false; a generated key must be passphrase-protected")
	}

	if _, err := New().ImportSecret(armored, []byte("wrong-pass")); err == nil {
		t.Error("ImportSecret accepted the wrong passphrase")
	}
	if _, err := New().ImportSecret(armored, []byte(pass)); err != nil {
		t.Errorf("ImportSecret with the right passphrase: %v", err)
	}
}

func TestGenerateRejectsMissingEmail(t *testing.T) {
	for _, email := range []string{"", "   "} {
		if _, err := Generate(GenerateOptions{Name: "No Email", Email: email, Passphrase: []byte("p")}); err == nil {
			t.Errorf("Generate with email %q should have been rejected", email)
		}
	}
}

// TestGenerateUsesTheCurvesWePinned guards the algorithm choice. Ed25519 for
// signing and a Curve25519 encryption subkey is the shape gpg and pass prefer;
// a default change in go-crypto would silently produce a different kind of key.
func TestGenerateUsesTheCurvesWePinned(t *testing.T) {
	armored, err := Generate(GenerateOptions{Name: "Curves", Email: "curves@example.com", Passphrase: []byte("p")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	el, err := readArmoredKeyRing(armored)
	if err != nil {
		t.Fatalf("readArmoredKeyRing: %v", err)
	}
	e := el[0]
	if e.PrimaryKey.PubKeyAlgo != packet.PubKeyAlgoEdDSA {
		t.Errorf("primary algorithm = %v, want EdDSA", e.PrimaryKey.PubKeyAlgo)
	}
	if curve, err := e.PrimaryKey.Curve(); err != nil || curve != packet.Curve25519 {
		t.Errorf("primary curve = %v (err %v), want Curve25519", curve, err)
	}
	var encSub int
	for _, sub := range e.Subkeys {
		if sub.PublicKey.PubKeyAlgo != packet.PubKeyAlgoECDH {
			continue
		}
		encSub++
		if curve, err := sub.PublicKey.Curve(); err != nil || curve != packet.Curve25519 {
			t.Errorf("encryption subkey curve = %v (err %v), want Curve25519", curve, err)
		}
	}
	if encSub != 1 {
		t.Errorf("found %d ECDH subkeys, want 1", encSub)
	}
}

// TestGeneratedKeysDiffer proves a fresh key is really generated per call, so
// two users on two machines do not end up with the same fingerprint.
func TestGeneratedKeysDiffer(t *testing.T) {
	a, err := Generate(GenerateOptions{Name: "A", Email: "a@example.com", Passphrase: []byte("p")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := Generate(GenerateOptions{Name: "A", Email: "a@example.com", Passphrase: []byte("p")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ea, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(a))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	eb, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	if fingerprintOf(ea[0]) == fingerprintOf(eb[0]) {
		t.Error("two Generate calls returned the same fingerprint")
	}
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
