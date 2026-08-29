package sshx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func marshalTestKey(t *testing.T, priv any) []byte {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "unit@example.com")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func TestImportEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := marshalTestKey(t, priv)

	k, err := ImportPrivateKey(pemBytes, nil)
	if err != nil {
		t.Fatalf("ImportPrivateKey: %v", err)
	}
	if k.Algorithm() != ssh.KeyAlgoED25519 {
		t.Fatalf("Algorithm = %q", k.Algorithm())
	}
	if k.Fingerprint() == "" {
		t.Fatal("expected a fingerprint")
	}
	if !ed25519PublicKeyEqual(k, pub) {
		t.Fatal("public key does not match the generated key")
	}
}

func ed25519PublicKeyEqual(k *SSHKey, pub ed25519.PublicKey) bool {
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(k.PublicAuthorizedKey())
	if err != nil {
		return false
	}
	got, ok := parsed.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	return got.CryptoPublicKey().(ed25519.PublicKey).Equal(pub)
}

func TestImportRejectsUnsupportedType(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := marshalTestKey(t, key)
	if _, err := ImportPrivateKey(pemBytes, nil); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("expected ErrUnsupportedKey, got %v", err)
	}
}

func TestImportGarbage(t *testing.T) {
	if _, err := ImportPrivateKey([]byte("not a key"), nil); err == nil {
		t.Fatal("expected garbage to be rejected")
	}
}

func TestPrivateKeyRequiresPassphrase(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := marshalTestKey(t, priv)
	need, err := PrivateKeyRequiresPassphrase(pemBytes)
	if err != nil {
		t.Fatalf("PrivateKeyRequiresPassphrase: %v", err)
	}
	if need {
		t.Fatal("plain key should not require a passphrase")
	}
}

func TestFingerprintStable(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := marshalTestKey(t, priv)
	k1, err := ImportPrivateKey(pemBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ImportPrivateKey(pemBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if k1.Fingerprint() != k2.Fingerprint() {
		t.Fatal("fingerprint must be deterministic")
	}
}

func TestImportPassphraseProtectedKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "unit@example.com", []byte("secret"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	if _, err := ImportPrivateKey(pemBytes, nil); err == nil {
		t.Fatal("expected passphrase-protected key to require a passphrase")
	}
	k, err := ImportPrivateKey(pemBytes, []byte("secret"))
	if err != nil {
		t.Fatalf("ImportPrivateKey with passphrase: %v", err)
	}
	if k.Signer() == nil {
		t.Fatal("expected signer")
	}
	k.Lock()
	if k.Signer() != nil {
		t.Fatal("expected signer to be nil after Lock")
	}
}

func TestPrivateKeyRequiresPassphraseEncrypted(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "unit@example.com", []byte("secret"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	need, err := PrivateKeyRequiresPassphrase(pemBytes)
	if err != nil {
		t.Fatalf("PrivateKeyRequiresPassphrase: %v", err)
	}
	if !need {
		t.Fatal("expected encrypted key to require passphrase")
	}
}

func TestPrivateKeyRequiresPassphraseGarbage(t *testing.T) {
	need, err := PrivateKeyRequiresPassphrase([]byte("not a key"))
	if err == nil {
		t.Fatal("expected garbage to return an error")
	}
	if need {
		t.Fatal("expected need=false for garbage")
	}
}

func TestSetPassphraseNil(t *testing.T) {
	k := &SSHKey{passphrase: []byte("old")}
	k.setPassphrase(nil)
	if k.passphrase != nil {
		t.Fatal("expected passphrase to be nil")
	}
}

func TestPublicKeyHelpers(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()

	fp := HostKeyFingerprint(pub)
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("HostKeyFingerprint = %q", fp)
	}
	if KeyAlgorithm(pub) != ssh.KeyAlgoED25519 {
		t.Fatalf("KeyAlgorithm = %q", KeyAlgorithm(pub))
	}
	raw := pub.Marshal()
	parsed, err := ParsePublicKey(raw)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !bytes.Equal(parsed.Marshal(), raw) {
		t.Fatal("ParsePublicKey roundtrip mismatch")
	}
}
