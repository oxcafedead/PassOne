package security

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // see keys.go: DSA keys must be wipeable
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	pgecdh "github.com/ProtonMail/go-crypto/openpgp/ecdh"
	pgecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	pged25519 "github.com/ProtonMail/go-crypto/openpgp/ed25519"
	pged448 "github.com/ProtonMail/go-crypto/openpgp/ed448"
	pgeddsa "github.com/ProtonMail/go-crypto/openpgp/eddsa"
	pgelgamal "github.com/ProtonMail/go-crypto/openpgp/elgamal"
	pgmldsa "github.com/ProtonMail/go-crypto/openpgp/mldsa_eddsa"
	pgmlkem "github.com/ProtonMail/go-crypto/openpgp/mlkem_ecdh"
	pgx25519 "github.com/ProtonMail/go-crypto/openpgp/x25519"
	pgx448 "github.com/ProtonMail/go-crypto/openpgp/x448"
)

func TestZeroInt(t *testing.T) {
	ZeroInt(nil)

	x := new(big.Int).Lsh(big.NewInt(0xdeadbeef), 300)
	words := x.Bits()
	if len(words) == 0 {
		t.Fatal("expected a non-empty mantissa")
	}
	ZeroInt(x)
	if x.Sign() != 0 {
		t.Fatalf("ZeroInt left %v", x)
	}
	for i, w := range words {
		if w != 0 {
			t.Fatalf("mantissa word %d survived the wipe: %x", i, w)
		}
	}
	// A zeroed value must stay usable as a big.Int: no panic, no stale length.
	if got := x.Cmp(big.NewInt(0)); got != 0 {
		t.Fatalf("Cmp = %d, want 0", got)
	}
	x.Add(x, big.NewInt(7))
	if x.String() != "7" {
		t.Fatalf("after Add: %s, want 7", x)
	}
}

// TestWipeKeyRSACoversPrecomputed pins that the RSA wipe reaches the CRT values
// the parsers build with Precompute, not just D and the primes.
func TestWipeKeyRSACoversPrecomputed(t *testing.T) {
	k := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17},
		D:         big.NewInt(2753),
		Primes:    []*big.Int{big.NewInt(61), big.NewInt(53)},
	}
	k.Precompute()
	//nolint:staticcheck // deprecated for use, still populated by Precompute, and still secret
	k.Precomputed.CRTValues = []rsa.CRTValue{{
		Exp:   big.NewInt(11),
		Coeff: big.NewInt(13),
		R:     big.NewInt(17),
	}}

	if !WipeKey(k) {
		t.Fatal("WipeKey did not recognize *rsa.PrivateKey")
	}
	// The public modulus is not secret and must survive: it is the identity of
	// the key, and the vault still refers to it after the session ends.
	if k.N.Int64() != 3233 {
		t.Fatalf("N was modified: %v", k.N)
	}
	secrets := map[string]*big.Int{
		"D":          k.D,
		"Primes[0]":  k.Primes[0],
		"Primes[1]":  k.Primes[1],
		"Precomp.Dp": k.Precomputed.Dp,
		"Precomp.Dq": k.Precomputed.Dq,
		//nolint:staticcheck // see above
		"Precomp.Qinv": k.Precomputed.Qinv,
		//nolint:staticcheck // see above
		"CRT.Exp": k.Precomputed.CRTValues[0].Exp,
		//nolint:staticcheck // see above
		"CRT.Coeff": k.Precomputed.CRTValues[0].Coeff,
		//nolint:staticcheck // see above
		"CRT.R": k.Precomputed.CRTValues[0].R,
	}
	for name, v := range secrets {
		if v == nil {
			t.Fatalf("%s is nil; Precompute did not populate it as expected", name)
		}
		if v.Sign() != 0 {
			t.Fatalf("%s survived the wipe: %v", name, v)
		}
	}
}

func TestWipeKeyByteKeys(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, 64)
	edPtr := ed25519.PrivateKey(bytes.Clone(seed))
	tests := map[string]any{
		"ed25519 value":       ed25519.PrivateKey(bytes.Clone(seed)),
		"ed25519 pointer":     &edPtr,
		"openpgp ed25519":     &pged25519.PrivateKey{Key: bytes.Clone(seed)},
		"openpgp ed448":       &pged448.PrivateKey{Key: bytes.Clone(seed)},
		"openpgp eddsa":       &pgeddsa.PrivateKey{D: bytes.Clone(seed)},
		"openpgp x25519":      &pgx25519.PrivateKey{Secret: bytes.Clone(seed)},
		"openpgp x448":        &pgx448.PrivateKey{Secret: bytes.Clone(seed)},
		"openpgp ecdh":        &pgecdh.PrivateKey{D: bytes.Clone(seed)},
		"openpgp mldsa eddsa": &pgmldsa.PrivateKey{SecretEc: bytes.Clone(seed), SecretMldsaSeed: bytes.Clone(seed)},
		"openpgp mlkem ecdh":  &pgmlkem.PrivateKey{SecretEc: bytes.Clone(seed), SecretMlkemSeed: bytes.Clone(seed)},
	}
	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			fields := keyByteFields(key)
			if len(fields) == 0 {
				t.Fatalf("keyByteFields found no secret fields in %T", key)
			}
			// Alias the fields before wiping: the wipe must be observable
			// through a reference the caller already held, which is the whole
			// point of wiping in place rather than dropping the reference.
			before := make([][]byte, len(fields))
			aliases := make([][]byte, len(fields))
			for i, f := range fields {
				before[i] = bytes.Clone(f)
				aliases[i] = f
				if allZero(f) {
					t.Fatalf("test setup: field %d is already zeroed", i)
				}
			}
			if !WipeKey(key) {
				t.Fatal("WipeKey did not recognize the key type")
			}
			for i, f := range fields {
				// Zero overwrites with random bytes, not zeros, so the
				// assertion is that nothing of the original survives.
				if bytes.Equal(aliases[i], before[i]) {
					t.Fatalf("field %d survived the wipe: %x", i, aliases[i])
				}
				if !bytes.Equal(f, aliases[i]) {
					t.Fatalf("field %d was replaced instead of wiped", i)
				}
			}
		})
	}
}

func TestWipeKeyBigIntKeys(t *testing.T) {
	secret := big.NewInt(0x0badc0de)
	tests := map[string]any{
		"dsa":             &dsa.PrivateKey{X: new(big.Int).Set(secret)},
		"ecdsa":           &ecdsa.PrivateKey{D: new(big.Int).Set(secret)},
		"openpgp ecdsa":   &pgecdsa.PrivateKey{D: new(big.Int).Set(secret)},
		"openpgp elgamal": &pgelgamal.PrivateKey{X: new(big.Int).Set(secret)},
	}
	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			fields := keyIntFields(key)
			if len(fields) == 0 {
				t.Fatalf("keyIntFields found no secret fields in %T", key)
			}
			if !WipeKey(key) {
				t.Fatal("WipeKey did not recognize the key type")
			}
			for i, f := range fields {
				if f == nil || f.Sign() != 0 {
					t.Fatalf("field %d survived the wipe: %v", i, f)
				}
			}
		})
	}
}

// TestWipeKeyUnrecognized documents the contract for types WipeKey cannot
// handle: nothing is wiped and the caller is told, rather than the function
// pretending it cleaned up.
func TestWipeKeyUnrecognized(t *testing.T) {
	if WipeKey(nil) {
		t.Fatal("an untyped nil should not be reported as wiped")
	}
	if WipeKey((*rsa.PrivateKey)(nil)) {
		t.Fatal("a typed nil should not be reported as wiped, and must not panic")
	}
	// A public key is not secret material; refusing to claim a wipe is the
	// honest answer.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if WipeKey(pub) {
		t.Fatal("ed25519.PublicKey should not be reported as wiped")
	}
	if WipeKey("not a key") {
		t.Fatal("a string should not be reported as wiped")
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// keyByteFields returns the secret byte slices a key type holds, so the tests
// can assert on the wipe without re-implementing WipeKey's type switch.
func keyByteFields(key any) [][]byte {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return [][]byte{k}
	case *ed25519.PrivateKey:
		return [][]byte{*k}
	case *pged25519.PrivateKey:
		return [][]byte{k.Key}
	case *pged448.PrivateKey:
		return [][]byte{k.Key}
	case *pgeddsa.PrivateKey:
		return [][]byte{k.D}
	case *pgx25519.PrivateKey:
		return [][]byte{k.Secret}
	case *pgx448.PrivateKey:
		return [][]byte{k.Secret}
	case *pgecdh.PrivateKey:
		return [][]byte{k.D}
	case *pgmldsa.PrivateKey:
		return [][]byte{k.SecretEc, k.SecretMldsaSeed}
	case *pgmlkem.PrivateKey:
		return [][]byte{k.SecretEc, k.SecretMlkemSeed}
	default:
		return nil
	}
}

// keyIntFields is keyByteFields for the big.Int-based key types.
func keyIntFields(key any) []*big.Int {
	switch k := key.(type) {
	case *dsa.PrivateKey:
		return []*big.Int{k.X}
	case *ecdsa.PrivateKey:
		//nolint:staticcheck // see keys.go: D is what we are wiping
		return []*big.Int{k.D}
	case *pgecdsa.PrivateKey:
		return []*big.Int{k.D}
	case *pgelgamal.PrivateKey:
		return []*big.Int{k.X}
	default:
		return nil
	}
}
