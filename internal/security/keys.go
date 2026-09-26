package security

import (
	// DSA is deprecated for key generation, but a user can still hand us a DSA
	// key to import, and a wipe helper that skipped it would leave the secret
	// behind on the unsupported-key path.
	"crypto/dsa" //nolint:staticcheck
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

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

// WipeKey overwrites the secret scalars of a parsed private key in place and
// reports whether it recognized the type. It is the counterpart of Zero for key
// material: a private key is not a byte slice we hold, it is a tree of typed
// structs owned by a crypto library, and dereferencing it only makes the
// collector reclaim it eventually without ever erasing it.
//
// The types below are the ones the libraries this project actually parses into:
// the standard library types reached through golang.org/x/crypto/ssh, and the
// openpgp/ed25519 (and friends) types reached through ProtonMail/go-crypto.
// Every field carrying secret material in those types is exported and therefore
// overwritable. A type whose secret fields are not exported is left untouched
// and reported as unrecognized, so a caller can tell that nothing was wiped
// instead of assuming it was.
//
// Known residue, which no amount of care in this function can remove:
//
//   - Go's garbage collector reclaims but never erases, and no library here
//     guarantees that its parser did not leave intermediate copies (decrypted
//     DER, CFB output, big.Int temporaries) elsewhere on the heap. WipeKey
//     shortens the window for the long-lived copies; it does not close it.
//   - rsa.PrivateKey.PrecomputedValues carries an unexported shadow key, but
//     only when FIPS mode is active.
//   - The post-quantum composite keys keep an expanded private key (an opaque
//     circl type) beside the seeds wiped here, and an SLH-DSA key exposes nothing
//     but an opaque signer, so it is reported as unrecognized.
//
// A key still referenced after WipeKey holds zeroed scalars: it cannot sign or
// decrypt, and a library asked to will fail rather than produce a
// plausible-looking wrong answer.
func WipeKey(key any) bool {
	switch k := key.(type) {
	case nil:
		return false
	case *rsa.PrivateKey:
		return wipePtr(k, func(k *rsa.PrivateKey) {
			ZeroInt(k.D)
			for _, p := range k.Primes {
				ZeroInt(p)
			}
			// Both the SSH and the OpenPGP parsers call Precompute on the way
			// in, so these hold copies of the exponents. Without D and the
			// primes they cannot sign anything, but they are still secret.
			ZeroInt(k.Precomputed.Dp)
			ZeroInt(k.Precomputed.Dq)
			ZeroInt(k.Precomputed.Qinv)
			//nolint:staticcheck // deprecated for use, still populated by Precompute, and still secret
			for _, crt := range k.Precomputed.CRTValues {
				ZeroInt(crt.Exp)
				ZeroInt(crt.Coeff)
				ZeroInt(crt.R)
			}
		})
	case *dsa.PrivateKey:
		return wipePtr(k, func(k *dsa.PrivateKey) { ZeroInt(k.X) })
	case *ecdsa.PrivateKey:
		//nolint:staticcheck // D is deprecated for *constructing* keys; overwriting it is the whole point here
		return wipePtr(k, func(k *ecdsa.PrivateKey) { ZeroInt(k.D) })
	case ed25519.PrivateKey:
		Zero(k)
		return true
	case *ed25519.PrivateKey:
		return wipePtr(k, func(k *ed25519.PrivateKey) { Zero(*k) })
	case *pgecdsa.PrivateKey:
		return wipePtr(k, func(k *pgecdsa.PrivateKey) { ZeroInt(k.D) })
	case *pgecdh.PrivateKey:
		return wipePtr(k, func(k *pgecdh.PrivateKey) { Zero(k.D) })
	case *pgeddsa.PrivateKey:
		return wipePtr(k, func(k *pgeddsa.PrivateKey) { Zero(k.D) })
	case *pged25519.PrivateKey:
		return wipePtr(k, func(k *pged25519.PrivateKey) { Zero(k.Key) })
	case *pged448.PrivateKey:
		return wipePtr(k, func(k *pged448.PrivateKey) { Zero(k.Key) })
	case *pgx25519.PrivateKey:
		return wipePtr(k, func(k *pgx25519.PrivateKey) { Zero(k.Secret) })
	case *pgx448.PrivateKey:
		return wipePtr(k, func(k *pgx448.PrivateKey) { Zero(k.Secret) })
	case *pgelgamal.PrivateKey:
		return wipePtr(k, func(k *pgelgamal.PrivateKey) { ZeroInt(k.X) })
	case *pgmldsa.PrivateKey:
		return wipePtr(k, func(k *pgmldsa.PrivateKey) {
			Zero(k.SecretEc)
			Zero(k.SecretMldsaSeed)
		})
	case *pgmlkem.PrivateKey:
		return wipePtr(k, func(k *pgmlkem.PrivateKey) {
			Zero(k.SecretEc)
			Zero(k.SecretMlkemSeed)
		})
	default:
		return false
	}
}

// wipePtr applies wipe to a non-nil key. A private key handed to WipeKey can
// legitimately be a typed nil (packet.PrivateKey.PrivateKey is an interface),
// and Lock must never panic on the way out of an unlocked session.
func wipePtr[T any](k *T, wipe func(*T)) bool {
	if k == nil {
		return false
	}
	wipe(k)
	return true
}
