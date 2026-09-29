package pgp

import (
	"bytes"
	"crypto"
	"errors"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// GenerateOptions describes the key to create.
type GenerateOptions struct {
	// Name and Email form the single user id on the primary key. Name may be
	// empty; Email may not.
	Name  string
	Email string
	// Passphrase encrypts the private key material. It may be empty, which
	// produces an unencrypted secret key, but the app never stores a key that
	// way: the key ends up behind DPAPI regardless, and an unencrypted key
	// would be a plain secret sitting in a file the user may export.
	Passphrase []byte
}

// Generate creates a new OpenPGP key pair and returns the armored secret key,
// ready to hand to Import.
//
// The key is a modern Ed25519/Curve25519 pair rather than the RSA default that
// gpg 1.x produced. The store encrypts to it, so the only thing that matters is
// that pass, GnuPG and go-crypto can both read the result: Ed25519 for signing
// and a Curve25519 subkey for encryption is the shape both prefer, and a
// generated key is only ever consumed by this app's own import path.
//
// The private key packets are encrypted before serialisation. An encrypted key
// cannot be re-signed, so the block is emitted with SerializePrivateWithoutSigning
// and the self-signatures NewEntity wrote are left untouched.
func Generate(opts GenerateOptions) ([]byte, error) {
	email := strings.TrimSpace(opts.Email)
	if email == "" {
		return nil, errors.New("an email address is required to generate a key")
	}
	name := strings.TrimSpace(opts.Name)

	// Pin the algorithms instead of inheriting whatever the library defaults
	// happen to be, so a key generated today and one generated after a
	// dependency bump are the same kind of key.
	cfg := &packet.Config{
		Algorithm:              packet.PubKeyAlgoEdDSA,
		Curve:                  packet.Curve25519,
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionNone,
	}
	entity, err := openpgp.NewEntity(name, "", email, cfg)
	if err != nil {
		return nil, err
	}
	if len(opts.Passphrase) > 0 {
		if err := entity.EncryptPrivateKeys(opts.Passphrase, cfg); err != nil {
			return nil, err
		}
	}

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, err
	}
	if err := entity.SerializePrivateWithoutSigning(w, nil); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
