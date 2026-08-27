package pgp

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/oxcafedead/gopass-desktop/internal/security"
)

// KeyInfo is a non-secret description of an OpenPGP key used for display.
type KeyInfo struct {
	Fingerprint string   // 40 hex chars of the primary key
	KeyID       string   // short key id (16 hex chars)
	UserIDs     []string // user ids on the key
	Algorithm   string   // public key algorithm
	HasSecret   bool     // whether the block carries private key material
}

// Service holds the in-memory OpenPGP key material while the application is
// unlocked. Lock must be called to drop references to key material.
type Service struct {
	entities   []*openpgp.Entity // decrypted private keys while unlocked
	passphrase []byte            // kept in memory while unlocked
}

// New returns an empty Service.
func New() *Service {
	return &Service{}
}

// readArmoredKeyRing reads an entity list from ASCII-armored OpenPGP data.
func readArmoredKeyRing(block []byte) (openpgp.EntityList, error) {
	armored, err := armor.Decode(bytes.NewReader(block))
	if err != nil {
		return nil, err
	}
	return openpgp.ReadKeyRing(armored.Body)
}

// Describe returns non-secret details about a parsed entity list.
func Describe(entities []*openpgp.Entity) []*KeyInfo {
	var out []*KeyInfo
	for _, e := range entities {
		info := KeyInfo{
			Fingerprint: FingerprintOf(e),
			KeyID:       KeyIDOf(e),
			Algorithm:   pubKeyAlgoName(e.PrimaryKey.PubKeyAlgo),
			HasSecret:   e.PrivateKey != nil && !e.PrivateKey.Dummy(),
		}
		var ids []string
		for _, ident := range e.Identities {
			ids = append(ids, ident.Name)
		}
		sort.Strings(ids)
		info.UserIDs = ids
		out = append(out, &info)
	}
	return out
}

// DescribeOwn describes the currently imported keys.
func (s *Service) DescribeOwn() []*KeyInfo {
	return Describe(s.entities)
}

// ImportSecret validates and takes ownership of an armored secret key block.
// The passphrase is validated and the entity list is kept decrypted in memory.
func (s *Service) ImportSecret(block []byte, passphrase []byte) ([]*KeyInfo, error) {
	entities, err := readArmoredKeyRing(block)
	if err != nil {
		return nil, fmt.Errorf("unable to parse the OpenPGP private key: %v", err)
	}
	if len(entities) == 0 {
		return nil, errors.New("no OpenPGP key found in the supplied data")
	}
	if err := unlockEntities(entities, passphrase); err != nil {
		return nil, err
	}
	s.entities = entities
	s.setPassphrase(passphrase)
	return Describe(entities), nil
}

// ArmoredSecret serializes the imported key material back to an ASCII-armored
// private key block for local storage (sealed by the vault). The serialization
// preserves each secret key packet as it was imported.
func (s *Service) ArmoredSecret() ([]byte, error) {
	if len(s.entities) == 0 {
		return nil, errors.New("no key material in memory")
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, err
	}
	for _, e := range s.entities {
		if err := e.SerializePrivate(w, nil); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unlock parses stored armored key material and decrypts the private keys
// with the given passphrase, keeping the result in memory.
func (s *Service) Unlock(block []byte, passphrase []byte) error {
	entities, err := readArmoredKeyRing(block)
	if err != nil {
		return fmt.Errorf("unable to parse the stored OpenPGP key: %v", err)
	}
	if err := unlockEntities(entities, passphrase); err != nil {
		return err
	}
	s.entities = entities
	s.setPassphrase(passphrase)
	return nil
}

// BlockRequiresPassphrase reports whether any secret key in the block is
// passphrase-encrypted. Used to decide whether to prompt for a passphrase.
func BlockRequiresPassphrase(block []byte) (bool, error) {
	entities, err := readArmoredKeyRing(block)
	if err != nil {
		return false, err
	}
	for _, e := range entities {
		if e.PrivateKey != nil && e.PrivateKey.Encrypted {
			return true, nil
		}
		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
				return true, nil
			}
		}
	}
	return false, nil
}

func unlockEntities(entities []*openpgp.Entity, passphrase []byte) error {
	for _, e := range entities {
		if e.PrivateKey == nil {
			continue
		}
		if err := e.DecryptPrivateKeys(passphrase); err != nil {
			if os.Getenv("GOPASS_DESKTOP_DEBUG") != "" {
				return fmt.Errorf("unable to unlock the OpenPGP key (passphrase len=%d): %v", len(passphrase), err)
			}
			return fmt.Errorf("unable to unlock the OpenPGP key with the given passphrase")
		}
	}
	return nil
}

func (s *Service) setPassphrase(passphrase []byte) {
	if s.passphrase != nil {
		security.Zero(s.passphrase)
	}
	if passphrase == nil {
		s.passphrase = nil
		return
	}
	s.passphrase = make([]byte, len(passphrase))
	copy(s.passphrase, passphrase)
}

// Lock drops all in-memory key material and passphrases (best effort).
func (s *Service) Lock() {
	if s.passphrase != nil {
		security.Zero(s.passphrase)
	}
	s.passphrase = nil
	s.entities = nil
	// Best effort: prompt the collector to reclaim decrypted key memory.
	runtime.GC()
}

var lockedErr = errors.New("the application is locked; run unlock first")

// Encrypt encrypts plaintext to the given recipient entities, producing a
// standard OpenPGP message compatible with GnuPG and pass.
func Encrypt(plaintext []byte, recipients []*openpgp.Entity) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no encryption recipients available (.gpg-id misconfigured)")
	}
	var buf bytes.Buffer
	w, err := openpgp.Encrypt(&buf, recipients, nil, &openpgp.FileHints{
		IsBinary: false,
		FileName: "secret",
	}, gnuPGCompatConfig())
	if err != nil {
		return nil, fmt.Errorf("unable to start OpenPGP encryption: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// pubKeyAlgoName maps a public key algorithm to a human-readable name.
func pubKeyAlgoName(a packet.PublicKeyAlgorithm) string {
	switch a {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		return "RSA"
	case packet.PubKeyAlgoEdDSA:
		return "Ed25519"
	case packet.PubKeyAlgoECDSA:
		return "ECDSA"
	case packet.PubKeyAlgoECDH:
		return "ECDH"
	case packet.PubKeyAlgoDSA:
		return "DSA"
	case packet.PubKeyAlgoElGamal:
		return "ElGamal"
	default:
		return "unknown"
	}
}

// gnuPGCompatConfig tunes encryption for maximum interoperability with
// GnuPG/pass: AES-256 like GnuPG's default cipher, AEAD disabled (SEIPDv1,
// the format pass and GnuPG expect), no compression, SHA-256.
func gnuPGCompatConfig() *packet.Config {
	return &packet.Config{
		DefaultCipher:          packet.CipherAES256,
		DefaultHash:            crypto.SHA256,
		DefaultCompressionAlgo: packet.CompressionNone,
		AEADConfig:             nil,
	}
}

// Decrypt decrypts an OpenPGP message using the unlocked in-memory keyring.
func (s *Service) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(s.entities) == 0 {
		return nil, lockedErr
	}
	md, err := openpgp.ReadMessage(
		bytes.NewReader(ciphertext),
		openpgp.EntityList(s.entities),
		func(_ []openpgp.Key, _ bool) ([]byte, error) {
			if s.passphrase == nil {
				return nil, lockedErr
			}
			return s.passphrase, nil
		},
		nil,
	)
	if err != nil {
		return nil, userError(err)
	}
	if !md.IsEncrypted {
		return nil, errors.New("the file is not an OpenPGP encrypted message")
	}
	// Consume the full body so the modification-detection code is verified.
	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, userError(err)
	}
	return plaintext, nil
}

// userError maps low-level crypto errors to user-readable messages without
// leaking secrets or technical noise.
func userError(err error) error {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no valid pgp data"):
		return errors.New("the file does not contain a valid OpenPGP message")
	case strings.Contains(msg, "unable to decrypt"):
		return errors.New("unable to decrypt with the configured key; the OpenPGP key may not match this file")
	case strings.Contains(msg, "modification") || strings.Contains(msg, "integrity"):
		return errors.New("decrypted data failed its integrity check; the file may be corrupted")
	case strings.Contains(msg, "packet"):
		return errors.New("unable to decrypt: malformed or unsupported OpenPGP packets")
	default:
		return errors.New("unable to decrypt the password: the OpenPGP key may be missing or the passphrase incorrect")
	}
}

// ResolveRecipients maps the identifiers listed in .gpg-id to entities from
// the unlocked keyring. Identifiers may be fingerprints, key ids, or user id
// names. Any identifier that cannot be resolved is reported, and no partial
// recipient list is silently used.
func (s *Service) ResolveRecipients(ids []string) ([]*openpgp.Entity, error) {
	var resolved []*openpgp.Entity
	var missing []string
	for _, id := range ids {
		norm := strings.ToUpper(strings.TrimSpace(id))
		if norm == "" {
			continue
		}
		var found *openpgp.Entity
		for _, e := range s.entities {
			if entityMatches(e, norm, id) {
				found = e
				break
			}
		}
		if found == nil {
			missing = append(missing, id)
			continue
		}
		resolved = append(resolved, found)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf(
			"required OpenPGP key not found:\n  %s\nImport the matching key to continue, or fix .gpg-id.",
			strings.Join(missing, "\n  "),
		)
	}
	return resolved, nil
}

func entityMatches(e *openpgp.Entity, upperID, original string) bool {
	fp := strings.ToUpper(FingerprintOf(e))
	// Full fingerprint or a suffix (covers short and long key ids).
	if upperID == fp || strings.HasSuffix(fp, upperID) {
		return true
	}
	lOriginal := strings.ToLower(original)
	for _, ident := range e.Identities {
		if strings.EqualFold(strings.TrimSpace(ident.Name), original) {
			return true
		}
		if strings.Contains(strings.ToLower(ident.Name), lOriginal) {
			return true
		}
	}
	return false
}

// FingerprintOf returns the 40-char uppercase hex fingerprint.
func FingerprintOf(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}

// KeyIDOf returns the 16-char uppercase hex key id.
func KeyIDOf(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint[len(e.PrimaryKey.Fingerprint)-8:]))
}

// SinglePrimaryFingerprint returns the primary fingerprint of the single
// imported key. It is used when a fresh store needs a default .gpg-id.
func (s *Service) SinglePrimaryFingerprint() (string, error) {
	if len(s.entities) == 0 {
		return "", lockedErr
	}
	if len(s.entities) > 1 {
		return "", errors.New("multiple keys imported; cannot choose a default automatically")
	}
	return FingerprintOf(s.entities[0]), nil
}
