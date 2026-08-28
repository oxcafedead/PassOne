package sshx

import (
	"errors"
	"fmt"

	"github.com/oxcafedead/passone/internal/security"
	"golang.org/x/crypto/ssh"
)

// SSHKey holds an imported SSH identity in memory while unlocked.
type SSHKey struct {
	signer     ssh.Signer
	passphrase []byte // preserved while unlocked; zeroed by Lock
	public     []byte // authorized_keys line (non-secret)
	algorithm  string
	comment    string
}

// ErrUnsupportedKey is returned for key types outside the v1 scope.
var ErrUnsupportedKey = errors.New("unsupported SSH key type: only Ed25519 and RSA are supported in this version")

// ImportPrivateKey parses an OpenSSH private key file (PEM or the OpenSSH
// format), validating the passphrase when the key is encrypted. Unsupported
// key types are rejected for v1.
func ImportPrivateKey(pemBytes []byte, passphrase []byte) (*SSHKey, error) {
	var signer ssh.Signer
	var err error
	signer, err = ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			if passphrase == nil {
				return nil, errors.New("the SSH key is passphrase-protected; a passphrase is required")
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)
		}
		if err != nil {
			return nil, fmt.Errorf("unable to parse the SSH private key: %v", err)
		}
	}

	algo := signer.PublicKey().Type()
	if algo != ssh.KeyAlgoED25519 && algo != ssh.KeyAlgoRSA {
		return nil, ErrUnsupportedKey
	}

	k := &SSHKey{
		signer:    signer,
		algorithm: algo,
		public:    append([]byte(nil), ssh.MarshalAuthorizedKey(signer.PublicKey())...),
	}
	k.setPassphrase(passphrase)
	return k, nil
}

// Algorithm returns the public key algorithm (e.g. ssh-ed25519).
func (k *SSHKey) Algorithm() string { return k.algorithm }

// PublicAuthorizedKey returns the public key in authorized_keys format.
func (k *SSHKey) PublicAuthorizedKey() []byte { return append([]byte(nil), k.public...) }

// Fingerprint returns the SHA256 fingerprint of the public key.
func (k *SSHKey) Fingerprint() string { return ssh.FingerprintSHA256(k.signer.PublicKey()) }

// Signer exposes the configured signer for SSH authentication.
func (k *SSHKey) Signer() ssh.Signer { return k.signer }

func (k *SSHKey) setPassphrase(passphrase []byte) {
	if k.passphrase != nil {
		security.Zero(k.passphrase)
	}
	if passphrase == nil {
		k.passphrase = nil
		return
	}
	k.passphrase = make([]byte, len(passphrase))
	copy(k.passphrase, passphrase)
}

// Lock drops the passphrase and signer from memory (best effort).
func (k *SSHKey) Lock() {
	if k.passphrase != nil {
		security.Zero(k.passphrase)
	}
	k.passphrase = nil
	k.signer = nil
}

// PrivateKeyRequiresPassphrase reports whether the PEM/OpenSSH key is
// encrypted with a passphrase.
func PrivateKeyRequiresPassphrase(pemBytes []byte) (bool, error) {
	_, err := ssh.ParsePrivateKey(pemBytes)
	if err == nil {
		return false, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return true, nil
	}
	return false, fmt.Errorf("unable to parse the SSH private key: %v", err)
}

// ParsePublicKey parses a base64 ssh public key blob (used by known_hosts).
func ParsePublicKey(blob []byte) (ssh.PublicKey, error) {
	return ssh.ParsePublicKey(blob)
}
