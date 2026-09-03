package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/oxcafedead/passone/internal/config"
)

// keyLen is the length of the derived vault key in bytes (AES-256).
const keyLen = 32

// argon2 parameters. These are high enough to slow offline guessing of a weak
// master passphrase (see docs/security.md) while staying interactive on a
// typical desktop. They only apply when a key is first sealed or opened.
const (
	argonTime    = 4
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
)

// Vault seals and opens key material with a derived key
// (key_disk = Argon2id(master_passphrase)). No persistent secret key is ever
// stored on disk; the derived key exists only in process memory.
type Vault struct {
	paths config.Paths
}

// OpenVault binds a Vault to the application data layout. It does not touch
// any key material; callers derive key_disk via DeriveKey on each unlock.
func OpenVault(paths config.Paths) (*Vault, error) {
	return &Vault{paths: paths}, nil
}

// DeriveKey computes key_disk = Argon2id(passphrase, salt). The result must be
// wiped with Zero when no longer needed.
func DeriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, keyLen)
}

// LoadOrCreateSalt returns the on-disk random salt used for key derivation,
// creating it (restrictive permissions) if it does not yet exist.
func (v *Vault) LoadOrCreateSalt() ([]byte, error) {
	path := v.paths.SaltFile
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) == 0 {
			Zero(data)
			return nil, errors.New("vault salt is empty")
		}
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read vault salt: %w", err)
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		Zero(salt)
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, salt, 0o600); err != nil {
		Zero(salt)
		return nil, err
	}
	_ = config.RestrictACL(tmp)
	if err := atomicMove(tmp, path); err != nil {
		Zero(salt)
		return nil, err
	}
	_ = config.RestrictACL(path)
	return salt, nil
}

// Seal encrypts plaintext with key_disk (AES-256-GCM).
func (v *Vault) Seal(key, plaintext []byte) ([]byte, error) {
	block, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, block.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return block.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts data previously produced by Seal.
func (v *Vault) Open(key, sealed []byte) ([]byte, error) {
	block, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < block.NonceSize() {
		return nil, errors.New("sealed blob too short")
	}
	nonce, ciphertext := sealed[:block.NonceSize()], sealed[block.NonceSize():]
	plaintext, err := block.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	return plaintext, nil
}

// ErrIntegrity is returned (wrapped) when opening a sealed blob fails the
// AES-GCM authentication check, typically because the wrong key was used or
// the data was tampered with.
var ErrIntegrity = errors.New("key material integrity check failed")

// IsIntegrityError reports whether err is an integrity-check failure.
func IsIntegrityError(err error) bool {
	return errors.Is(err, ErrIntegrity)
}

// LoadSealed reads a vault-sealed blob and opens it with key_disk.
func (v *Vault) LoadSealed(key []byte, path string) ([]byte, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer Zero(sealed)
	return v.Open(key, sealed)
}

// Store seals plaintext with key_disk and writes it atomically to path with
// restrictive permissions.
func (v *Vault) Store(key []byte, path string, plaintext []byte) error {
	sealed, err := v.Seal(key, plaintext)
	if err != nil {
		return err
	}
	defer Zero(sealed)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return err
	}
	_ = config.RestrictACL(tmp)
	if err := atomicMove(tmp, path); err != nil {
		return err
	}
	_ = config.RestrictACL(path)
	return nil
}

// StoreSalt persists the vault salt at a given path with restrictive
// permissions. It is used by migration tests and upgrades.
func (v *Vault) StoreSalt(path string, salt []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, salt, 0o600); err != nil {
		return err
	}
	_ = config.RestrictACL(tmp)
	if err := atomicMove(tmp, path); err != nil {
		return err
	}
	_ = config.RestrictACL(path)
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, errors.New("vault key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func atomicMove(src, dst string) error {
	return config.MoveFile(src, dst)
}
