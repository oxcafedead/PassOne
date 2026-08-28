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

	"github.com/oxcafedead/passone/internal/config"
)

// Vault seals and opens key material using a random application key that is
// itself protected at rest by a KeyProtector (DPAPI initially, Windows Hello
// later). The application key lives only in memory while the process runs.
type Vault struct {
	key       []byte
	protector KeyProtector
	keyPath   string
}

// OpenVault loads (creating if needed) the protected application key and
// returns a Vault bound to it.
func OpenVault(paths config.Paths) (*Vault, error) {
	protector := &DPAPIKeyProtector{}
	key, err := loadOrCreateAppKey(protector, paths.AppKeyFile)
	if err != nil {
		return nil, err
	}
	return &Vault{key: key, protector: protector, keyPath: paths.AppKeyFile}, nil
}

// Seal encrypts plaintext with the application key (AES-256-GCM).
func (v *Vault) Seal(plaintext []byte) ([]byte, error) {
	if v == nil || v.key == nil {
		return nil, errors.New("vault is not initialized")
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts data previously produced by Seal.
func (v *Vault) Open(sealed []byte) ([]byte, error) {
	if v == nil || v.key == nil {
		return nil, errors.New("vault is not initialized")
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed blob too short")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("key material integrity check failed: %w", err)
	}
	return plaintext, nil
}

// Wipe zeroes the in-memory application key. The Vault becomes unusable.
func (v *Vault) Wipe() {
	if v == nil {
		return
	}
	Zero(v.key)
	v.key = nil
}

// KeyPath returns the on-disk location of the protected application key.
func (v *Vault) KeyPath() string {
	return v.keyPath
}

func loadOrCreateAppKey(protector KeyProtector, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, err := protector.Unprotect(data)
		if err != nil {
			return nil, fmt.Errorf("unable to unprotect application key: %w", err)
		}
		if len(key) != 32 {
			Zero(key)
			return nil, errors.New("application key has unexpected length")
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read application key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	sealed, err := protector.Protect(key)
	if err != nil {
		Zero(key)
		return nil, fmt.Errorf("unable to protect application key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		Zero(key)
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		Zero(key)
		return nil, err
	}
	_ = config.RestrictACL(tmp)
	if err := atomicMove(tmp, path); err != nil {
		Zero(key)
		return nil, err
	}
	_ = config.RestrictACL(path)
	return key, nil
}

// LoadSealed reads a vault-sealed blob and opens it.
func (v *Vault) LoadSealed(path string) ([]byte, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer Zero(sealed)
	return v.Open(sealed)
}

// Store seals plaintext with the application key and writes it atomically to
// path with restrictive permissions.
func (v *Vault) Store(path string, plaintext []byte) error {
	sealed, err := v.Seal(plaintext)
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

func atomicMove(src, dst string) error {
	return config.MoveFile(src, dst)
}
