package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Config holds the user-visible application configuration.
// It must never contain passphrases, private keys or plaintext secrets.
type Config struct {
	StorePath             string `json:"storePath"`
	GitRemote             string `json:"gitRemote"`
	SSHKeyID              string `json:"sshKeyId"`
	PGPKeyFingerprint     string `json:"pgpKeyFingerprint"`
	AutoLockMinutes       int    `json:"autoLockMinutes"`
	ClipboardClearSeconds int    `json:"clipboardClearSeconds"`
	GitAuthorName         string `json:"gitAuthorName"`
	GitAuthorEmail        string `json:"gitAuthorEmail"`
}

// Paths describes the layout of the per-user application data directory.
type Paths struct {
	Base           string
	KeysDir        string
	StoresDir      string
	ConfigFile     string
	KnownHostsFile string
	AppKeyFile     string
	PGPKeyFile     string
	SSHKeyFile     string
}

func defaultConfig() *Config {
	return &Config{
		AutoLockMinutes:       5,
		ClipboardClearSeconds: 30,
		GitAuthorName:         "PassOne",
	}
}

// ResolvePaths returns an absolute Paths structure rooted at the application
// data directory. If LOCALAPPDATA is unset the user home directory is used.
// The PASSONE_DIR environment variable overrides the base directory
// (used by tests and for portable-mode operation).
func ResolvePaths() Paths {
	base := os.Getenv("PASSONE_DIR")
	if base != "" {
		return PathsFromBase(base)
	}
	base = os.Getenv("LOCALAPPDATA")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		base = filepath.Join(home, "AppData", "Local")
	}
	return PathsFromBase(filepath.Join(base, "PassOne"))
}

// PathsFromBase builds a Paths structure from an explicit base directory.
func PathsFromBase(base string) Paths {
	keys := filepath.Join(base, "keys")
	return Paths{
		Base:           base,
		KeysDir:        keys,
		StoresDir:      filepath.Join(base, "stores"),
		ConfigFile:     filepath.Join(base, "config.json"),
		KnownHostsFile: filepath.Join(base, "known_hosts"),
		AppKeyFile:     filepath.Join(keys, "app.key"),
		PGPKeyFile:     filepath.Join(keys, "pgp.dat"),
		SSHKeyFile:     filepath.Join(keys, "ssh.dat"),
	}
}

// Manager loads and persists the configuration file.
type Manager struct {
	paths Paths
	mu    sync.Mutex
}

func NewManager(paths Paths) *Manager {
	return &Manager{paths: paths}
}

// EnsureDirectories creates the application data directories.
func (m *Manager) EnsureDirectories() error {
	for _, d := range []string{m.paths.Base, m.paths.KeysDir, m.paths.StoresDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// Load reads the configuration, returning defaults (unsaved) if absent.
func (m *Manager) Load() (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg := defaultConfig()
	data, err := os.ReadFile(m.paths.ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.AutoLockMinutes <= 0 {
		cfg.AutoLockMinutes = 5
	}
	if cfg.ClipboardClearSeconds <= 0 {
		cfg.ClipboardClearSeconds = 30
	}
	return cfg, nil
}

// Save atomically writes the configuration.
func (m *Manager) Save(cfg *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.EnsureDirectories(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.paths.ConfigFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return atomicReplace(tmp, m.paths.ConfigFile)
}
