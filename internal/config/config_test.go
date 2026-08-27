package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPathsFromBase(t *testing.T) {
	p := PathsFromBase("C:\\base")
	if p.KeysDir != "C:\\base\\keys" {
		t.Fatalf("KeysDir = %q", p.KeysDir)
	}
	if p.AppKeyFile != filepath.Join("C:\\base\\keys", "app.key") {
		t.Fatalf("AppKeyFile = %q", p.AppKeyFile)
	}
	if p.PGPKeyFile != filepath.Join("C:\\base\\keys", "pgp.dat") {
		t.Fatalf("PGPKeyFile = %q", p.PGPKeyFile)
	}
}

func TestManagerDefaults(t *testing.T) {
	paths := PathsFromBase(t.TempDir())
	m := NewManager(paths)
	cfg, err := m.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AutoLockMinutes != 5 {
		t.Fatalf("AutoLockMinutes = %d", cfg.AutoLockMinutes)
	}
	if cfg.ClipboardClearSeconds != 30 {
		t.Fatalf("ClipboardClearSeconds = %d", cfg.ClipboardClearSeconds)
	}
}

func TestManagerSaveLoadRoundtrip(t *testing.T) {
	paths := PathsFromBase(t.TempDir())
	m := NewManager(paths)
	in := &Config{
		StorePath:             "C:\\stores\\pass",
		GitRemote:             "git@github.com:user/pass.git",
		SSHKeyID:              "ssh-ed25519 ABC...",
		PGPKeyFingerprint:     "AABBCCDDEE",
		AutoLockMinutes:       9,
		ClipboardClearSeconds: 12,
		GitAuthorName:         "Gopass Desktop",
		GitAuthorEmail:        "me@example.com",
	}
	if err := m.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := m.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.StorePath != in.StorePath || out.ReString() != in.ReString() {
		t.Fatalf("roundtrip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func (c *Config) ReString() string {
	return strings.Join([]string{c.GitRemote, c.SSHKeyID, c.PGPKeyFingerprint,
		c.GitAuthorName, c.GitAuthorEmail}, "|")
}

func TestManagerFixesBadDefaults(t *testing.T) {
	paths := PathsFromBase(t.TempDir())
	if err := os.WriteFile(paths.ConfigFile, []byte(`{"autoLockMinutes":0,"clipboardClearSeconds":-1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(paths)
	cfg, err := m.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AutoLockMinutes != 5 || cfg.ClipboardClearSeconds != 30 {
		t.Fatalf("bad values not repaired: %+v", cfg)
	}
}
