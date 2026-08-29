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
		GitAuthorName:         "PassOne",
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

func TestResolvePathsUsesEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PASSONE_DIR", dir)
	p := ResolvePaths()
	if p.Base != dir {
		t.Fatalf("ResolvePaths base = %q, want %q", p.Base, dir)
	}
	if p.ConfigFile != filepath.Join(dir, "config.json") {
		t.Fatalf("ConfigFile = %q", p.ConfigFile)
	}
}

func TestRestrictACLAndMoveFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestrictACL(src); err != nil {
		t.Fatalf("RestrictACL: %v", err)
	}
	if err := MoveFile(src, dst); err != nil {
		t.Fatalf("MoveFile: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("source should be gone after move")
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("moved content = %q", data)
	}
}

func TestDirIsEmpty(t *testing.T) {
	empty := t.TempDir()
	ok, err := DirIsEmpty(empty)
	if err != nil {
		t.Fatalf("DirIsEmpty: %v", err)
	}
	if !ok {
		t.Fatal("expected empty dir")
	}

	nonEmpty := t.TempDir()
	if err := os.WriteFile(filepath.Join(nonEmpty, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err = DirIsEmpty(nonEmpty)
	if err != nil {
		t.Fatalf("DirIsEmpty: %v", err)
	}
	if ok {
		t.Fatal("expected non-empty dir")
	}
}

func TestManagerLoadMalformedJSON(t *testing.T) {
	paths := PathsFromBase(t.TempDir())
	if err := os.WriteFile(paths.ConfigFile, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(paths)
	if _, err := m.Load(); err == nil {
		t.Fatal("expected Load to fail on malformed JSON")
	}
}
