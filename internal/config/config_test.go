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
	if cfg.UsernameSource != "auto" {
		t.Fatalf("UsernameSource = %q", cfg.UsernameSource)
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
		UsernameSource:        "body",
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
		c.GitAuthorName, c.GitAuthorEmail, c.UsernameSource}, "|")
}

func TestManagerFixesBadDefaults(t *testing.T) {
	paths := PathsFromBase(t.TempDir())
	if err := os.WriteFile(paths.ConfigFile, []byte(`{"autoLockMinutes":-1,"clipboardClearSeconds":-1,"usernameSource":"bogus"}`), 0o600); err != nil {
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
	if cfg.UsernameSource != "auto" {
		t.Fatalf("bad usernameSource not repaired: %+v", cfg)
	}
}

// TestManagerKeepsDisabledAutoLock pins that a stored 0 is a setting rather than
// a missing value. "Never auto-lock" is what SetAutoLock documents 0 as and
// what the GUI offers as "0 = never", so Load repaired it to the 5-minute
// default and the setting reverted to a timeout the user had explicitly turned
// off (GH #42).
func TestManagerKeepsDisabledAutoLock(t *testing.T) {
	paths := PathsFromBase(t.TempDir())
	m := NewManager(paths)
	if err := m.Save(&Config{AutoLockMinutes: 0, ClipboardClearSeconds: 30}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	cfg, err := m.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AutoLockMinutes != 0 {
		t.Fatalf("AutoLockMinutes = %d, want 0 (auto-lock disabled)", cfg.AutoLockMinutes)
	}
}

// TestManagerMissingAutoLockKeyTakesTheDefault is the other half: 0 may mean
// "never", but a config file that never mentions the setting still has to get
// the default rather than an unarmed auto-lock.
func TestManagerMissingAutoLockKeyTakesTheDefault(t *testing.T) {
	paths := PathsFromBase(t.TempDir())
	if err := os.WriteFile(paths.ConfigFile, []byte(`{"gitRemote":"git@github.com:user/pass.git"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := NewManager(paths).Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AutoLockMinutes != defaultAutoLockMinutes {
		t.Fatalf("AutoLockMinutes = %d, want %d", cfg.AutoLockMinutes, defaultAutoLockMinutes)
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

func TestResolvePathsLocalAppData(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PASSONE_DIR", "")
	t.Setenv("LOCALAPPDATA", dir)
	p := ResolvePaths()
	want := filepath.Join(dir, "PassOne")
	if p.Base != want {
		t.Fatalf("ResolvePaths base = %q, want %q", p.Base, want)
	}
	if p.ConfigFile != filepath.Join(want, "config.json") {
		t.Fatalf("ConfigFile = %q", p.ConfigFile)
	}
}

func TestResolvePathsFallbackToHome(t *testing.T) {
	t.Setenv("PASSONE_DIR", "")
	t.Setenv("LOCALAPPDATA", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("UserHomeDir: %v", err)
	}
	p := ResolvePaths()
	want := filepath.Join(home, "AppData", "Local", "PassOne")
	if p.Base != want {
		t.Fatalf("ResolvePaths base = %q, want %q", p.Base, want)
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

func TestRestrictACLError(t *testing.T) {
	if err := RestrictACL(filepath.Join(t.TempDir(), "does", "not", "exist.txt")); err == nil {
		t.Fatal("expected RestrictACL to fail on a missing file")
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

func TestDirIsEmptyErrors(t *testing.T) {
	_, err := DirIsEmpty(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected error for missing directory")
	}

	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = DirIsEmpty(f)
	if err == nil {
		t.Fatal("expected error when path is a file")
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

func TestManagerLoadReadError(t *testing.T) {
	paths := PathsFromBase(t.TempDir())
	if err := os.Mkdir(paths.ConfigFile, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := NewManager(paths).Load()
	if err == nil {
		t.Fatal("expected Load to fail when config file is a directory")
	}
}

func TestEnsureDirectoriesErrors(t *testing.T) {
	t.Run("base is file", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "base")
		paths := PathsFromBase(base)
		if err := os.WriteFile(base, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := NewManager(paths).EnsureDirectories(); err == nil {
			t.Fatal("expected error when base exists as a file")
		}
	})
	t.Run("keys is file", func(t *testing.T) {
		paths := PathsFromBase(t.TempDir())
		if err := os.WriteFile(paths.KeysDir, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := NewManager(paths).EnsureDirectories(); err == nil {
			t.Fatal("expected error when keys exists as a file")
		}
	})
}

func TestSaveErrors(t *testing.T) {
	t.Run("ensure directories fails", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "base")
		paths := PathsFromBase(base)
		if err := os.WriteFile(base, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := NewManager(paths).Save(defaultConfig()); err == nil {
			t.Fatal("expected Save to fail when base is a file")
		}
	})
	t.Run("write temp fails", func(t *testing.T) {
		base := t.TempDir()
		paths := PathsFromBase(base)
		// The temporary file name is derived from ConfigFile, so an invalid
		// basename causes the WriteFile call to fail.
		paths.ConfigFile = filepath.Join(base, "config>.json")
		if err := NewManager(paths).Save(defaultConfig()); err == nil {
			t.Fatal("expected Save to fail writing temp file with invalid name")
		}
	})
}

func TestAtomicReplaceError(t *testing.T) {
	if err := atomicReplace(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "dst")); err == nil {
		t.Fatal("expected atomicReplace to fail on a missing source")
	}
}
