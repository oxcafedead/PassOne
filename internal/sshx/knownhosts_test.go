package sshx

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func hostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

func TestKnownHostsLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	k1 := hostKey(t)
	k2 := hostKey(t)

	store, err := NewKnownHostsStore(path)
	if err != nil {
		t.Fatalf("NewKnownHostsStore: %v", err)
	}
	if err := store.Add("github.com", k1); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.Add("github.com", k1); err != nil {
		t.Fatalf("re-Add same key: %v", err)
	}
	if err := store.Verify("GITHUB.COM:22", k1); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := store.Verify("github.com", k2); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("expected ErrHostKeyChanged, got %v", err)
	}
	if err := store.Verify("example.net", k1); !errors.Is(err, ErrUnknownHostKey) {
		t.Fatalf("expected ErrUnknownHostKey, got %v", err)
	}
	if store.LineCount() != 1 {
		t.Fatalf("LineCount = %d", store.LineCount())
	}

	reloaded, err := NewKnownHostsStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := reloaded.Verify("github.com", k1); err != nil {
		t.Fatalf("verify after reload: %v", err)
	}
	listed := reloaded.List()
	if len(listed) != 1 {
		t.Fatalf("List = %v", listed)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"GITHUB.COM":     "github.com",
		"github.com:22":  "github.com",
		"  GitHub.com  ": "github.com",
		"git@github.com": "git@github.com", // not a known_hosts form; left as-is
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCallbackFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	store, err := NewKnownHostsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Callback()("known-hostonly", nil, hostKey(t)); !errors.Is(err, ErrUnknownHostKey) {
		t.Fatalf("expected callback to fail for unknown host, got %v", err)
	}
}

func TestKnownHostsListSkipsBadLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("bad-line\n\n# comment\ngithub.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIhz2GK/XCUj4i6Q5yQJNL1Mad6Yhy1hVA0F5Kp8GDK\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewKnownHostsStore(path)
	if err != nil {
		t.Fatalf("NewKnownHostsStore: %v", err)
	}
	listed := store.List()
	if len(listed) != 1 {
		t.Fatalf("List = %v", listed)
	}
}

func TestKnownHostsVerifySkipsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	// A line for the right host but with only one field should be skipped.
	if err := os.WriteFile(path, []byte("github.com ssh-ed25519\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewKnownHostsStore(path)
	if err != nil {
		t.Fatalf("NewKnownHostsStore: %v", err)
	}
	if err := store.Verify("github.com", hostKey(t)); !errors.Is(err, ErrUnknownHostKey) {
		t.Fatalf("expected unknown host, got %v", err)
	}
}

func TestParseStoredKeyErrors(t *testing.T) {
	if _, err := parseStoredKey([]string{"ssh-ed25519"}); err == nil {
		t.Fatal("expected error for incomplete stored key")
	}
	if _, err := parseStoredKey([]string{"ssh-ed25519", "!!!not-base64!!!"}); err == nil {
		t.Fatal("expected base64 decode error")
	}
	if _, err := parseStoredKey([]string{"ssh-ed25519", "aGVsbG8="}); err == nil {
		t.Fatal("expected parse public key error")
	}
}

func TestRecordLineRoundtrip(t *testing.T) {
	key := hostKey(t)
	line := recordLine("github.com", key)
	fields := strings.Fields(line)
	if len(fields) != 3 {
		t.Fatalf("recordLine = %q (%d fields)", line, len(fields))
	}
	parsed, err := parseStoredKey(fields[1:])
	if err != nil {
		t.Fatalf("parseStoredKey: %v", err)
	}
	if !bytes.Equal(parsed.Marshal(), key.Marshal()) {
		t.Fatal("recordLine roundtrip mismatch")
	}
}

func TestNewKnownHostsStoreDirectoryPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewKnownHostsStore(path); err == nil {
		t.Fatal("expected error when known_hosts path is a directory")
	}
}

func TestKnownHostsAddWriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer func() { _ = os.Chmod(path, 0o600) }()

	store, err := NewKnownHostsStore(path)
	if err != nil {
		t.Fatalf("NewKnownHostsStore: %v", err)
	}
	if err := store.Add("host", hostKey(t)); err == nil {
		t.Fatal("expected write error on read-only known_hosts file")
	}
}
