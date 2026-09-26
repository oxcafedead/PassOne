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

func TestHostPortKey(t *testing.T) {
	cases := map[string]string{
		"github.com":      "github.com:22",
		"github.com:22":   "github.com:22",
		"GitHub.com:2222": "github.com:2222",
		"[::1]:2222":      "[::1]:2222",
		"127.0.0.1:1":     "127.0.0.1:1",
	}
	for in, want := range cases {
		if got := HostPortKey(in); got != want {
			t.Errorf("HostPortKey(%q) = %q, want %q", in, got, want)
		}
	}
	if got := HostPortKey("  github.com:2222 "); got != "github.com:2222" {
		t.Errorf("HostPortKey did not trim: %q", got)
	}
	// Canonicalisation must be idempotent, since stored records go through it.
	for _, in := range []string{"github.com", "github.com:2222", "[::1]:2222"} {
		once := HostPortKey(in)
		if twice := HostPortKey(once); twice != once {
			t.Errorf("HostPortKey(%q) = %q then %q", in, once, twice)
		}
	}
}

func TestKnownHostsAddRefusesChangedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	store, err := NewKnownHostsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first, second := hostKey(t), hostKey(t)
	if err := store.Add("github.com", first); err != nil {
		t.Fatalf("Add: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// A different key for a host that is already trusted must be refused, not
	// appended: the caller cannot tell "user confirmed a new key" from
	// "attacker answered the second connection".
	if err := store.Add("github.com", second); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("expected ErrHostKeyChanged, got %v", err)
	}
	if store.LineCount() != 1 {
		t.Fatalf("LineCount = %d, want 1", store.LineCount())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("store was rewritten:\nbefore %q\nafter  %q", before, after)
	}
	if err := store.Verify("github.com", first); err != nil {
		t.Fatalf("the trusted key must survive a refused Add: %v", err)
	}
}

func TestKnownHostsVerifyIsPerPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	store, err := NewKnownHostsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	key := hostKey(t)
	if err := store.Add("github.com:2222", key); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Same key, but the host is reached on a different port: unknown, not trusted.
	if err := store.Verify("github.com:22", key); !errors.Is(err, ErrUnknownHostKey) {
		t.Fatalf("expected ErrUnknownHostKey on another port, got %v", err)
	}
	if err := store.Verify("github.com:2222", key); err != nil {
		t.Fatalf("Verify on the trusted port: %v", err)
	}
	// A different key on :22 is a separate host:port and can be trusted.
	other := hostKey(t)
	if err := store.Add("github.com", other); err != nil {
		t.Fatalf("Add on the default port: %v", err)
	}
	if store.LineCount() != 2 {
		t.Fatalf("LineCount = %d, want 2", store.LineCount())
	}
}

func TestKnownHostsVerifyAcceptsAnyStoredKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	// A host that publishes two keys (e.g. ed25519 and rsa) must verify
	// against the second record, not be reported as changed by the first.
	first, second, third := hostKey(t), hostKey(t), hostKey(t)
	lines := recordLine("github.com:22", first) + "\n" + recordLine("github.com:22", second) + "\n"
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewKnownHostsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Verify("github.com", first); err != nil {
		t.Fatalf("Verify first key: %v", err)
	}
	if err := store.Verify("github.com", second); err != nil {
		t.Fatalf("Verify second key: %v", err)
	}
	err = store.Verify("github.com", third)
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("expected ErrHostKeyChanged for a third key, got %v", err)
	}
	// The report names both the trusted and the presented fingerprint.
	if !strings.Contains(err.Error(), ssh.FingerprintSHA256(first)) ||
		!strings.Contains(err.Error(), ssh.FingerprintSHA256(third)) {
		t.Fatalf("change report does not name both fingerprints: %v", err)
	}
}

func TestKnownHostsVerifyLegacyBareHostRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := hostKey(t)
	// Records written before trust was keyed on the port carry a bare host;
	// they are read as the default port so an existing store keeps working.
	if err := os.WriteFile(path, []byte(recordLine("github.com", key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewKnownHostsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Verify("github.com:22", key); err != nil {
		t.Fatalf("Verify legacy record: %v", err)
	}
	if err := store.Verify("github.com:2222", key); !errors.Is(err, ErrUnknownHostKey) {
		t.Fatalf("expected ErrUnknownHostKey on another port, got %v", err)
	}
}

func TestKnownHostsNilKey(t *testing.T) {
	store, err := NewKnownHostsStore(filepath.Join(t.TempDir(), "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add("github.com", nil); err == nil {
		t.Fatal("expected Add to reject a nil key")
	}
	if err := store.Verify("github.com", nil); err == nil {
		t.Fatal("expected Verify to reject a nil key")
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
	if err := os.WriteFile(path, []byte("github.com:22 ssh-ed25519\n"), 0o600); err != nil {
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
