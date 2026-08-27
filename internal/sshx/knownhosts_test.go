package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
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
