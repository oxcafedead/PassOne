package sshx

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestEnsurePort(t *testing.T) {
	cases := map[string]string{
		"github.com":       "github.com:22",
		"github.com:22":    "github.com:22",
		"git.example:2222": "git.example:2222",
		"EXAMPLE.com":      "EXAMPLE.com:22",
	}
	for in, want := range cases {
		if got := ensurePort(in); got != want {
			t.Errorf("ensurePort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCaptureHostKeyTimesOut(t *testing.T) {
	// Use a port that is extremely unlikely to accept connections.
	// CaptureHostKey should fail quickly thanks to the timeout.
	start := time.Now()
	if _, err := CaptureHostKey("127.0.0.1:1"); err == nil {
		t.Fatal("expected CaptureHostKey to fail")
	}
	if time.Since(start) > 30*time.Second {
		t.Fatal("CaptureHostKey took too long to fail")
	}
}

func TestCaptureHostKeySuccess(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				// The client aborts after the host key is presented, so the
				// handshake is expected to return an error.
				_, _, _, _ = ssh.NewServerConn(c, serverConfig)
			}(conn)
		}
	}()

	key, err := CaptureHostKey(listener.Addr().String())
	if err != nil {
		t.Fatalf("CaptureHostKey: %v", err)
	}
	if key == nil {
		t.Fatal("expected a captured host key")
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("host key type = %q", key.Type())
	}

	_ = listener.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server goroutine did not finish")
	}
}

func TestTestConnectionLocalServer(t *testing.T) {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _, _, _ = ssh.NewServerConn(c, serverConfig)
			}(conn)
		}
	}()

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}

	hostKey, err := CaptureHostKey(listener.Addr().String())
	if err != nil {
		t.Fatalf("CaptureHostKey: %v", err)
	}
	callback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if bytes.Equal(key.Marshal(), hostKey.Marshal()) {
			return nil
		}
		return errors.New("host key mismatch")
	}
	if err := TestConnection("git", listener.Addr().String(), clientSigner, callback); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}

	_ = listener.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server goroutine did not finish")
	}
}
