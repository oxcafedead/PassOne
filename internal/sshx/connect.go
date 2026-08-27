package sshx

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

var errCaptureOnly = errors.New("host key captured")

// ensurePort defaults the SSH port to 22 when the address has no explicit port.
// net.Dial requires a port, and callers may pass a bare hostname.
func ensurePort(hostport string) string {
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		return net.JoinHostPort(hostport, "22")
	}
	return hostport
}

// CaptureHostKey connects to hostport and returns the server host key without
// trusting it. The handshake is deliberately aborted after the key is seen.
func CaptureHostKey(hostport string) (ssh.PublicKey, error) {
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "git",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return errCaptureOnly
		},
		Timeout: 20 * time.Second,
	}
	conn, err := ssh.Dial("tcp", ensurePort(hostport), cfg)
	if conn != nil {
		_ = conn.Close()
	}
	if captured != nil {
		return captured, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unable to reach %s: %v", hostport, err)
	}
	return nil, fmt.Errorf("unable to reach %s: no SSH host key received", hostport)
}

// TestConnection authenticates to hostport over SSH using the provided signer
// and host key callback. A successful Dial implies the server accepted the
// key. GitHub reports success via the transport; the session itself is not
// usable for a shell, which is expected.
func TestConnection(user, hostport string, signer ssh.Signer, hostKeyCallback ssh.HostKeyCallback) error {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         20 * time.Second,
	}
	conn, err := ssh.Dial("tcp", ensurePort(hostport), cfg)
	if err != nil {
		return fmt.Errorf("SSH connection failed: %v", err)
	}
	_ = conn.Close()
	return nil
}
