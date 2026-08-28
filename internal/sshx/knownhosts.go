package sshx

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/oxcafedead/passone/internal/config"
	"golang.org/x/crypto/ssh"
)

// Sentinel errors for the application-specific host-key store.
var (
	ErrUnknownHostKey = errors.New("unknown SSH host key for this host")
	ErrHostKeyChanged = errors.New("SSH host key changed for this host")
)

// KnownHostsStore is the application's own known_hosts database. It is
// independent of the user's OpenSSH ~/.ssh/known_hosts.
type KnownHostsStore struct {
	path  string
	lines []string
}

// NewKnownHostsStore loads (or creates empty) the store at path.
func NewKnownHostsStore(path string) (*KnownHostsStore, error) {
	k := &KnownHostsStore{path: path}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return k, nil
		}
		return nil, err
	}
	defer f.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k.lines = append(k.lines, line)
	}
	return k, nil
}

// NormalizeHost lowercases a hostname and strips a port if present.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

// Verify checks that the presented host key matches the stored one.
func (k *KnownHostsStore) Verify(host string, key ssh.PublicKey) error {
	host = NormalizeHost(host)
	for _, line := range k.lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[0] != host {
			continue
		}
		expected, err := parseStoredKey(fields[1:])
		if err != nil {
			continue
		}
		if bytes.Equal(expected.Marshal(), key.Marshal()) {
			return nil
		}
		return ErrHostKeyChanged
	}
	return ErrUnknownHostKey
}

// Add stores a host key and persists the store.
func (k *KnownHostsStore) Add(host string, key ssh.PublicKey) error {
	host = NormalizeHost(host)
	if err := k.Verify(host, key); err == nil {
		return nil
	}
	k.lines = append(k.lines, recordLine(host, key))
	k.sortLines()
	data := bytes.Join([][]byte{[]byte(strings.Join(k.lines, "\n"))}, []byte("\n"))
	data = append(data, '\n')
	tmp := k.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	_ = config.RestrictACL(tmp)
	if err := config.MoveFile(tmp, k.path); err != nil {
		return err
	}
	_ = config.RestrictACL(k.path)
	return nil
}

// List returns entries "host keytype SHA256:<fingerprint>".
func (k *KnownHostsStore) List() []string {
	out := make([]string, 0, len(k.lines))
	for _, line := range k.lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pub, err := parseStoredKey(fields[1:])
		if err != nil {
			continue
		}
		out = append(out, fields[0]+" "+fields[1]+" "+ssh.FingerprintSHA256(pub))
	}
	sort.Strings(out)
	return out
}

// Callback returns an ssh.HostKeyCallback bound to this store. Unknown or
// changed keys fail closed.
func (k *KnownHostsStore) Callback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return k.Verify(hostname, key)
	}
}

// HostKeyFingerprint formats the SHA256 fingerprint, trimming to the familiar
// "SHA256:..." form used by ssh.
func HostKeyFingerprint(key ssh.PublicKey) string {
	return ssh.FingerprintSHA256(key)
}

// KeyAlgorithm returns the key algorithm name (e.g. ssh-ed25519).
func KeyAlgorithm(key ssh.PublicKey) string {
	return key.Type()
}

func recordLine(host string, key ssh.PublicKey) string {
	fields := strings.Fields(string(ssh.MarshalAuthorizedKey(key)))
	if len(fields) == 0 {
		return host + " unknown"
	}
	// fields[0] = algorithm, fields[1] = base64
	if len(fields) >= 2 {
		return host + " " + fields[0] + " " + fields[1]
	}
	return host + " " + fields[0]
}

// parseStoredKey decodes "algo base64" fields (as stored by recordLine) back
// to an ssh.PublicKey. ParsePublicKey expects the raw wire blob, so the base64
// must be decoded first.
func parseStoredKey(fields []string) (ssh.PublicKey, error) {
	if len(fields) < 2 {
		return nil, errors.New("sshx: incomplete stored key")
	}
	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, err
	}
	return ssh.ParsePublicKey(raw)
}

func (k *KnownHostsStore) sortLines() {
	sort.Strings(k.lines)
}

// LineCount reports how many host records are stored.
func (k *KnownHostsStore) LineCount() int { return len(k.lines) }
