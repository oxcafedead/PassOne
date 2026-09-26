package sshx

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/oxcafedead/passone/internal/config"
	"golang.org/x/crypto/ssh"
)

// Sentinel errors for the application-specific host-key store. Callers must
// match them with errors.Is: Verify wraps ErrHostKeyChanged with the stored
// and presented fingerprints, so the error text is not a stable contract.
var (
	ErrUnknownHostKey = errors.New("unknown SSH host key for this host")
	ErrHostKeyChanged = errors.New("SSH host key changed")
)

// KnownHostsStore is the application's own known_hosts database. It is
// independent of the user's OpenSSH ~/.ssh/known_hosts. Records are keyed on
// HostPortKey (host:port), so trust never leaks between ports of one host.
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
	defer func() { _ = f.Close() }()
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

// NormalizeHost lowercases a hostname and strips a port if present. It is the
// display form of a host; trust is keyed on HostPortKey, which keeps the port.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

// HostPortKey returns the canonical store key for a host: a lowercased
// host:port pair with the port defaulting to 22, the same shape OpenSSH writes
// to known_hosts. Trust is per port, so a key confirmed on :22 says nothing
// about the same host reached on another port.
func HostPortKey(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	h, port, err := net.SplitHostPort(hostport)
	if err != nil {
		h, port = hostport, defaultSSHPort
	}
	if port == "" {
		port = defaultSSHPort
	}
	return net.JoinHostPort(strings.ToLower(h), port)
}

const defaultSSHPort = "22"

// Verify checks the presented host key against every key stored for the host.
// A host may legitimately publish more than one key (several algorithms), so a
// match against any record for the host counts as verified and only a host
// that has records but none matching is reported as changed. Records written
// by older versions carry a bare host and are read as the default port, so an
// existing known_hosts file keeps working.
func (k *KnownHostsStore) Verify(hostport string, key ssh.PublicKey) error {
	if key == nil {
		return errors.New("sshx: no host key presented")
	}
	host := HostPortKey(hostport)
	var stored []ssh.PublicKey
	for _, line := range k.lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if HostPortKey(fields[0]) != host {
			continue
		}
		expected, err := parseStoredKey(fields[1:])
		if err != nil {
			continue
		}
		if bytes.Equal(expected.Marshal(), key.Marshal()) {
			return nil
		}
		stored = append(stored, expected)
	}
	if len(stored) > 0 {
		return fmt.Errorf("%w: %s is trusted with %s but the server presented %s",
			ErrHostKeyChanged, host, fingerprints(stored), ssh.FingerprintSHA256(key))
	}
	return ErrUnknownHostKey
}

// Add records a host key and persists the store. It is the only writer, so the
// trust invariant lives here: a host that is already trusted keeps the key it
// has, and a different key is refused with ErrHostKeyChanged instead of
// replacing it. Callers must confirm the key with the user out of band.
func (k *KnownHostsStore) Add(hostport string, key ssh.PublicKey) error {
	if key == nil {
		return errors.New("sshx: no host key to store")
	}
	host := HostPortKey(hostport)
	err := k.Verify(hostport, key)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrUnknownHostKey) {
		// ErrHostKeyChanged, or anything a future Verify may add: a host that
		// is not new never gets its key replaced here.
		return err
	}
	// First contact with this host:port, so record the key.
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

// List returns entries "host:port keytype SHA256:<fingerprint>".
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

// fingerprints renders stored keys for a change report, e.g.
// "SHA256:aaa..., SHA256:bbb...".
func fingerprints(keys []ssh.PublicKey) string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, ssh.FingerprintSHA256(k))
	}
	return strings.Join(out, ", ")
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
