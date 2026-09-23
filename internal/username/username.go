// Package username derives the login of a password entry. Pass stores the
// secret in the first line of the plaintext; the login can be encoded either
// in the entry's file name or in a "user: ..." style field in the body.
package username

import (
	"errors"
	"strings"
)

// Mode selects where the login is looked up.
type Mode int

const (
	// ModeAuto prefers a login field in the entry body and falls back to the
	// file name when the body does not carry one.
	ModeAuto Mode = iota
	// ModeBody only reads a login field from the entry body.
	ModeBody
	// ModeFilename only derives the login from the entry's file name.
	ModeFilename
)

// DefaultMode is the mode used when the configuration value is empty or
// unrecognized.
const DefaultMode = "auto"

// ErrUnknownMode is returned when a mode string is not recognized.
var ErrUnknownMode = errors.New("unknown username source")

// ParseMode converts a configuration value to a Mode. An empty value resolves
// to ModeAuto.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return ModeAuto, nil
	case "body":
		return ModeBody, nil
	case "filename":
		return ModeFilename, nil
	}
	return ModeAuto, ErrUnknownMode
}

// String returns the canonical configuration value for the mode.
func (m Mode) String() string {
	switch m {
	case ModeBody:
		return "body"
	case ModeFilename:
		return "filename"
	default:
		return "auto"
	}
}

// Valid reports whether s names a known mode.
func Valid(s string) bool {
	_, err := ParseMode(s)
	return err == nil
}

// Normalize returns the canonical configuration value for s, defaulting to
// DefaultMode for empty or unknown values.
func Normalize(s string) string {
	m, err := ParseMode(s)
	if err != nil {
		return DefaultMode
	}
	return m.String()
}

// bodyLabels are the recognized keys of "key: value" lines that carry the login.
var bodyLabels = map[string]bool{
	"user":       true,
	"username":   true,
	"login":      true,
	"login name": true,
	"user name":  true,
}

// FromBody scans the entry plaintext for the first recognized login field and
// returns its value, or "" when none is present.
func FromBody(body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		label := strings.ToLower(normalizeSpace(line[:i]))
		if !bodyLabels[label] {
			continue
		}
		return strings.TrimSpace(line[i+1:])
	}
	return ""
}

// normalizeSpace collapses runs of whitespace into a single space.
func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// FromName derives the login from the entry's file name using the common pass
// conventions:
//   - "alice@example.com" stores username alice;
//   - "example.com/alice" stores username alice in a per-site folder;
//   - a bare name such as "alice" is itself the login.
//
// A bare top-level file that looks like a site (for example "example.com")
// carries no encoded login.
func FromName(name string) string {
	base := name[strings.LastIndex(name, "/")+1:]
	if i := strings.IndexByte(base, '@'); i >= 0 {
		return strings.TrimSpace(base[:i])
	}
	if strings.Contains(name, "/") {
		return strings.TrimSpace(base)
	}
	if strings.Contains(base, ".") {
		return ""
	}
	return strings.TrimSpace(base)
}

// Extract resolves the login for a password entry according to mode.
func Extract(name string, body []byte, mode Mode) string {
	switch mode {
	case ModeBody:
		return FromBody(body)
	case ModeFilename:
		return FromName(name)
	default:
		if u := FromBody(body); u != "" {
			return u
		}
		return FromName(name)
	}
}
