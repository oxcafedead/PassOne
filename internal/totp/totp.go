// Package totp extracts otpauth:// URIs from pass entry bodies and generates
// time-based one-time passwords following RFC 6238.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrNoOTP is returned when the entry body does not contain an otpauth:// URI.
var ErrNoOTP = errors.New("no otpauth:// URI found in the entry")

// uriParams holds the parsed parameters from an otpauth:// URI.
type uriParams struct {
	secret    string
	digits    int
	period    int
	algorithm string
}

// ExtractURI scans body lines for the first otpauth:// URI (pass-otp convention)
// and returns it. The body is the full plaintext of a password entry.
func ExtractURI(body []byte) (string, error) {
	text := string(body)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "otpauth://") {
			return line, nil
		}
	}
	return "", ErrNoOTP
}

// GenerateCode generates the current TOTP code for the given otpauth:// URI.
func GenerateCode(uri string) (string, error) {
	p, err := parseURI(uri)
	if err != nil {
		return "", err
	}
	return generateCode(p, time.Now())
}

func parseURI(uri string) (*uriParams, error) {
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		return nil, fmt.Errorf("unsupported otpauth URI: %s", uri)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid otpauth URI: %v", err)
	}
	q := parsed.Query()
	secret := q.Get("secret")
	if secret == "" {
		return nil, errors.New("otpauth URI missing secret parameter")
	}
	p := &uriParams{
		secret:    strings.ToUpper(secret),
		digits:    6,
		period:    30,
		algorithm: "SHA1",
	}
	if v := q.Get("digits"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && (d == 6 || d == 8) {
			p.digits = d
		}
	}
	if v := q.Get("period"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			p.period = d
		}
	}
	if v := q.Get("algorithm"); v != "" {
		p.algorithm = strings.ToUpper(v)
	}
	return p, nil
}

func generateCode(p *uriParams, t time.Time) (string, error) {
	if p.algorithm != "SHA1" {
		return "", fmt.Errorf("unsupported TOTP algorithm: %s (only SHA1 is supported)", p.algorithm)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(p.secret)
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret: %v", err)
	}
	counter := uint64(math.Floor(float64(t.Unix()) / float64(p.period)))
	mac := hmac.New(sha1.New, secret)
	_ = binary.Write(mac, binary.BigEndian, counter)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(math.Pow10(p.digits))
	code %= mod
	return fmt.Sprintf("%0*d", p.digits, code), nil
}
