package totp

import (
	"testing"
	"time"
)

func TestExtractURI(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantURI string
		wantErr bool
	}{
		{
			name:    "otpauth on its own line",
			body:    "secret123\notpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			wantURI: "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
		},
		{
			name:    "otpauth with surrounding whitespace",
			body:    "secret123\n  otpauth://totp/Test?secret=ABC  \nnotes here",
			wantURI: "otpauth://totp/Test?secret=ABC",
		},
		{
			name:    "otpauth with url on line 2",
			body:    "mypassword\nhttps://example.com\notpauth://totp/MyApp?secret=JBSWY3DPEHPK3PXP",
			wantURI: "otpauth://totp/MyApp?secret=JBSWY3DPEHPK3PXP",
		},
		{
			name:    "no otpauth",
			body:    "secret123\nhttps://example.com\nsome notes",
			wantErr: true,
		},
		{
			name:    "empty body",
			body:    "",
			wantErr: true,
		},
		{
			name:    "otpauth is first line",
			body:    "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP",
			wantURI: "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri, err := ExtractURI([]byte(tt.body))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExtractURI() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && uri != tt.wantURI {
				t.Errorf("ExtractURI() = %q, want %q", uri, tt.wantURI)
			}
		})
	}
}

func TestGenerateCode(t *testing.T) {
	// Known test secret (base32 for "Hello!") with fixed time to get a deterministic code.
	uri := "otpauth://totp/Test:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test"
	// 2006-01-02T15:04:05Z = 1136171445
	// 1136171445 / 30 = 37872381
	// Generate the code at a fixed time and verify it's a 6-digit string.
	now := time.Unix(1136171445, 0)
	p, err := parseURI(uri)
	if err != nil {
		t.Fatalf("parseURI: %v", err)
	}
	code, err := generateCode(p, now)
	if err != nil {
		t.Fatalf("generateCode: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q (len=%d)", code, len(code))
	}
	// Run twice at the same time and verify the code is stable.
	code2, err := generateCode(p, now)
	if err != nil {
		t.Fatalf("generateCode (second call): %v", err)
	}
	if code != code2 {
		t.Errorf("same time should produce same code: %q != %q", code, code2)
	}
}

func TestGenerateCode8Digits(t *testing.T) {
	uri := "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=8"
	now := time.Unix(1136171445, 0)
	code, err := GenerateCode(uri)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if len(code) != 8 {
		t.Fatalf("expected 8-digit code, got %q (len=%d)", code, len(code))
	}
	_ = now
}

func TestGenerateCodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"empty uri", "", true},
		{"hotp scheme", "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP", true},
		{"missing secret", "otpauth://totp/Test?issuer=Foo", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateCode(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseURI(t *testing.T) {
	uri := "otpauth://totp/Big%20Corp:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Big+Corp&digits=8&period=60&algorithm=SHA1"
	p, err := parseURI(uri)
	if err != nil {
		t.Fatalf("parseURI: %v", err)
	}
	if p.secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("secret = %q, want JBSWY3DPEHPK3PXP", p.secret)
	}
	if p.digits != 8 {
		t.Errorf("digits = %d, want 8", p.digits)
	}
	if p.period != 60 {
		t.Errorf("period = %d, want 60", p.period)
	}
	if p.algorithm != "SHA1" {
		t.Errorf("algorithm = %q, want SHA1", p.algorithm)
	}
}

func TestParseUIDefaults(t *testing.T) {
	uri := "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"
	p, err := parseURI(uri)
	if err != nil {
		t.Fatalf("parseURI: %v", err)
	}
	if p.digits != 6 {
		t.Errorf("digits = %d, want 6", p.digits)
	}
	if p.period != 30 {
		t.Errorf("period = %d, want 30", p.period)
	}
	if p.algorithm != "SHA1" {
		t.Errorf("algorithm = %q, want SHA1", p.algorithm)
	}
}
