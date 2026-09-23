package username

import "testing"

func TestParseMode(t *testing.T) {
	cases := []struct {
		in      string
		want    Mode
		wantErr bool
	}{
		{"", ModeAuto, false},
		{"auto", ModeAuto, false},
		{"AUTO", ModeAuto, false},
		{" body ", ModeBody, false},
		{"Body", ModeBody, false},
		{"filename", ModeFilename, false},
		{"FileName", ModeFilename, false},
		{"path", ModeAuto, true},
		{"", ModeAuto, false},
	}
	for _, tc := range cases {
		got, err := ParseMode(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseMode(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParseMode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestModeString(t *testing.T) {
	cases := map[Mode]string{
		ModeAuto:     "auto",
		ModeBody:     "body",
		ModeFilename: "filename",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", m, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"":         "auto",
		"auto":     "auto",
		"Body":     "body",
		"filename": "filename",
		"bogus":    "auto",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValid(t *testing.T) {
	if !Valid("auto") || !Valid("body") || !Valid("filename") || !Valid("") {
		t.Fatal("expected known modes to be valid")
	}
	if Valid("nope") {
		t.Fatal("expected unknown mode to be invalid")
	}
}

func TestFromBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"user field", "secret123\nuser: alice\nurl: https://x.com\n", "alice"},
		{"username field", "secret123\nusername: bob\n", "bob"},
		{"login field", "secret123\nlogin: carol\n", "carol"},
		{"login name field", "secret123\nlogin name: dan\n", "dan"},
		{"user name field", "secret123\nuser name: eve\n", "eve"},
		{"mixed case label", "secret123\nUSER: frank\n", "frank"},
		{"multiple spaces in label", "secret123\nlogin   name: gina\n", "gina"},
		{"value with colon", "secret123\nusername: user:name\n", "user:name"},
		{"whitespace around value", "secret123\n  username:   hank   \n", "hank"},
		{"field before other lines", "secret123\nurl: https://x.com\nusername: ivy\n", "ivy"},
		{"no login field", "secret123\nurl: https://x.com\n", ""},
		{"password looks like a field", "p@ss:word\nurl: https://x.com\n", ""},
		{"empty body", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FromBody([]byte(tc.body)); got != tc.want {
				t.Errorf("FromBody(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

func TestFromName(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"alice@example.com", "alice"},
		{"work/alice@example.com", "alice"},
		{"example.com/alice", "alice"},
		{"example.com", ""},
		{"work/example.com", "example.com"},
		{"alice", "alice"},
	}
	for _, tc := range cases {
		if got := FromName(tc.name); got != tc.want {
			t.Errorf("FromName(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestExtract(t *testing.T) {
	body := []byte("secret\nusername: alice\n")

	if got := Extract("sites/example.com/alice", body, ModeBody); got != "alice" {
		t.Errorf("ModeBody = %q, want alice", got)
	}
	if got := Extract("sites/example.com", body, ModeFilename); got != "example.com" {
		t.Errorf("ModeFilename = %q, want example.com", got)
	}
	// Auto prefers the body field.
	if got := Extract("alice@example.com", body, ModeAuto); got != "alice" {
		t.Errorf("ModeAuto with body = %q, want alice", got)
	}
	// Auto falls back to the file name when the body has no field.
	if got := Extract("sites/example.com/bob", []byte("secret\nurl: x\n"), ModeAuto); got != "bob" {
		t.Errorf("ModeAuto fallback = %q, want bob", got)
	}
}
