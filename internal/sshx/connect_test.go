package sshx

import "testing"

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
