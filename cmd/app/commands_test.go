package main

import "testing"

func TestHostportOf(t *testing.T) {
	cases := map[string]string{
		"github.com":       "github.com:22",
		"github.com:22":    "github.com:22",
		"git.example:2222": "git.example:2222",
	}
	for in, want := range cases {
		if got := hostportOf(in); got != want {
			t.Errorf("hostportOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGitHost(t *testing.T) {
	cases := map[string]string{
		"git@github.com:oxcafedead/pass.git":       "github.com",
		"ssh://git@github.com/oxcafedead/pass.git": "github.com",
		"https://github.com/oxcafedead/pass.git":   "https://github.com/oxcafedead/pass.git", // unsupported form, returned verbatim
	}
	for in, want := range cases {
		if got := gitHost(in); got != want {
			t.Errorf("gitHost(%q) = %q, want %q", in, got, want)
		}
	}
}
