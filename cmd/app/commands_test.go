package main

import (
	"os"
	"strings"
	"testing"

	"github.com/oxcafedead/passone/internal/app"
	"github.com/oxcafedead/passone/internal/version"
)

func TestPositionalKeepsStdinDash(t *testing.T) {
	got := positional([]string{"test_passone", "-", "--full"})
	want := []string{"test_passone", "-"}
	if len(got) != len(want) {
		t.Fatalf("positional() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("positional() = %v, want %v", got, want)
		}
	}
}

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

func TestHasFlag(t *testing.T) {
	if !hasFlag([]string{"--full", "path"}, "full") {
		t.Fatal("expected --full to match")
	}
	if !hasFlag([]string{"-full", "path"}, "full") {
		t.Fatal("expected -full to match")
	}
	if !hasFlag([]string{"FULL", "path"}, "full") {
		t.Fatal("expected case-insensitive match")
	}
	if hasFlag([]string{"path"}, "full") {
		t.Fatal("expected no match")
	}
}

func TestOrNone(t *testing.T) {
	if got := orNone(""); got != "(none)" {
		t.Fatalf("orNone(\"\") = %q", got)
	}
	if got := orNone("x"); got != "x" {
		t.Fatalf("orNone(\"x\") = %q", got)
	}
}

func TestZero(t *testing.T) {
	b := []byte("secret")
	zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
	}
}

func TestReadAllStdin(t *testing.T) {
	in := "hello from stdin"
	f := testFile(t, in)
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("close stdin temp file: %v", err)
		}
	}()
	e := &env{stdin: f, stdout: os.Stdout, stderr: os.Stderr}
	got, err := readAllStdin(e)
	if err != nil {
		t.Fatalf("readAllStdin: %v", err)
	}
	if string(got) != in {
		t.Fatalf("readAllStdin = %q", got)
	}
}

func testFile(t *testing.T, content string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCmdVersion(t *testing.T) {
	e := newTestEnv(t)
	cmd := commands()["version"]
	if cmd == nil {
		t.Fatal("version command not registered")
	}
	if err := cmd(e, nil); err != nil {
		t.Fatalf("version command: %v", err)
	}
	out := readOut(t, e.stdout)
	if !strings.Contains(out, "PassOne") || !strings.Contains(out, version.Version) {
		t.Fatalf("version output = %q", out)
	}
}

func TestCmdInit(t *testing.T) {
	t.Setenv("PASSONE_DIR", t.TempDir())
	a, err := app.New()
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	out, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{app: a, stdout: out, stderr: os.Stderr, stdin: os.Stdin}
	if err := cmdInit(e, nil); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Application data directory") {
		t.Fatalf("output = %q", string(data))
	}
}
