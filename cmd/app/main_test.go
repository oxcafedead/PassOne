package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/oxcafedead/passone/internal/version"
)

// main() is the CLI's whole contract with whatever invoked it: three spellings
// of the version, a usage dump, an unknown-command exit and a per-command error
// exit. None of it runs in-process — main writes to the real stdout and calls
// os.Exit — so it is driven through a re-invoked copy of this test binary.

const (
	cliHelperEnv = "PASSONE_TEST_CLI"
	cliArgvEnv   = "PASSONE_TEST_CLI_ARGV"
	cliArgSep    = "\x1f"

	cliExitOK      = 0
	cliExitFailure = 1
	cliExitUsage   = 2
)

// TestHelperCLI is not a real test: as a subprocess it runs main() with the
// argv supplied in cliArgvEnv. The two variables are separate because "no
// command at all" is itself a case under test, and an empty argv has to be
// distinguishable from "this process is not the helper".
func TestHelperCLI(t *testing.T) {
	if os.Getenv(cliHelperEnv) == "" {
		return
	}
	os.Args = []string{"passone"}
	if argv := os.Getenv(cliArgvEnv); argv != "" {
		os.Args = append(os.Args, strings.Split(argv, cliArgSep)...)
	}
	main()
}

func TestCLIDispatch(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		wantCode int
		wantOut  []string
	}{
		{
			name:     "no arguments prints usage and succeeds",
			argv:     nil,
			wantCode: cliExitOK,
			wantOut:  []string{"Usage: passone <command> [arguments]"},
		},
		{
			name:     "help prints usage and succeeds",
			argv:     []string{"help"},
			wantCode: cliExitOK,
			wantOut:  []string{"Usage: passone <command> [arguments]"},
		},
		{
			name:     "version command",
			argv:     []string{"version"},
			wantCode: cliExitOK,
			wantOut:  []string{"PassOne " + version.Version},
		},
		{
			name:     "--version is answered before the app is even created",
			argv:     []string{"--version"},
			wantCode: cliExitOK,
			wantOut:  []string{"PassOne " + version.Version},
		},
		{
			name:     "-version",
			argv:     []string{"-version"},
			wantCode: cliExitOK,
			wantOut:  []string{"PassOne " + version.Version},
		},
		{
			name:     "-v",
			argv:     []string{"-v"},
			wantCode: cliExitOK,
			wantOut:  []string{"PassOne " + version.Version},
		},
		{
			name:     "an unknown command is a usage error, not a silent success",
			argv:     []string{"frobnicate"},
			wantCode: cliExitUsage,
			wantOut:  []string{"unknown command: frobnicate", "Usage: passone <command>"},
		},
		{
			name:     "a command that fails exits 1 with the reason",
			argv:     []string{"save"},
			wantCode: cliExitFailure,
			wantOut:  []string{"error: save requires <path> <file>"},
		},
		{
			name:     "a second failing command is reported the same way",
			argv:     []string{"edit"},
			wantCode: cliExitFailure,
			wantOut:  []string{"error: edit requires a password path"},
		},
		{
			name:     "init reports the data directory it was pointed at",
			argv:     []string{"init"},
			wantCode: cliExitOK,
			wantOut:  []string{"Application data directory:"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// main() calls createApp, which reads PASSONE_DIR. Without this the
			// subprocess would touch the real application data directory.
			dir := t.TempDir()
			code, output := runCLI(t, dir, tc.argv)
			if code != tc.wantCode {
				t.Errorf("exit code %d, want %d (output: %s)", code, tc.wantCode, output)
			}
			for _, want := range tc.wantOut {
				if !strings.Contains(output, want) {
					t.Errorf("output does not mention %q:\n%s", want, output)
				}
			}
		})
	}
}

// TestCLIVersionNeedsNoDataDir: the version flags are answered before the app is
// constructed, so `passone --version` works even where the application data
// directory is unusable. PASSONE_DIR points at a path that cannot be created.
func TestCLIVersionNeedsNoDataDir(t *testing.T) {
	unusable := t.TempDir() + string(os.PathSeparator) + "file-in-the-way"
	if err := os.WriteFile(unusable, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("blocking the data dir: %v", err)
	}
	code, output := runCLI(t, unusable, []string{"--version"})
	if code != cliExitOK {
		t.Errorf("exit code %d, want %d (output: %s)", code, cliExitOK, output)
	}
	if !strings.Contains(output, "PassOne ") {
		t.Errorf("output does not name the version: %s", output)
	}
}

// runCLI re-invokes this test binary as the passone CLI and returns its exit
// code together with everything it printed.
func runCLI(t *testing.T, dataDir string, argv []string) (int, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=TestHelperCLI")
	cmd.Env = append(os.Environ(),
		cliHelperEnv+"=1",
		cliArgvEnv+"="+strings.Join(argv, cliArgSep),
		"PASSONE_DIR="+dataDir,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return cliExitOK, string(out)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("running the passone helper: %v (%s)", err, out)
	}
	code := exit.ExitCode()
	if code == -1 {
		t.Fatalf("helper did not exit normally: %v (%s)", err, out)
	}
	return code, string(out)
}
