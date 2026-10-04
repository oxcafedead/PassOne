package main

import (
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This tool decides whether CI passes, and it is the one gate whose own failure
// mode is silence: a profile it cannot read exits 2, and a total it cannot find
// exits 2, and neither is a test failure anywhere else. So the exit codes, the
// threshold comparison and the parsing of `go tool cover` output are pinned here.

const (
	ccHelperEnv = "PASSONE_TEST_COVERAGECHECK_ARGV"
	ccArgSep    = "\x1f"

	ccExitPass   = 0
	ccExitUnder  = 1
	ccExitBroken = 2
)

// blockFile names a file that exists in this package. `go tool cover -func`
// resolves each profile path through `go list` and then reads the file to
// attribute a block to a function, so a synthetic path would not do.
const blockFile = "github.com/oxcafedead/passone/tools/coveragecheck/main.go"

// funcSpan returns the first and last line of the named function in main.go.
// Deriving the synthetic block ranges from the source rather than hard-coding
// line numbers keeps these tests working when main.go is edited.
func funcSpan(t *testing.T, name string) (int, int) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		return fset.Position(fn.Pos()).Line, fset.Position(fn.End()).Line
	}
	t.Fatalf("no function %q in main.go", name)
	return 0, 0
}

// blocksIn splits fn's line span into n non-overlapping ranges, marking the
// first covered of them as executed. Each range counts as one statement, so a
// profile of covered/n is exactly covered/n*100 percent.
func blocksIn(t *testing.T, fn string, n, covered int) []string {
	t.Helper()
	first, last := funcSpan(t, fn)
	step := (last - first + 1) / n
	if step < 1 {
		t.Fatalf("%s spans lines %d-%d, too few for %d blocks", fn, first, last, n)
	}
	blocks := make([]string, 0, n)
	for i := range n {
		start := first + i*step
		end := start + step - 1
		if i == n-1 {
			end = last
		}
		count := 0
		if i < covered {
			count = 1
		}
		blocks = append(blocks, fmt.Sprintf("%s:%d.1,%d.1 1 %d", blockFile, start, end, count))
	}
	return blocks
}

// writeProfile writes a Go coverage profile and returns its path.
func writeProfile(t *testing.T, blocks ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "coverage.out")
	body := "mode: set\n" + strings.Join(blocks, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing profile: %v", err)
	}
	return path
}

func TestTotalCoverage(t *testing.T) {
	tests := []struct {
		name       string
		n, covered int
		want       float64
	}{
		{name: "nothing covered", n: 4, covered: 0, want: 0},
		{name: "one in four", n: 4, covered: 1, want: 25},
		{name: "half", n: 4, covered: 2, want: 50},
		{name: "three in four", n: 4, covered: 3, want: 75},
		{name: "everything covered reports a full 100%", n: 4, covered: 4, want: 100},
		{name: "a single statement", n: 1, covered: 1, want: 100},
		{name: "an odd split still reports exactly", n: 3, covered: 1, want: 100.0 / 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := totalCoverage(writeProfile(t, blocksIn(t, "totalCoverage", tc.n, tc.covered)...))
			if err != nil {
				t.Fatalf("totalCoverage: %v", err)
			}
			// go tool cover prints one decimal, so compare at that precision.
			if want := round1(tc.want); got != want {
				t.Errorf("totalCoverage = %v, want %v", got, want)
			}
		})
	}
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}

// TestTotalCoverageRejectsUnusableProfiles: a profile the tool cannot read must
// be an error. Reporting 0% would fail the build for the wrong reason, and
// reporting nothing at all would pass it.
func TestTotalCoverageRejectsUnusableProfiles(t *testing.T) {
	tests := []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{
			name: "missing file",
			path: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.out") },
			want: "go tool cover -func",
		},
		{
			name: "not a profile at all",
			path: func(t *testing.T) string { return writeProfile(t, "this is not a coverage profile") },
			want: "go tool cover -func",
		},
		{
			name: "profile with no blocks at all",
			path: func(t *testing.T) string { return writeProfile(t) },
			want: "go tool cover -func",
		},
		{
			name: "blocks in no package go list knows",
			path: func(t *testing.T) string { return writeProfile(t, "nowhere/nothing.go:1.1,2.2 1 1") },
			want: "go tool cover -func",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := totalCoverage(tc.path(t))
			if err == nil {
				t.Fatalf("totalCoverage = %v, want an error", got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %q, want it to mention %q", err, tc.want)
			}
			// The message has to carry the underlying reason: a bare
			// "go tool cover -func" is all CI would ever print.
			if len(err.Error()) <= len("go tool cover -func") {
				t.Errorf("error %q carries no detail from go tool cover", err)
			}
		})
	}
}

// TestTotalLineMatchesRealOutput pins the summary regex against lines in the
// shape `go tool cover -func` actually emits, including the CRLF endings it
// produces on Windows. A per-function line and a total line differ only by that
// prefix, so a loose pattern would silently start reading the wrong number.
func TestTotalLineMatchesRealOutput(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		match bool
	}{
		{
			name:  "total line with a fractional percentage",
			line:  "total:\t(statements)\t77.4%",
			match: true,
		},
		{
			name:  "total line with no fractional part",
			line:  "total:\t(statements)\t100%",
			match: true,
		},
		{
			name:  "total line with a trailing carriage return",
			line:  "total:\t(statements)\t81.3%\r",
			match: true,
		},
		{
			name:  "a per-function line is not a total",
			line:  "github.com/x/y.go:12.34,13.56\t2\t100.0%",
			match: false,
		},
		{
			name:  "a function whose name contains total: is not a total",
			line:  "github.com/x/y.go:1.1,2.2\t1\ttotal:\t(statements)\t9.9%",
			match: false,
		},
		{
			name:  "a total line with no percentage",
			line:  "total:\t(statements)",
			match: false,
		},
		{
			name:  "an empty line",
			line:  "",
			match: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// totalCoverage trims the carriage return before matching, so the
			// table goes through the same trim.
			if got := totalLine.MatchString(strings.TrimRight(tc.line, "\r")); got != tc.match {
				t.Errorf("MatchString(%q) = %v, want %v", tc.line, got, tc.match)
			}
		})
	}
}

// TestHelperCoveragecheck is not a real test: as a subprocess it runs main()
// with the argv supplied in ccHelperEnv, so the gate's own exit codes are
// observable. main parses flags and calls os.Exit, so flag.CommandLine is reset
// first — the test binary's own flags would otherwise be parsed a second time.
func TestHelperCoveragecheck(t *testing.T) {
	argv := os.Getenv(ccHelperEnv)
	if argv == "" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("coveragecheck", flag.ContinueOnError)
	os.Args = append([]string{"coveragecheck"}, strings.Split(argv, ccArgSep)...)
	main()
}

// TestCoveragecheckExitCodes is the gate's contract with CI: 0 when the total
// clears the threshold, 1 when it does not, and 2 when the profile is
// unreadable. 1 and 2 both fail the step, but only 2 means "the gate itself
// could not decide".
func TestCoveragecheckExitCodes(t *testing.T) {
	half := writeProfile(t, blocksIn(t, "totalCoverage", 4, 2)...)
	all := writeProfile(t, blocksIn(t, "totalCoverage", 4, 4)...)
	none := writeProfile(t, blocksIn(t, "totalCoverage", 4, 0)...)
	broken := filepath.Join(t.TempDir(), "absent.out")

	tests := []struct {
		name     string
		argv     []string
		wantCode int
		wantOut  string
	}{
		{
			name:     "above the threshold passes",
			argv:     []string{"-profile=" + half, "-threshold=40"},
			wantCode: ccExitPass,
			wantOut:  "coverage=50.00% (threshold=40.00%)",
		},
		{
			name:     "exactly at the threshold passes",
			argv:     []string{"-profile=" + half, "-threshold=50"},
			wantCode: ccExitPass,
			wantOut:  "coverage=50.00%",
		},
		{
			name:     "below the threshold fails",
			argv:     []string{"-profile=" + half, "-threshold=50.1"},
			wantCode: ccExitUnder,
			wantOut:  "is below the minimum of 50.10%",
		},
		{
			name:     "full coverage passes any threshold",
			argv:     []string{"-profile=" + all, "-threshold=99"},
			wantCode: ccExitPass,
			wantOut:  "coverage=100.00%",
		},
		{
			name:     "zero coverage fails the default threshold",
			argv:     []string{"-profile=" + none},
			wantCode: ccExitUnder,
			wantOut:  "coverage=0.00% (threshold=70.00%)",
		},
		{
			name:     "an unreadable profile is a broken gate, not a low score",
			argv:     []string{"-profile=" + broken},
			wantCode: ccExitBroken,
			wantOut:  "go tool cover -func",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, output := runCoveragecheck(t, tc.argv)
			if code != tc.wantCode {
				t.Errorf("exit code %d, want %d (output: %s)", code, tc.wantCode, output)
			}
			if !strings.Contains(output, tc.wantOut) {
				t.Errorf("output %q does not mention %q", output, tc.wantOut)
			}
		})
	}
}

// TestCoveragecheckDefaults pins the defaults, because CI passes only -profile
// and relies on the threshold baked in here being 70.
func TestCoveragecheckDefaults(t *testing.T) {
	code, output := runCoveragecheck(t, []string{"-h"})
	if code == ccExitPass {
		t.Errorf("-h should not exit 0; output: %s", output)
	}
	for _, want := range []string{"-profile", "coverage.out", "-threshold", "70"} {
		if !strings.Contains(output, want) {
			t.Errorf("usage does not mention %q: %s", want, output)
		}
	}
}

// runCoveragecheck re-invokes this test binary as the coveragecheck CLI and
// returns its exit code together with everything it printed.
func runCoveragecheck(t *testing.T, argv []string) (int, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=TestHelperCoveragecheck")
	cmd.Env = append(os.Environ(), ccHelperEnv+"="+strings.Join(argv, ccArgSep))
	out, err := cmd.CombinedOutput()
	if err == nil {
		return ccExitPass, string(out)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("running the coveragecheck helper: %v (%s)", err, out)
	}
	code := exit.ExitCode()
	if code == -1 {
		t.Fatalf("helper did not exit normally: %v (%s)", err, out)
	}
	return code, string(out)
}
