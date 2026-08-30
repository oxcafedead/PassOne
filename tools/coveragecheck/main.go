// Command coveragecheck verifies that the total statement coverage reported in
// a Go coverage profile meets a minimum threshold. It is used as a quality gate
// in CI after the test suite has produced a merged coverage.out file.
//
// The authoritative percentage is taken from `go tool cover -func <profile>`,
// which correctly interprets Go's merged (multi-package) profile format. The
// tool exits non-zero when coverage falls below the configured threshold, so a
// regression in test coverage fails CI.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// totalLine matches the summary line emitted by `go tool cover -func`, e.g.:
//
//	total:							(statements)			81.3%
var totalLine = regexp.MustCompile(`^total:.*\(statements\).*?([0-9]+\.[0-9]+|100)%\s*$`)

func main() {
	profile := flag.String("profile", "coverage.out", "path to the Go coverage text profile")
	threshold := flag.Float64("threshold", 70.0, "minimum acceptable coverage percentage")
	flag.Parse()

	actual, err := totalCoverage(*profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coveragecheck: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("coveragecheck: coverage=%.2f%% (threshold=%.2f%%)\n", actual, *threshold)

	if actual < *threshold {
		fmt.Fprintf(os.Stderr,
			"coveragecheck: FAIL coverage %.2f%% is below the minimum of %.2f%%\n",
			actual, *threshold)
		os.Exit(1)
	}
}

// totalCoverage returns the overall statement coverage percentage reported by
// `go tool cover -func` for the given profile.
func totalCoverage(profile string) (float64, error) {
	cmd := exec.Command("go", "tool", "cover", "-func="+profile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("go tool cover -func: %v: %s", err, strings.TrimSpace(string(out)))
	}

	for _, line := range strings.Split(string(out), "\n") {
		m := totalLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m != nil {
			v, err := strconv.ParseFloat(m[1], 64)
			if err != nil {
				return 0, fmt.Errorf("parsing total coverage %q: %w", m[1], err)
			}
			return v, nil
		}
	}
	return 0, fmt.Errorf("no total line found in go tool cover output")
}
