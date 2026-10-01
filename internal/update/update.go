// Package update asks GitHub whether a newer PassOne release has been
// published.
//
// It deliberately stops there. Nothing in this package downloads, verifies or
// installs anything: a password manager that fetches a replacement for itself
// over the network would be a much larger decision than one, and the part of it
// a user is actually missing is the notice that a newer release exists.
package update

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/oxcafedead/passone/internal/version"
)

const (
	// defaultLatestURL is GitHub's "latest published full release" endpoint for
	// this repository. It is a constant, not something assembled from input:
	// the check talks to this one repository and to nothing else, so there is no
	// value for a caller to redirect.
	defaultLatestURL = "https://api.github.com/repos/oxcafedead/passone/releases/latest"

	// requestTimeout bounds one check. It runs at startup without blocking
	// anything, so an unreachable or slow api.github.com has to end the wait
	// rather than leave a goroutine holding a connection for the life of the
	// process.
	requestTimeout = 10 * time.Second

	// maxResponse bounds how much of the reply is read. A release payload is a
	// few kilobytes; a reply that runs far past that is not the JSON decoded
	// below, and reading it in full would only turn a bad answer into a large
	// allocation.
	maxResponse = 1 << 20
)

var (
	// latestURL is indirected so a test can point the check at a local server
	// instead of api.github.com.
	latestURL = defaultLatestURL

	// httpClient carries the timeout, and is indirected for the same reason.
	httpClient = &http.Client{Timeout: requestTimeout}
)

// Release is a published PassOne release, as far as this app cares.
type Release struct {
	// Tag is the git tag it was cut from, e.g. "v0.2.0". It is the only part
	// Newer compares.
	Tag string
	// URL is the release page a user can read about it.
	URL string
}

// Latest returns the newest published PassOne release that is not a
// pre-release.
//
// GitHub's /releases/latest endpoint documents itself as "the latest published
// full release, excluding drafts and pre-releases", and the release pipeline
// opens a tag as a draft for a human to review before publishing it, so an
// unreviewed build is already invisible here. Both flags are still asserted
// after the payload is decoded anyway: this app promises not to offer a
// pre-release, and a promise that exists only in a remote service's
// documentation is not one this repository can test.
func Latest(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURL, nil)
	if err != nil {
		return nil, err
	}
	// GitHub rejects a request with no User-Agent outright and answers an
	// unfamiliar one with a 403, so the check has to identify itself. The
	// version goes in the agent string because it is the one thing about this
	// request a maintainer reading a rate-limit log would want to see.
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "passone/"+version.Version)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach GitHub: %w", err)
	}
	defer func() {
		// Drain what is left so the connection can go back to the pool, then
		// close it. Neither error is actionable and neither may mask the one
		// this function is about to return.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, fmt.Errorf("could not read GitHub's answer: %w", err)
	}

	// Only the four fields this app reads are declared. A GitHub release object
	// carries a great deal more — assets, authors, bodies — and decoding all of
	// it would be a way to break on an addition.
	var payload struct {
		TagName    string `json:"tag_name"`
		HTMLURL    string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("could not read GitHub's answer: %w", err)
	}
	if payload.Draft || payload.Prerelease {
		return nil, errors.New("GitHub's latest release is a draft or a pre-release, which PassOne does not offer")
	}
	tag := strings.TrimSpace(payload.TagName)
	if tag == "" {
		return nil, errors.New("GitHub's latest release carries no tag")
	}
	return &Release{Tag: tag, URL: payload.HTMLURL}, nil
}

// IsRelease reports whether v is a release version a published tag can be
// compared against. The "dev" sentinel a local build carries is not one, and
// neither is anything that is not a version at all.
func IsRelease(v string) bool {
	_, ok := parseVersion(v)
	return ok
}

// Newer reports whether latest is a strictly newer release version than
// current.
//
// Precedence follows SemVer, including the rule that a pre-release sorts below
// the release it leads to: a user running v0.2.0-rc.1 is still told when the
// stable v0.2.0 lands, which is the whole reason the pipeline is allowed to tag
// pre-releases at all. A version that does not parse is never newer, so a local
// "dev" build is not told to upgrade — there is no published version it is
// meaningfully behind.
func Newer(latest, current string) bool {
	lv, ok := parseVersion(latest)
	if !ok {
		return false
	}
	cv, ok := parseVersion(current)
	if !ok {
		return false
	}
	return lv.compare(cv) > 0
}

// parsed is a release version split into the two parts SemVer precedence
// compares: the numeric core and the pre-release identifiers after the hyphen.
type parsed struct {
	core []int
	pre  []string
}

// parseVersion reads MAJOR[.MINOR[.PATCH]][-PRE][+BUILD] with an optional
// leading "v", because that is how releases are tagged. Missing core components
// count as zero, so "v1" and "v1.0.0" are one version rather than two.
//
// Anything else — the "dev" sentinel, four components, a non-numeric field, a
// leading zero — is rejected rather than guessed at. A guess here is not a
// cosmetic problem: it either nags a user about a version that does not exist,
// or reads a real update as "no update available".
func parseVersion(s string) (parsed, bool) {
	raw := strings.TrimSpace(s)
	raw = strings.TrimPrefix(raw, "v")
	// Build metadata takes no part in precedence (SemVer §10), so it is dropped
	// before anything is compared rather than being parsed and then ignored.
	if i := strings.IndexByte(raw, '+'); i >= 0 {
		raw = raw[:i]
	}
	var p parsed
	if i := strings.IndexByte(raw, '-'); i >= 0 {
		p.pre = strings.Split(raw[i+1:], ".")
		raw = raw[:i]
	}
	fields := strings.Split(raw, ".")
	if len(fields) == 0 || len(fields) > 3 {
		return parsed{}, false
	}
	p.core = make([]int, 3)
	for i, f := range fields {
		if f == "" || (len(f) > 1 && f[0] == '0') {
			return parsed{}, false
		}
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 {
			return parsed{}, false
		}
		p.core[i] = n
	}
	for _, id := range p.pre {
		if id == "" {
			return parsed{}, false
		}
		// SemVer §9: a numeric identifier carries no leading zero, so "rc.01" is
		// not a version. Left accepted it would read as rc.1 and compare against a
		// build that was never tagged.
		if n, isNum := numeric(id); isNum && len(n) > 1 && n[0] == '0' {
			return parsed{}, false
		}
	}
	return p, true
}

// compare orders two parsed versions: the numeric core first, then the
// pre-release, which sorts below the release it leads to.
func (a parsed) compare(b parsed) int {
	for i := range a.core {
		if c := cmp.Compare(a.core[i], b.core[i]); c != 0 {
			return c
		}
	}
	return comparePre(a.pre, b.pre)
}

// comparePre orders two pre-release identifier lists per SemVer §11: no
// pre-release outranks any pre-release, identifiers are compared left to right —
// numerically when both are digits, as text otherwise, with a numeric
// identifier ranking below an alphanumeric one at the first difference — and a
// shorter run of otherwise equal identifiers is the lower version.
func comparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aNum := numeric(a[i])
		bn, bNum := numeric(b[i])
		switch {
		case aNum && bNum:
			if c := compareNumeric(an, bn); c != 0 {
				return c
			}
		case aNum:
			return -1
		case bNum:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return cmp.Compare(len(a), len(b))
}

// numeric reports whether an identifier is made entirely of digits and, if so,
// returns it unchanged.
//
// It is kept as a string rather than parsed, and that is not fussiness:
// strconv.Atoi overflows on a long run of digits, so parsing would report a
// numeric identifier as alphanumeric and quietly replace a numeric comparison
// with a text one. Under Atoi, "rc.100000000000000000000" sorted *below* "rc.99"
// because '1' precedes '9'.
//
// No empty-string case: every call site is an identifier from parsed.pre, which
// parseVersion has already refused when empty.
func numeric(id string) (string, bool) {
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return "", false
		}
	}
	return id, true
}

// compareNumeric orders two all-digit identifiers of any length. With leading
// zeros already rejected by parseVersion, more digits is the larger number, and
// equal lengths fall back to a byte comparison.
func compareNumeric(a, b string) int {
	if len(a) != len(b) {
		return cmp.Compare(len(a), len(b))
	}
	return strings.Compare(a, b)
}
