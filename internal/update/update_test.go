package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNewer pins the version comparison, which is the one piece of this
// package a wrong answer is invisible in production: no toast at all looks
// exactly like "you are up to date".
func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
		why             string
	}{
		{"v0.2.0", "v0.1.1", true, "a newer patch is newer"},
		{"v0.1.1", "v0.1.1", false, "the release in use is not an update"},
		{"v0.1.0", "v0.1.1", false, "an older patch is not an update"},
		{"v1.0.0", "v0.9.9", true, "the major component dominates"},
		{"v0.2.0", "v0.2.0-rc.1", true, "a stable release outranks its own pre-release"},
		{"v0.2.0-rc.1", "v0.2.0", false, "a stable build is not behind its own pre-release"},
		{"v0.2.0-rc.2", "v0.2.0-rc.1", true, "pre-release identifiers order numerically"},
		{"v0.2.0-rc.10", "v0.2.0-rc.9", true, "rc.10 is above rc.9, not below it"},
		{"v0.2.0-rc.1.1", "v0.2.0-rc.1", true, "a longer run of equal identifiers is the higher version"},
		{"v0.2.0-alpha.beta", "v0.2.0-alpha.1", true, "an alphanumeric identifier outranks a numeric one"},
		{"v0.2.0-alpha.1", "v0.2.0-alpha.beta", false, "and the other way round is not an update"},
		{"v0.2.0-rc.1", "v0.2.0-rc.1", false, "the same pre-release is not an update"},
		{"v0.2.0-beta", "v0.2.0-alpha", true, "alphanumeric identifiers order as text"},
		{"v0.2.0", "v0.2.0+build9", false, "build metadata takes no part in precedence"},
		{"v1.10.0", "v1.9.0", true, "minor versions compare as numbers, not as text"},
		{"v0.2", "v0.1.9", true, "a missing patch component counts as zero"},
		{"v2", "v1.9.9", true, "a missing minor component counts as zero"},
		{"2.0.0", "1.9.9", true, "the leading v is optional on either side"},
		{"dev", "v0.1.1", false, "a development build is not behind a release"},
		{"v0.2.0", "dev", false, "a development build has no release to be behind"},
		{"", "v0.1.1", false, "an empty tag is never an update"},
		{"not-a-version", "v0.1.1", false, "an unparseable tag is never an update"},
		{"v0.1.1.1", "v0.1.1", false, "a four-component tag is rejected, not guessed at"},
		{"v0.01.1", "v0.1.0", false, "a leading zero is rejected, not read as a number"},
		{"v0.2.0-rc.01", "v0.1.0", false, "a leading zero in a pre-release identifier is rejected, not read as rc.1"},
		{"v0.2.0-rc.100000000000000000000", "v0.2.0-rc.99", true, "a pre-release number longer than an int64 still compares as a number"},
		{"v0.2.0-rc.3", "v0.2.0-rc.99999999999999999999", false, "and does not flip to a text comparison that overflows"},
		{"v0.2.0-0.0", "v0.2.0-0", true, "a bare zero is a valid numeric identifier, and 0.0 outranks 0"},
	}
	for _, tc := range cases {
		if got := Newer(tc.latest, tc.current); got != tc.want {
			t.Errorf("Newer(%q, %q) = %v, want %v (%s)", tc.latest, tc.current, got, tc.want, tc.why)
		}
	}
}

// TestIsRelease separates the version a release build stamps from the "dev"
// sentinel a local one carries. It is what decides whether a check is made at
// all, so "dev" must not be one of these.
func TestIsRelease(t *testing.T) {
	cases := map[string]bool{
		"dev":               false,
		"":                  false,
		"   ":               false,
		"v1.2.3":            true,
		"1.2.3":             true,
		"v1.2.3-rc.1":       true,
		"v1.2":              true,
		"v1":                true,
		" v1.2.3 ":          true,
		"v1.2.3.4":          false,
		"vx.y.z":            false,
		"v1.2.x":            false,
		"v1.2.-3":           false,
		"v1.2.3-":           false,
		"v1.2.3-rc.01":      false,
		"v1.2.3-rc.0":       true,
		"release-candidate": false,
	}
	for v, want := range cases {
		if got := IsRelease(v); got != want {
			t.Errorf("IsRelease(%q) = %v, want %v", v, got, want)
		}
	}
}

// serveLatest points the package at a local server for the duration of a test
// and returns the requests it saw.
func serveLatest(t *testing.T, handler http.HandlerFunc) *[]*http.Request {
	t.Helper()
	var seen []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	oldURL, oldClient := latestURL, httpClient
	latestURL = srv.URL
	t.Cleanup(func() {
		latestURL, httpClient = oldURL, oldClient
	})
	return &seen
}

func TestLatestReadsTheNewestRelease(t *testing.T) {
	serveLatest(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"tag_name": "v0.2.0",
			"html_url": "https://github.com/oxcafedead/passone/releases/tag/v0.2.0",
			"draft": false,
			"prerelease": false,
			"name": "PassOne v0.2.0"
		}`))
	})

	got, err := Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got.Tag != "v0.2.0" {
		t.Errorf("Tag = %q, want v0.2.0", got.Tag)
	}
	if got.URL != "https://github.com/oxcafedead/passone/releases/tag/v0.2.0" {
		t.Errorf("URL = %q", got.URL)
	}
}

// TestLatestIdentifiesItself pins the headers GitHub needs: a request with no
// User-Agent is rejected outright, so a check that dropped this would fail on
// every machine rather than only under a proxy.
func TestLatestIdentifiesItself(t *testing.T) {
	seen := serveLatest(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.2.0"}`))
	})

	if _, err := Latest(context.Background()); err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if len(*seen) != 1 {
		t.Fatalf("made %d requests, want 1", len(*seen))
	}
	req := (*seen)[0]
	if ua := req.Header.Get("User-Agent"); !strings.HasPrefix(ua, "passone/") {
		t.Errorf("User-Agent = %q, want it to start with passone/", ua)
	}
	if accept := req.Header.Get("Accept"); accept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", accept)
	}
}

// TestLatestRefusesDraftsAndPreReleases is the guarantee this package exists to
// back: the pipeline tags pre-releases, and a v1.3.0-rc.1 must never be offered
// to someone on v1.2.0 as if it were the stable build.
func TestLatestRefusesDraftsAndPreReleases(t *testing.T) {
	for name, body := range map[string]string{
		"draft":      `{"tag_name":"v0.2.0","draft":true}`,
		"prerelease": `{"tag_name":"v0.2.0-rc.1","prerelease":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			serveLatest(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			})
			if _, err := Latest(context.Background()); err == nil {
				t.Fatal("Latest accepted a " + name)
			}
		})
	}
}

func TestLatestRejectsUnusableAnswers(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"rate limited":   {status: http.StatusForbidden, body: `{"tag_name":"v9.9.9"}`},
		"server error":   {status: http.StatusInternalServerError, body: `{"tag_name":"v9.9.9"}`},
		"not json":       {status: http.StatusOK, body: `<html>nope</html>`},
		"no tag":         {status: http.StatusOK, body: `{"html_url":"https://example.com"}`},
		"blank tag":      {status: http.StatusOK, body: `{"tag_name":"   "}`},
		"empty response": {status: http.StatusOK, body: ``},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			serveLatest(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			if _, err := Latest(context.Background()); err == nil {
				t.Fatal("Latest accepted an answer it cannot use")
			}
		})
	}
}

// TestLatestBoundsTheResponse keeps a bad answer from becoming a large
// allocation: a reply well past the size of a release payload is refused rather
// than read to the end.
func TestLatestBoundsTheResponse(t *testing.T) {
	serveLatest(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.2.0","body":"` + strings.Repeat("x", 2*maxResponse) + `"}`))
	})

	if _, err := Latest(context.Background()); err == nil {
		t.Fatal("Latest accepted an oversized response")
	}
}

// TestLatestHonoursACancelledContext proves the check gives up when the caller
// does, rather than leaving a request running past the window that started it.
func TestLatestHonoursACancelledContext(t *testing.T) {
	serveLatest(t, func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Latest(ctx); err == nil {
		t.Fatal("Latest ignored a cancelled context")
	}
}

// TestLatestFailsOnAnUnusableEndpoint covers the failure before a connection is
// ever made. The endpoint is a constant, so this is not reachable in
// production -- which is exactly why it is worth having: it pins that the error
// path exists rather than panicking on a nil response.
func TestLatestFailsOnAnUnusableEndpoint(t *testing.T) {
	old := latestURL
	latestURL = "://not-a-url"
	t.Cleanup(func() { latestURL = old })

	if _, err := Latest(context.Background()); err == nil {
		t.Fatal("Latest accepted an endpoint it cannot build a request for")
	}
}

// TestLatestURLIsTheOneRepository pins the endpoint, which is a constant on
// purpose: nothing a caller passes can redirect the check at another host.
func TestLatestURLIsTheOneRepository(t *testing.T) {
	if latestURL != defaultLatestURL {
		t.Fatalf("latestURL = %q, want %q", latestURL, defaultLatestURL)
	}
	if !strings.HasPrefix(defaultLatestURL, "https://api.github.com/repos/oxcafedead/passone/") {
		t.Fatalf("defaultLatestURL = %q", defaultLatestURL)
	}
}
