package ui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/oxcafedead/passone/internal/update"
	"github.com/oxcafedead/passone/internal/version"
)

// stubRunningAs builds that look like a real release install, since the "dev"
// sentinel a local build carries is the one version that is never checked.
func stubRunningAs(t *testing.T, current string) {
	t.Helper()
	old := version.Version
	version.Version = current
	t.Cleanup(func() { version.Version = old })
}

// stubLatest answers the check without reaching api.github.com, and records
// that it was asked.
func stubLatest(t *testing.T, release *update.Release, err error) *int {
	t.Helper()
	calls := 0
	old := checkLatest
	checkLatest = func(context.Context) (*update.Release, error) {
		calls++
		return release, err
	}
	t.Cleanup(func() { checkLatest = old })
	return &calls
}

// TestCheckForUpdatesSkipsDevelopmentBuilds is the reason a local build is not
// nagged: "dev" is not a version, so there is nothing to compare a published tag
// against, and a check that guessed would either invent an update or hide one.
func TestCheckForUpdatesSkipsDevelopmentBuilds(t *testing.T) {
	g := newTestGUI(t)
	stubRunningAs(t, "dev")
	calls := stubLatest(t, &update.Release{Tag: "v9.9.9"}, nil)

	info, err := g.CheckForUpdates()
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if *calls != 0 {
		t.Errorf("asked GitHub %d time(s) from a development build, want 0", *calls)
	}
	if info.Available {
		t.Error("Available = true for a development build")
	}
	if !strings.Contains(info.Message, "dev") {
		t.Errorf("Message = %q, want it to name the version it is on", info.Message)
	}
}

// TestCheckForUpdatesAnnouncesANewerRelease covers the whole point of the
// feature: the wording names both versions, so a user can tell which release to
// fetch without opening anything.
func TestCheckForUpdatesAnnouncesANewerRelease(t *testing.T) {
	g := newTestGUI(t)
	stubRunningAs(t, "v0.1.1")
	stubLatest(t, &update.Release{Tag: "v0.2.0"}, nil)

	info, err := g.CheckForUpdates()
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if !info.Available {
		t.Error("Available = false for a newer release")
	}
	for _, want := range []string{"v0.2.0", "v0.1.1"} {
		if !strings.Contains(info.Message, want) {
			t.Errorf("Message = %q, want it to mention %s", info.Message, want)
		}
	}
}

// TestCheckForUpdatesAnnouncesPreReleasesToo: the pipeline is allowed to tag
// v0.2.0-rc.2, and someone running rc.1 is behind it exactly as much as someone
// on v0.1.1 is behind v0.2.0. GitHub's endpoint does not hand back a
// pre-release, but the comparison has to be right if one ever arrives.
func TestCheckForUpdatesAnnouncesPreReleasesToo(t *testing.T) {
	g := newTestGUI(t)
	stubRunningAs(t, "v0.2.0-rc.1")
	stubLatest(t, &update.Release{Tag: "v0.2.0-rc.2"}, nil)

	info, err := g.CheckForUpdates()
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if !info.Available {
		t.Errorf("Available = false for a newer pre-release: %+v", info)
	}
}

// TestCheckForUpdatesStaysQuietWhenCurrent covers the answers that mean the
// build in use is the one to keep, including a pre-release that is ahead of
// what has been published.
func TestCheckForUpdatesStaysQuietWhenCurrent(t *testing.T) {
	for name, tc := range map[string]struct {
		current, latest string
	}{
		"same version":        {current: "v0.1.1", latest: "v0.1.1"},
		"older release":       {current: "v0.2.0", latest: "v0.1.1"},
		"a local pre-release": {current: "v0.3.0-rc.1", latest: "v0.2.0"},
	} {
		t.Run(name, func(t *testing.T) {
			g := newTestGUI(t)
			stubRunningAs(t, tc.current)
			stubLatest(t, &update.Release{Tag: tc.latest}, nil)

			info, err := g.CheckForUpdates()
			if err != nil {
				t.Fatalf("CheckForUpdates: %v", err)
			}
			if info.Available {
				t.Errorf("Available = true for latest %q against %q", tc.latest, tc.current)
			}
			if !strings.Contains(info.Message, tc.current) {
				t.Errorf("Message = %q, want it to name the version in use %s", info.Message, tc.current)
			}
		})
	}
}

// TestCheckForUpdatesReportsAFailedCheck makes sure a network failure comes back
// as an error the UI can show rather than as silence: a check that cannot be
// made and a check that found nothing look the same to a user, and only one of
// them is a fact.
func TestCheckForUpdatesReportsAFailedCheck(t *testing.T) {
	g := newTestGUI(t)
	stubRunningAs(t, "v0.1.1")
	stubLatest(t, nil, errors.New("could not reach GitHub: no such host"))

	info, err := g.CheckForUpdates()
	if err == nil {
		t.Fatalf("CheckForUpdates = %+v, want an error", info)
	}
	if info.Available || info.Message != "" {
		t.Errorf("CheckForUpdates returned %+v alongside an error; a failure must not look like a result", info)
	}
	if !strings.Contains(err.Error(), "could not reach GitHub") {
		t.Errorf("error = %q, want the cause kept in the chain", err)
	}
}
