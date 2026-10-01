package ui

import (
	"context"
	"fmt"
	"time"

	"github.com/oxcafedead/passone/internal/update"
	"github.com/oxcafedead/passone/internal/version"
)

// updateCheckTimeout bounds one check. internal/update has its own HTTP
// timeout; this is the outer bound, so a caller that stops waiting releases
// the connection even if the inner one somehow has not.
const updateCheckTimeout = 10 * time.Second

// checkLatest is indirected so a test can assert the exact wording of a notice
// without reaching api.github.com. The seams are set in tests that need it and
// restored by their cleanup.
var checkLatest = update.Latest

// UpdateInfo is what one update check found, in the two shapes the UI needs:
// whether there is anything worth saying, and the words to say.
//
// The wording is built here rather than in the renderer because the two
// version strings it is built from are the whole answer, and a message whose
// text is decided in TypeScript is a message this repository cannot test. The
// renderer chooses only when to show it: silently at startup, always when the
// user asked.
type UpdateInfo struct {
	Available bool   `json:"available"`
	Message   string `json:"message"`
}

// CheckForUpdates asks GitHub whether a newer published PassOne release exists.
//
// It answers a question and does nothing else. Nothing is downloaded, replaced
// or installed, and a failure is returned rather than acted on, so the worst a
// bad answer can do is produce a message saying the check did not work.
//
// A development build makes no request at all. "dev" is not a version a tag can
// be compared against, so every launch of a locally built binary would either
// report an update that does not apply or hide a real one; saying so plainly is
// the honest answer, and it is the reason the release pipeline stamps
// internal/version.Version rather than leaving it alone.
func (g *GUI) CheckForUpdates() (UpdateInfo, error) {
	current := version.Version
	if !update.IsRelease(current) {
		return UpdateInfo{
			Message: fmt.Sprintf("PassOne %s is a development build; update checks only run for released versions", current),
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
	defer cancel()

	release, err := checkLatest(ctx)
	if err != nil {
		return UpdateInfo{}, fmt.Errorf("could not check for a newer PassOne: %w", err)
	}
	if !update.Newer(release.Tag, current) {
		return UpdateInfo{
			Message: fmt.Sprintf("PassOne %s is the latest published release", current),
		}, nil
	}
	return UpdateInfo{
		Available: true,
		Message:   fmt.Sprintf("PassOne %s is available (this build is %s)", release.Tag, current),
	}, nil
}
