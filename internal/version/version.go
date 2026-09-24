// Package version holds the application release version.
//
// The value is replaced at release build time via
//
//	go build -ldflags "-X github.com/oxcafedead/passone/internal/version.Version=v1.2.3"
//
// and falls back to the "dev" sentinel for local builds.
package version

// Version is the release version of the application. A "dev" value means the
// binary was built outside of a release pipeline.
var Version = "dev"
