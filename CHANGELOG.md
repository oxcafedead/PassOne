# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.2] - 2026-09-25

### Fixed

- The **Edit** button in the GUI was inert: the Edit entry action rendered and
  looked enabled but was never bound to its `openEdit` handler, so clicking it
  did nothing and entries could not be modified from the UI. The handler was
  dropped from the markup in an unrelated CLI commit.

### Added

- `tools/checkui`, a build gate that fails `go test ./...` when a Svelte
  component contains dead interactivity: a `<button>` with no click handler and
  no `type="submit"`, or a handler function that nothing references. Both
  mistakes compile cleanly and produce no Svelte warning, which is how the Edit
  button shipped broken in the first place.

## [v0.1.1] - 2026-09-24

### Fixed

- The sync button now appears for git-backed stores opened outside the clone
  flow (for example via the folder picker); previously it was hidden unless the
  store had been cloned through the app.
- Draft releases are published with the preinstalled `gh` CLI instead of
  `softprops/action-gh-release`, which failed with a request-body length error.

### Changed

- Release archives are now split into three: `passone-cli`, `passone-ui`
  (GUI only) and `passone-all` (GUI + CLI), each with SHA-256 checksums.

## [v0.1.0] - 2026-09-24

### Added

- Versioned releases: a tag-driven [`Release`](.github/workflows/release.yml)
  workflow, a `version` CLI command (`passone version` / `passone --version`),
  and an `internal/version` package as the single source of the version string
  (injected at build time via `-ldflags`).
- Release artifacts ship as per-version Windows archives with a SHA256
  `SHA256SUMS.txt` checksum file.
- `RELEASES.md` documents tagging policy, build matrix and verification steps.