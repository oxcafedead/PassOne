# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.0] - 2026-09-24

### Added

- Versioned releases: a tag-driven [`Release`](.github/workflows/release.yml)
  workflow, a `version` CLI command (`passone version` / `passone --version`),
  and an `internal/version` package as the single source of the version string
  (injected at build time via `-ldflags`).
- Release artifacts ship as per-version Windows archives with a SHA256
  `SHA256SUMS.txt` checksum file.
- `RELEASES.md` documents tagging policy, build matrix and verification steps.