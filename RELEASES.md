# Releasing PassOne

This document describes how PassOne is versioned and released, what artifacts
are published, and how end users verify their integrity.

## Versioning

- PassOne follows [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.
- Releases are cut from `main` by pushing a signed, annotated tag:

  ```
  git tag -s -a v1.2.3 -m "Release v1.2.3"
  git push origin v1.2.3
  ```

- Tags must start with `v` (`v1.2.3`, not `1.2.3`).
- Pre-release tags (`v1.2.3-rc.1`, `v1.2.3-beta.2`) are allowed; the workflow
  publishes them as pre-releases. A `v*` pattern triggers the release pipeline.
- `go.mod` module path is `github.com/oxcafedead/passone`; tags stay in sync with
  the module path.

The single source of truth for the version string is
`internal/version.Version`. It defaults to `dev` for local builds and is
replaced at release time with `-ldflags`:

```
-X github.com/oxcafedead/passone/internal/version.Version=v1.2.3
```

Local builds never claim a release version; `passone version` prints
`PassOne dev` until a release build stamps it.

## What the release workflow does

`.github/workflows/release.yml` runs on `v*` tag pushes. It:

1. Builds the frontend, then runs `go test ./...` as a gate.
2. Builds `passone.exe` (CLI) with the tag version embedded.
3. Stamps `productVersion` into `cmd/gui/wails.json` and builds the GUI with
   `wails build`, so the Windows file/version resource and the embedded version
   both match the tag.
4. Packs the three archives below and computes SHA-256 checksums.
5. Opens a **draft** GitHub Release populated from the matching `CHANGELOG.md`
   section. Review the notes, then click "Publish release" manually.

### Build matrix

| Artifact | Contents |
|----------|----------|
| `passone-cli-vX.Y.Z-windows-amd64.zip` | `passone.exe` (CLI) |
| `passone-ui-vX.Y.Z-windows-amd64.zip` | `passone-ui.exe` (GUI) |
| `passone-all-vX.Y.Z-windows-amd64.zip` | `passone-ui.exe` (GUI) **and** `passone.exe` (CLI) |
| `SHA256SUMS.txt` | SHA-256 of every `.zip` |

Only `windows-amd64` is built: the app is Windows-specific (systray,
clipboard, WebView2, DPAPI). Add other targets to the workflow if they ever
become supported. If the project grows portable targets, re-evaluate
[goreleaser](https://goreleaser.com/), which handles cross-platform matrices
and installers but does not currently fit the Wails `wails build` packaging
step used here.

## End-user verification

Checksums:

```
sha256sum -c SHA256SUMS.txt
```

On Windows, `certutil -hashfile Foo.zip SHA256` or PowerShell
`Get-FileHash Foo.zip -Algorithm SHA256` can stand in for `sha256sum`.

## Release checklist

1. Update `CHANGELOG.md` (Keep a Changelog format) with the changes since the
   last release; the heading must be `## [vX.Y.Z] - YYYY-MM-DD`.
2. Merge to `main`.
3. Tag and push: `git tag -a vX.Y.Z -m "Release vX.Y.Z" && git push origin vX.Y.Z`
   (`-s` optional if you sign your commits).
4. Wait for the `Release` workflow to finish and open the draft release.
5. Sanity-check the release body (auto-extracted from the changelog) and the
   attached artifacts and checksums.
6. Publish.

## Related

- `internal/version` — version string source (see above).
- `CHANGELOG.md` — release notes source for the workflow.