# AGENTS.md

Compact notes for agents working in this repo. If a fact is obvious from filenames, it is not here.

## Project

Windows password manager (`passone`) backed by a self-contained OpenPGP store. It does **not** require GnuPG, Git or SSH binaries on the target machine; everything is embedded Go code.

- CLI: `cmd/app` → `passone.exe`
- GUI: `cmd/gui` → Wails v2 + Svelte 5 desktop app (`passone-ui.exe`)
- Core: `internal/app` shared by CLI and GUI

## Repo layout

| path | purpose |
|------|---------|
| `cmd/app` | CLI entrypoint and commands |
| `cmd/gui` | Wails v2 GUI entrypoint, tray, single-instance lock |
| `cmd/gui/frontend` | Svelte 5 + Vite + Tailwind 4 frontend |
| `internal/app` | Core app logic (unlock, password ops, git sync, config) |
| `internal/ui` | Wails-specific facade over `internal/app`; frontend binds here |
| `internal/pgp` | OpenPGP encryption/decryption (ProtonMail/go-crypto) |
| `internal/sshx` | OpenSSH key parsing, signer, known-hosts store |
| `internal/gitx` | Pure-Go git operations (go-git) |
| `internal/store` | pass-format store layout (`*.gpg`, `.gpg-id`) |
| `internal/security` | DPAPI sealing, memory zeroing |
| `internal/config` | Config persistence, ACLs, paths |
| `internal/cliputil` | Clipboard write + auto-clear |
| `internal/version` | Single release-version source; injected via `-ldflags` at build time |
| `tools/checkicon` | CI gate: asserts the GUI exe embeds an icon resource |
| `tools/checkui` | CI gate: asserts no Svelte component has dead interactivity |
| `tools/coveragecheck` | CI gate: asserts the coverage profile clears a threshold |
| `tests/interop` | PowerShell harness that validates against real GnuPG |

## Everyday commands

```powershell
# CLI build
go build -o passone.exe ./cmd/app

# Frontend build (required before any Go test that touches cmd/gui)
cd cmd/gui/frontend
npm ci
npm run build
cd ../../..

# Full test suite (run after frontend build)
go test ./...

# Single package / single test
go test ./internal/app
go test ./internal/app -run TestImportUnlockDecryptFlow

# GUI binary build
cd cmd/gui
wails build -skipbindings -s -clean
# Verify the exe embeds the app icon (RT_GROUP_ICON resource)
cd ../..
go run ./tools/checkicon cmd/gui/build/bin/passone-ui.exe
```

Frontend development server (hot reload):

```powershell
cd cmd/gui/frontend
npm run dev
```

## Lint / format

Config lives in `.golangci.yml`. Enabled linters include `errcheck`, `revive`, `gocritic`, `gofmt`, `unused`, etc.

```powershell
# Format all Go files
gofmt -w .

# Run linter locally. Use `go run ...` because go.mod targets Go 1.26 while the
# prebuilt golangci-lint v2.12.x binary is built with Go 1.25 and fails to load deps.
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run --timeout=5m
```

CI (`.github/workflows/ci.yml`) installs golangci-lint with `install-mode: goinstall` to avoid the same version mismatch.

## CI / quality gates

- Runs on `windows-latest` (the app is Windows-specific: systray, clipboard, registry, DPAPI).
- Steps: checkout with full history → setup Go → setup Node → `npm ci && npm run build` → `go test` with coverage → Wails GUI build + `tools/checkicon` icon assertion → `golangci-lint` → SonarQube scan.
- Requires GitHub secret `SONAR_TOKEN`; project metadata is in `sonar-project.properties`.
- `tools/checkui` needs no dedicated CI step: its test lives in the `tools/checkui`
  package, so the ordinary `go test ./...` step runs it. It reads
  `cmd/gui/frontend/src`, so it works before the frontend is built.

### Dead-interactivity gate (`tools/checkui`)

`cmd/gui/frontend/src/App.svelte` is the whole UI, and Svelte raises no error
for a `<button>` that has no `on:click`. Such a button compiles, renders, looks
enabled and is permanently inert — exactly how the Edit button shipped broken.
`tools/checkui` fails the build on two rules:

- `button-no-handler` — a `<button>` with no click handler and no
  `type="submit"`.
- `orphan-handler` — a `function` declared in `<script>` that nothing else in
  the component references, so it can never be called.

Add a rule in `tools/checkui/main.go` and a case in `main_test.go` when you add
a new interactive element class (checkbox, link, keydown-only control).

Recommended local order before pushing:

1. `gofmt -w .`
2. `go test ./...`
3. `golangci-lint` (via `go run ...`)

## Releases

- Versioning is SemVer; releases are tagged `vMAJOR.MINOR.PATCH` on `main`.
  Full policy, artifact list and verification steps live in `RELEASES.md`.
- `.github/workflows/release.yml` triggers on `v*` tag pushes and produces a
  **draft** GitHub Release. It: builds frontend → `go test ./...` → builds CLI
  and GUI with `-ldflags -X .../internal/version.Version=<tag>` → packs
  `passone-cli-<ver>-windows-amd64.zip`, `passone-ui-<ver>-windows-amd64.zip`
  and `passone-all-<ver>-windows-amd64.zip` (GUI + CLI)
  → writes `SHA256SUMS.txt` → fills the body from the matching `CHANGELOG.md`
  section. Publish is manual.
- The Windows version resource for the GUI comes from a `productVersion` stamp
  on `cmd/gui/wails.json` before `wails build`.

## Environment

- `PASSONE_DIR` overrides the application data directory. Tests use `t.Setenv("PASSONE_DIR", t.TempDir())`.
- Default data dir: `%LOCALAPPDATA%\PassOne`.
- Required in PATH: Go, Node.js/npm, and optionally Wails CLI for GUI builds.

## Gotchas

- `cmd/gui/main.go` embeds `all:frontend/dist`. If the frontend has not been built, `go test ./...` fails with `pattern all:frontend/dist: no matching files found`.
- `go test -race` requires `CGO_ENABLED=1`; it is not used in CI.
- NEVER run `go build`/`go run` directly on `cmd/gui` as the app entrypoint: Wails requires its own build tags and aborts with `Error Wails applications will not build without the correct build tags`. Build the GUI with `wails build` from `cmd/gui` instead.
- Do NOT pass `-nopackage` to `wails build`. Wails only generates the `-res.syso` (which embeds `build/windows/icon.ico`, the application manifest and version info) when `options.Pack` is true; with `-nopackage` the exe is produced silently without any icon resource, so Explorer/taskbar show a generic icon. The `-nopackage` flag only matters for non-Windows packaging and is never needed here.
- The project targets Go 1.26 in `go.mod`, but `.golangci.yml` sets `run.go: '1.25'` so the linter can actually start. Do not change this unless the linter version is also updated.
- Exported identifiers must have doc comments (`revive` `exported` rule).
- `npm run check` (svelte-check) currently reports 4 pre-existing type errors
  and is not part of CI. Fix them before wiring it in, otherwise it is not a
  usable gate.
- Windows-only code uses `golang.org/x/sys/windows`, `syscall` lazy DLLs, and DPAPI. Cross-platform refactors need careful review.
- `tests/interop/run.ps1` is a manual integration harness that requires a built
  `passone.exe` and a real GnuPG installation. It is not part of `go test ./...`.
- `tests/interop/run.ps1` is a manual integration harness that requires a built `passone.exe` and a real GnuPG installation. It is not part of `go test ./...`.
