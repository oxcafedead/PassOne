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
wails build -skipbindings -s -nopackage -clean
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
# prebuilt golangci-lint v1.64 binary is built with Go 1.24 and fails to load deps.
go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run --timeout=5m
```

CI (`.github/workflows/ci.yml`) installs golangci-lint with `install-mode: goinstall` to avoid the same version mismatch.

## CI / quality gates

- Runs on `windows-latest` (the app is Windows-specific: systray, clipboard, registry, DPAPI).
- Steps: checkout with full history → setup Go → setup Node → `npm ci && npm run build` → `go test` with coverage → `golangci-lint` → SonarQube scan.
- Requires GitHub secret `SONAR_TOKEN`; project metadata is in `sonar-project.properties`.

Recommended local order before pushing:

1. `gofmt -w .`
2. `go test ./...`
3. `golangci-lint` (via `go run ...`)

## Environment

- `PASSONE_DIR` overrides the application data directory. Tests use `t.Setenv("PASSONE_DIR", t.TempDir())`.
- Default data dir: `%LOCALAPPDATA%\PassOne`.
- Required in PATH: Go, Node.js/npm, and optionally Wails CLI for GUI builds.

## Gotchas

- `cmd/gui/main.go` embeds `all:frontend/dist`. If the frontend has not been built, `go test ./...` fails with `pattern all:frontend/dist: no matching files found`.
- `go test -race` requires `CGO_ENABLED=1`; it is not used in CI.
- The project targets Go 1.26 in `go.mod`, but `.golangci.yml` sets `run.go: '1.24'` so the linter can actually start. Do not change this unless the linter version is also updated.
- Exported identifiers must have doc comments (`revive` `exported` rule).
- Windows-only code uses `golang.org/x/sys/windows`, `syscall` lazy DLLs, and DPAPI. Cross-platform refactors need careful review.
- `tests/interop/run.ps1` is a manual integration harness that requires a built `passone.exe` and a real GnuPG installation. It is not part of `go test ./...`.
