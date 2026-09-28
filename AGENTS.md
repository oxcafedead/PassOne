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
| `cmd/gui/frontend/test` | jsdom smoke tests for `App.svelte` (vitest) |
| `internal/app` | Core app logic (unlock, password ops, git sync, config) |
| `internal/ui` | Wails-specific facade over `internal/app`; frontend binds here |
| `internal/pgp` | OpenPGP encryption/decryption (ProtonMail/go-crypto) |
| `internal/sshx` | OpenSSH key parsing, signer, known-hosts store |
| `internal/gitx` | Pure-Go git operations (go-git) |
| `internal/store` | pass-format store layout (`*.gpg`, `.gpg-id`) |
| `internal/security` | DPAPI sealing, memory zeroing |
| `internal/config` | Config persistence, ACLs, paths |
| `internal/cliputil` | Clipboard write, auto-clear, Clipboard History markers |
| `internal/version` | Single release-version source; injected via `-ldflags` at build time |
| `tools/checkicon` | CI gate: asserts the GUI exe embeds an icon resource |
| `tools/checkui` | CI gate: asserts no Svelte component has dead interactivity and no renderer escape hatch (`{@html}`, `innerHTML`, missing CSP) |
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

# Frontend DOM smoke tests
cd cmd/gui/frontend
npm test
cd ../../..

# Full test suite (run after frontend build)
go test ./...

# Single package / single test
go test ./internal/app
go test ./internal/app -run TestImportUnlockDecryptFlow

# Race detector (CI runs this over ./...; needs cgo and a C compiler)
$env:CGO_ENABLED = 1
go test -race ./internal/app
go test -race ./internal/app -run TestStorePathConcurrentWithOpenLocalStore

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
- Steps: checkout with full history → setup Go → setup Node → `npm ci && npm run build` → `go test` with coverage → `go test -race ./...` → Wails GUI build + `tools/checkicon` icon assertion → `golangci-lint` → SonarQube scan.
- Requires GitHub secret `SONAR_TOKEN`; project metadata is in `sonar-project.properties`.
- `tools/checkui` needs no dedicated CI step: its test lives in the `tools/checkui`
  package, so the ordinary `go test ./...` step runs it. It reads
  `cmd/gui/frontend/src` and `cmd/gui/frontend/index.html`, so it works before
  the frontend is built.

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

### Renderer-escape-hatch gate (`tools/checkui`)

The same tool also refuses the constructs that would defeat Svelte's escaping
(the rationale is in the CSP section below):

- `raw-html` — a `{@html ...}` tag.
- `html-sink` — `innerHTML`/`outerHTML`, `insertAdjacentHTML`, `srcdoc`,
  `document.write`, `eval(`, `new Function(`.
- `missing-csp` / `weak-csp` — `index.html` has no CSP meta tag, or its policy
  would not actually restrict scripts (no `default-src`, `*`,
  `'unsafe-inline'`, `'unsafe-eval'`).

`.svelte` and `.ts`/`.js` files under `src/` are both scanned. A line that must
name a sink without using it (prose, a reviewed exception) is suppressed with
`// checkui:allow` on that line; if you need the exception often enough for
that to smell, the answer is `textContent`, not a suppression.

### Content-Security-Policy (do not remove)

`cmd/gui/frontend/index.html` carries
`<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'">`.
Wails v2 has **no** CSP option (`pkg/options/options.go` and
`pkg/options/assetserver/options.go` in v2.16.0 have no such field), so this
meta tag is the entire renderer-side policy. `tools/checkui` fails the build
(`missing-csp` / `weak-csp`) if it is deleted or weakened.

Why it matters here specifically: the webview is not a read-only view. It is
bound to the whole Go bridge — `ShowPassword`, `ImportPGPKeyFile`,
`ImportSSHKeyFile`, `OpenLocalStore`, `CloneStore`, `ChangeLockPassword`. Any
script that runs in the renderer can therefore read the vault, rewrite the lock
password or pivot the store. The app is safe today because Svelte escapes every
interpolation and secrets are rendered as text (`value={detail}` in a
textarea), but that is a convention, not a control. CSP is the control: it is
what turns a future `{@html}` mistake, an injected dependency or a hostile
`.gpg` filename into a broken panel instead of total compromise.

Notes for anyone touching the policy:

- `style-src` needs `'unsafe-inline'`: Svelte injects component CSS as runtime
  `<style>` elements. `script-src` does **not** — keep `'self'`; do not add
  `'unsafe-eval'`, and never add `'unsafe-inline'` to `script-src`.
- `connect-src 'self'` is enough for `npm run dev`: the vite HMR socket is
  same-origin, and a `ws://` URL matches `'self'` for an `http://` page.
- The CSP gates the document, not the Wails runtime scripts, which are injected
  as same-origin `<script src>` by the asset server.
- The asset server parses and re-renders `index.html` through
  `golang.org/x/net/html` before it reaches the webview.
  `TestCSPSurvivesWailsRender` in `tools/checkui` pins that the policy survives
  that round trip.
- Entry names and other vault data reach the DOM as text. If you ever need
  dynamic markup, prefer building nodes with `textContent`/`createElement` over
  `innerHTML`; both are refused by `tools/checkui`.

### Bridge-contract gate (`cmd/gui/binding_contract_test.go`)

`cmd/gui` is the only package holding Wails-bound methods, and a rename there
does not fail the Go build anywhere: the generated `wailsjs/go/main/App.js` and
`App.d.ts` are checked in, and `App.svelte` imports them by name. So a renamed
method compiles, ships, and leaves a button calling a name that no longer
exists. This test reflects over `*App` and asserts:

- every exported method has a matching export in `App.js` and a declaration in
  `App.d.ts`, with the same arity;
- declared parameter types match the Go types;
- every name `App.svelte` imports from `App.js` actually exists there;
- most generated bindings are still used by the UI (a low watermark catches
  bindings orphaned by a UI rewrite without failing on legitimately
  backend-only methods such as `Lock`, which the tray calls).

Add a case here when a new interactive element class appears (checkbox, link,
keydown-only control), alongside the matching `tools/checkui` rule.

### Frontend DOM smoke tests (`cmd/gui/frontend/test`)

vitest + jsdom, run by `npm test` in `cmd/gui/frontend` and as its own CI step.
`App.svelte` is mounted in jsdom with `test/setup.ts` installing a
`window.go.main.App` and `window.runtime` stand-in, so the **real** generated
`wailsjs` modules resolve and every backend call is assertable with `vi.fn`.
There is no module alias on purpose: a binding that calls the wrong `window`
path fails here too.

The tests drive the flows that have actually broken before — unlock, explicit
reveal, notes-only edit, add, two-step delete, auto-lock — and assert the exact
arguments sent to the bridge. That last part is the point. `Edit` sends
`UpdatePassword(name, '', body, true)` and lets Go splice the original first
line back in; a frontend that pre-built `"password\nnotes"` would corrupt every
notes-only edit, and only an argument assertion catches it.

`vitest.config.ts` pins `resolve.conditions: ['browser']` (Svelte's server
entry throws on `mount`) and deliberately omits the Tailwind plugin, which has
no named ESM export. `tsconfig.json` includes `test/**/*.ts` and
`vitest.config.ts` so `npm run check` covers them.

Recommended local order before pushing:

1. `gofmt -w .`
2. `go test ./...`
3. `cd cmd/gui/frontend && npm test`
4. `golangci-lint` (via `go run ...`)

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
- `go test -race` needs `CGO_ENABLED=1` and a C compiler; the CI step sets it explicitly because `CGO_ENABLED` defaults to 0 when Go finds no C compiler at install time. It runs over `./...` as a separate step from the coverage run, which stays un-instrumented.
- NEVER run `go build`/`go run` directly on `cmd/gui` as the app entrypoint: Wails requires its own build tags and aborts with `Error Wails applications will not build without the correct build tags`. Build the GUI with `wails build` from `cmd/gui` instead.
- Do NOT pass `-nopackage` to `wails build`. Wails only generates the `-res.syso` (which embeds `build/windows/icon.ico`, the application manifest and version info) when `options.Pack` is true; with `-nopackage` the exe is produced silently without any icon resource, so Explorer/taskbar show a generic icon. The `-nopackage` flag only matters for non-Windows packaging and is never needed here.
- The project targets Go 1.26 in `go.mod`, but `.golangci.yml` sets `run.go: '1.25'` so the linter can actually start. Do not change this unless the linter version is also updated.
- Exported identifiers must have doc comments (`revive` `exported` rule).
- `npm run check` (svelte-check) currently reports 4 pre-existing type errors
  and is not part of CI. Fix them before wiring it in, otherwise it is not a
  usable gate.
- Windows-only code uses `golang.org/x/sys/windows`, `syscall` lazy DLLs, and DPAPI. Cross-platform refactors need careful review.
- Clipboard copies are published with the `CanIncludeInClipboardHistory`,
  `CanUploadToCloudClipboard` and `ExcludeClipboardContentFromMonitorProcessing`
  formats (DWORD 0/0/1). Windows snapshots an item into Clipboard History and the
  cloud clipboard at `SetClipboardData`, so **no clear can reach them** — the
  formats are the only lever, they are a request Windows may ignore, and there is
  no API to delete a snapshot. `cliputil.Copied` therefore returns a
  `Result` whose `HistoryExcluded` says whether the marker actually went on, and
  the GUI/CLI warn when it did not. The `passone:clipboard-warning` event exists
  because a clear runs on a timer after the copy call returned, so its failures
  cannot travel back through that call's return value.
- `tests/interop/run.ps1` is a manual integration harness that requires a built
  `passone.exe` and a real GnuPG installation. It is not part of `go test ./...`.
- `tests/interop/run.ps1` is a manual integration harness that requires a built `passone.exe` and a real GnuPG installation. It is not part of `go test ./...`.
