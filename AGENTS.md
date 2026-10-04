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
| `internal/update` | "Is there a newer release?" — GitHub lookup + SemVer precedence |
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

Config lives in `.golangci.yml`. Enabled linters include `errcheck`, `revive`, `gocritic`, `gofmt`, `unused`, `gocognit`, etc.

```powershell
# Format all Go files
gofmt -w .

# Run linter locally. Use `go run ...` because go.mod targets Go 1.26 while the
# prebuilt golangci-lint v2.12.x binary is built with Go 1.25 and fails to load deps.
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run --timeout=5m
```

CI (`.github/workflows/ci.yml`) installs golangci-lint with `install-mode: goinstall` to avoid the same version mismatch.

### The cognitive-complexity gate (`gocognit`, threshold 15)

`gocognit` is enabled at `min-complexity: 15`, and 15 is SonarQube's own
`go:S3776` limit. The point of running it in the linter rather than only on the
dashboard is that **Sonar reports, the linter blocks**: without this a function
can cross the line and sit there indefinitely, because nothing fails the build
and the count is one number on a page nobody opens.

Two properties are load-bearing, and both are judgement rather than taste:

- **`gocognit` is stricter than Sonar, not the same.** It scores `switch` bodies
  more harshly, so it finds functions Sonar does not (`gitx.Pull` was ~24 and
  Sonar had never heard of it) — but it never misses one Sonar found at the same
  threshold, because the two differ by being harsher rather than by measuring
  something else. Passing this gate therefore implies passing Sonar, not the
  reverse. Expect the Sonar count to stay lower than the gate's.
- **Tests are excluded, and that is a decision.** 35 of the 40 functions over 15
  were in `_test.go`. A table-driven test's complexity is mostly irreducible
  setup plus a long tail of assertions, and decomposing it into helpers makes a
  failure harder to read, not easier — the opposite of what the linter is for.
  Sonar *does* score test functions, so its count here will stay above zero; it
  is not the gate.

**Raising the threshold is almost never the right response.** The gate's value is
that it stops a function growing, and raising the bar to clear today's offender
removes that. Split the function instead — every one of the five that were
already over the line when this was added (`checkicon.openPE`,
`checkicon.(*pe).walkDir`, `gitx.Pull`, `checkui.CheckTree`, `gui.trayReady`) got
there by accumulating unrelated decisions, and splitting along that seam made each
of them shorter without needing a single new comment.

To see the numbers without the linter:

```powershell
go run github.com/uudashr/gocognit/cmd/gocognit@v1.2.0 -over 15 <files...>
```

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
- `dead-interpolation` — a `{placeholder}` written inside a quoted string in an
  attribute **expression**, as in `class={on ? 'row {indent()}' : 'row'}`. Svelte
  interpolates in quoted attribute *text* but not in a string literal, so the
  text reaches the DOM verbatim: the row renders with a class literally called
  `{indent()}` and none of the styling it asked for. It compiled, it rendered,
  and nothing warned — it shipped once, as leaf rows losing their tree indent
  the day an inline `padding-left` became a class. A template literal is exempt
  (`${...}` does interpolate), and a string literal passed to an event handler
  is an argument, not a placeholder. Put the conditional in a `class:`
  directive or build the string in the script block.

Add a rule in `tools/checkui/main.go` and a case in `main_test.go` when you add
a new interactive element class (checkbox, link, keydown-only control) or a
new way of setting a style the policy blocks (a `style` prop on a component,
CSS-in-JS, a helper that wraps `el.style`). Add a DOM assertion to
`cmd/gui/frontend/test/app.test.ts` when a class you build by string is supposed
to end up on an element: `dead-interpolation` cannot see a placeholder you built
in the script block, and neither can the compiler.

### Renderer-escape-hatch gate (`tools/checkui`)

The same tool also refuses the constructs that would defeat Svelte's escaping
(the rationale is in the CSP section below):

- `raw-html` — a `{@html ...}` tag.
- `html-sink` — `innerHTML`/`outerHTML`, `insertAdjacentHTML`, `srcdoc`,
  `document.write`, `eval(`, `new Function(`.
- `inline-style` — a `style` attribute or Svelte `style:` directive in markup,
  or an inline-style write in script (`el.style.x =`, `el.style.cssText =`,
  `el.style.setProperty(`, `setAttribute('style'`, `createElement('style'`).
  `style-src 'self'` makes the webview drop these **with no error message**,
  so the rule belongs in `src/style.css` and a class belongs in the markup.
- `missing-csp` / `weak-csp` — `index.html` has no CSP meta tag, or its policy
  would not actually restrict scripts or styles (no `default-src`, `*`,
  `'unsafe-inline'` in `script-src`/`style-src`, `'unsafe-eval'`).

`.svelte` and `.ts`/`.js` files under `src/` are both scanned. A line that must
name a sink without using it (prose, a reviewed exception) is suppressed with
`// checkui:allow` on that line; if you need the exception often enough for
that to smell, the answer is `textContent`, not a suppression.

### Content-Security-Policy (do not remove)

`cmd/gui/frontend/index.html` carries
`<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'">`.
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

`style-src` is `'self'` with **no** `'unsafe-inline'` (Sonar Web:S7039 fires
otherwise). The production build emits exactly one stylesheet and links it from
`dist/index.html`, and every rule lives in `src/style.css`, so an inline style
has no reason to exist — and the webview would drop it silently anyway. Tree
indentation, which used to be `style="padding-left: {8 + row.depth * 14}px;"`,
is `.tree-d0` … `.tree-d12` (clamped in `indentClass`) for the same reason;
modal scrims are Tailwind's `bg-black/45`.

`npm run dev` is the one exception, and it is dev-only. Vite serves CSS as
JavaScript and appends `<style>` elements as modules load, which `style-src
'self'` blocks, so `devInlineStyleCSP()` in `cmd/gui/frontend/vite.config.ts`
rewrites `style-src` when the plugin is in `serve` mode. It rewrites rather than
adds a second meta tag because a browser enforces **every** policy it finds:
a second, relaxed one cannot relax the first. The built `dist/index.html` is
generated from the checked-in `index.html` and keeps the strict policy.

Notes for anyone touching the policy:

- Do not add `'unsafe-inline'` or `'unsafe-hashes'` to `style-src`, `'unsafe-eval'`
  to `script-src`, or `'unsafe-inline'` to `script-src` at all. `tools/checkui`
  fails on each of them; if one becomes genuinely necessary, the fix belongs in
  the app's own CSS, not in the policy.
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

### The entry's action row wraps, and nothing in it shrinks (GH #41)

The header above the detail pane is one `flex flex-wrap` row holding the entry
path, the copy-countdown badges and up to seven actions (Show, Copy, TOTP,
Username, Edit, Move, Delete). Two properties are load-bearing, not stylistic:

- **The row wraps and every item in it is `shrink-0` + `whitespace-nowrap`** —
  the badges included, since three countdowns can be running at once. A flex
  item cannot shrink below its own label, so a single-line row overflows the
  page as soon as the two conditional actions appear — which is every entry with
  a TOTP seed or a login, i.e. most of them. Overflowing content extends the
  document's scrollable area, so the window grew a horizontal scrollbar that cut
  the detail pane off, and it did not matter how wide the window was: the row
  wanted more than the screen had. Two more buttons were not the trigger, a
  non-wrapping row was.
- **The heading is `basis-full min-w-0 truncate`**, so a long path takes a line
  of its own and shortens instead of taking width from the buttons. It also
  means no `flex-1` spacer is needed to hold the actions right.

`describe('entry actions row')` in `cmd/gui/frontend/test/app.test.ts` pins all
three. jsdom has no layout engine, so the test asserts the classes, not a
measured width — which is the same reason the tree-indent assertions are class
assertions. Add a case there if a new action appears in that row, and re-run the
width arithmetic for the default `Width:` in `cmd/gui/main.go` (1020 fits all
seven beside the `w-72` sidebar; `MinWidth` stays at 720 and relies on the wrap).

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

### The edit form is always opened with the entry's notes (GH #39)

`openEdit` decrypts the entry through `ShowNotes` before it opens the dialog, and
`edBody` starts as a copy of them (`edOrig` keeps the original). Two properties
follow, and both are load-bearing rather than stylistic:

- **An edit dialog in edit mode is never open with an empty notes box that the
  user did not empty.** A failed `ShowNotes` opens no dialog at all, and the
  await is guarded by `selected !== name` so a lock or a row change in the
  meantime cannot drop notes into a dialog about another entry. If you ever
  reopen the dialog without loading the notes, an emptied box becomes
  indistinguishable from "delete the notes" and a save destroys them.
- **`ShowNotes` returns the body only, never the password line.** The password
  field opening empty is what keeps "empty means keep the stored secret" true, so
  the prefill must not be a full-plaintext call. The DOM test asserts
  `ShowPassword` is called zero times by the edit flow.

`body` is therefore the entry's whole new notes, and an empty `body` clears them
(`internal/ui.UpdatePassword` no longer short-circuits an empty body to "No
changes"). The no-op decision moved to the form, the only place that knows what
the field opened with: an unchanged save reports `No changes to <name>` and does
not re-encrypt identical plaintext just to commit the file again.

Recommended local order before pushing:

1. `gofmt -w .`
2. `go test ./...`
3. `cd cmd/gui/frontend && npm test && npm run check`
4. `golangci-lint` (via `go run ...`)

### The update check tells a stale build it is stale, and stops there (GH #31)

`internal/update` asks `api.github.com/.../releases/latest` whether a newer
release exists and compares the tag against `internal/version.Version` by SemVer
precedence. It **downloads, verifies and installs nothing** — that is the load-
bearing boundary. A password manager that fetches a replacement for itself over
the network is a much larger decision than one, and shipping it would mean a
trust decision about who may replace a binary holding an unlocked vault.

Four properties follow, and each is a test:

- **`internal/update.Latest` refuses a draft or a pre-release.** GitHub's
  `/releases/latest` already documents that exclusion and the pipeline publishes
  a tag as a draft first, so the flags are asserted again locally anyway: a
  promise that lives only in a remote service's documentation is not one this
  repository can test. Pre-releases are legitimate releases here (RELEASES.md
  allows `v1.2.3-rc.1` tags), so this is the assertion that keeps a `v1.3.0-rc.1`
  from being offered to someone on `v1.2.0` as the stable build.
- **A `dev` build makes no request at all.** `version.Version` defaults to `dev`,
  which is not a version a tag can be compared against, so `internal/ui`
  short-circuits on `update.IsRelease` and answers with why. Guessing would
  either invent an update or hide a real one.
- **An unparseable version is never newer.** `parseVersion` refuses rather than
  guesses: four components, a leading zero (`v0.01.1`, `rc.01`), a non-numeric
  field, and a core component too long for an `int` are all "not a version", so
  the answer is "no update" rather than a nag about a build that was never
  tagged. Pre-release numeric identifiers are compared as digit strings, not
  `strconv.Atoi`, because an identifier longer than an `int64` overflows and
  would silently become a *text* comparison — under `Atoi`, `rc.100000000000000000000`
  sorts below `rc.99` because `'1'` precedes `'9'`.
- **Nothing about the check blocks the app.** The frontend calls
  `CheckForUpdates` from `onMount` without awaiting it into `load()` — the
  unlock screen must not wait on the network — and a failure is swallowed when it
  was not asked for.
- **The startup check is silent unless there is something to say.** That is the
  whole of the `quiet` parameter on `checkForUpdates`. A toast on every launch
  saying "you are up to date" would be news nobody asked for, and it would land
  on top of the messages the launch itself produces. The tray's **Check for
  updates** item passes `false` and always answers.

The tray item emits `passone:check-updates` rather than calling the checker
itself, so one place decides what a check says and one toast says it. The cost is
that an event only lands if the page is already listening, so a tray click in the
first moments after launch is dropped — and the startup check that follows the
page load is what answers instead. `AGENTS.md`'s advice for anything that must
survive a late listener is to not use an event: the lock and unlock stream and the
clipboard warning are the two existing cases, and neither has a caller that can
ask a second time.

`cmd/gui/tray.go`'s `requestUpdateCheck` is the only new untested line
(`runtime.EventsEmit` needs a live Wails context), which is why the tray menu
itself is the part pinned here and in `internal/ui`.

### The tray goroutine is pinned to one OS thread (GH #14)

`runTray` in `cmd/gui/tray_loop.go` calls `runtime.LockOSThread` before
`systray.Run` and does not drop it until the loop returns. That is not
bookkeeping, it is the only thing keeping the tray icon's menu working:

- **systray's window is serviced by a thread queue.** It creates a hidden
  window and pumps it with `GetMessageW(hWnd = 0)`, which drains **the calling
  thread's** queue and nothing else. The window and the pump therefore have to
  stay on one thread, or the `WM_COMMAND` and the icon's callback message are
  posted to a queue nobody is reading.
- **systray's own pin is on the wrong thread for us.** Its package `init` calls
  `runtime.LockOSThread`, which pins whichever thread initialisation ran on —
  the main thread. Wails needs the main thread on Windows, which is exactly why
  the loop has to be on a goroutine of its own. A bare `go systray.Run(...)`
  therefore satisfies Wails and abandons systray's assumption silently.

The symptom when the pin is missing is not a crash, it is a quiet degradation,
which is what made this worth an issue rather than a stack trace (GH #14): the
icon stays drawn, left and right clicks stop doing anything after an
unpredictable amount of time, and since the tray holds the only **Quit
PassOne** item the process can then only be ended from Task Manager. Upstream
tracked the identical report at getlantern/systray#149, #161 and #269 (closed by
#281) and landed on the same fix.

Two things follow, and each is a test:

- **`TestRunTrayPinsItsGoroutineToOneOSThread`** substitutes a loop that samples
  `windows.GetCurrentThreadId()` either side of a yield storm and requires it to
  be unchanged. The positive direction cannot flake (`LockOSThread` guarantees
  it) and the negative one has real teeth: with the pin deleted it fails about
  four runs in five, because a goroutine that blocks hands its thread back to
  the scheduler. It runs against the `systrayRun` seam, so restoring the seam
  matters.
- **A tray loop that stops is never survivable, so `watchTray` ends the
  process.** The tray owns the process lifetime by design — `HideWindowOnClose`
  means closing the window only hides it, and every exit goes through the tray's
  Quit item, which closes `quitRequested` *before* `runtime.Quit`. A loop that
  stops for any other reason leaves an app with no way to close it that also
  keeps holding the single-instance mutex, so the next launch is turned away and
  finds nothing to show. Hence `classifyTrayStop`: a stop with no quit requested
  is a fault and exits `1`, and a stop during a quit is ordinary teardown that
  `main` drains itself. The only account of an exit can be `passone.log`, which
  is why `guiLog` goes through the `golog` outputs `main.go` sets up — nothing in
  the UI could report it, the UI being unreachable by definition at that point.

`appCtx` and `appBinding` are written by Wails callbacks and read by the tray
menu goroutine, so they are behind `appMu`. The `ctx != nil` / `a != nil` checks
read as guards but are not one without it: `context.Context` is two words, and a
torn read pairs a type pointer with another value's data pointer.

### What the SonarCloud scan is allowed to complain about, and what it is not

`sonar-project.properties` sets `sonar.sources=.` and `sonar.tests=.`, so the
scan covers production code, tests and the CI tooling alike. That is why most of
the open issue count is not about the vault: it is the frontend test harness and
the gate tools. Read the rule and the file before treating a count as a defect.

Findings that are **deliberate** and should not be "fixed":

- **`go:S4036` on `tools/coveragecheck` (`exec.Command("go", ...)`)** — the tool
  shells out to the Go toolchain CI installed. Resolving it by absolute path
  would mean hardcoding a toolchain location, which is the opposite of portable.
- **`godre:S8242` on `internal/ui.GUI.ctx`** — a `context.Context` held in a
  struct field is what the Wails binding requires: `SetContext` is called once
  during startup and the stored value is what `EventsEmit` needs long after.
  Passing it per-method would mean threading it through the tray, which has no
  context of its own to pass. Same shape as `cmd/gui`'s `appCtx` above.
- **`Web:S7039` in `cmd/gui/frontend/index.html`** — reported when `style-src`
  carries `'unsafe-inline'`. The checked-in policy does not; the rewrite lives in
  `vite.config.ts` and is dev-only (see the CSP section). If this reappears,
  check which analysis it came from before touching `index.html`.

Findings that are **noise in the frontend test harness**:

- **`typescript:S7503` (`async` with no `await`) in
  `cmd/gui/frontend/test/bridge.ts`** — that file is a hand-written stand-in for
  the *generated* `wailsjs` modules, and every real binding is async. Dropping
  `async` would make the mock less faithful to what it stands in for, and the
  `await`s in `app.test.ts` would still resolve. The async-ness is the contract.
- **`typescript:S7780` (`String.raw`) in `test/`** — cosmetic in assertions that
  exist to fail loudly if the string under test changes.

Cognitive complexity (`go:S3776`) is reported as **CRITICAL** on every function
over 15, which is most of the severity budget in this project and none of it is a
security signal. Zero open `BUG`s is the number that matters here.

Note that Sonar's Go S3776 and `gocognit` disagree: `internal/gitx.Pull` (~24 by
`gocognit`) and `tools/checkui.CheckTree` (~18) are not flagged by Sonar, because
it scores `switch` bodies more leniently. Both are now under the
`gocognit` gate after being split (see the complexity gate above), so the two
tools agreeing is now the expected state rather than a coincidence.

### Sonar's coverage number and the local one measure different things

`tools/coveragecheck` reported **77.3%** of Go *statements* while SonarCloud
reported **64.3%**. That was not a disagreement about the Go code, and no
instrumentation was missing. Two separate denominators:

- **Sonar counts every language it analyses**, and at the time it analysed 1,106
  lines of TypeScript plus 128 of PowerShell, none of which any step produced a
  coverage report for. Only `sonar.go.coverage.reportPaths` was configured.
- **Most of that TypeScript was the test harness.** `sonar.test.inclusions` was
  `**/*_test.go`, which does not match `test/app.test.ts`, `bridge.ts`,
  `runtime.ts` or `setup.ts`. With `sonar.sources=.` those four files were
  classified as *production* code and measured as uncovered product: 1,069 of
  the 1,078 uncovered TypeScript lines.

`sonar.test.inclusions` now also lists `**/frontend/test/**`, and
`sonar.coverage.exclusions` takes out the harness, the build configs and
`tests/interop`. That moves coverage from 64.3% to a projected **~76%**, which
is the Go figure all along (76.6% line-based vs 77.3% statement-based locally).
Both are above the gate; only Sonar's was failing.

An exclusion list is a claim that the code *cannot* be measured by this
pipeline, so it stays short on purpose. `src/main.ts` is nine uncovered lines of
real product code and is deliberately left in.

There is deliberately **no** `sonar.javascript.lcov.reportPath` and no
`@vitest/coverage-v8` dependency. Adding them looks like the obvious fix and
would move this metric by almost nothing, which is worth knowing before anyone
reaches for it.

### Sonar cannot see the Svelte UI

The scan analyses **zero `.svelte` files**. `cmd/gui/frontend/src/App.svelte` is
2,554 lines and is the entire user interface, and SonarCloud has no Svelte
analyser, so none of it appears in the scan at all — no issues, and no coverage
either way.

This is the context for the two facts above. The 49 `typescript:S7503` and 23
`typescript:S7780` findings are all in the harness; the 1,069 lines Sonar called
uncovered TypeScript are the harness; and the one frontend source file it does
see, `src/main.ts`, is 9 lines of bootstrap. The frontend looks heavily
uncovered and heavily smelly because what Sonar can see of the frontend is
almost entirely its own test harness.

So **frontend coverage wiring is not worth doing while `.svelte` is invisible**
— it would report coverage for `src/main.ts` and nothing else, because the
`lcov` entries for `App.svelte` would refer to a file the scan does not index.
The 56 DOM tests do exercise `App.svelte`; that is enforced by them failing, and
the coverage number would add nothing to it. Revisit if Sonar adds Svelte
support, or if the UI is ever split out of the single component.

Treat "coverage went up" from these changes as the accounting being corrected,
not as new tests. No test was added or removed.

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
- `npm run check` (svelte-check) reports 2 pre-existing `autofocus` a11y
  warnings and is not part of CI. It has no type errors, so it can be wired in
  as a gate; fix or suppress the two warnings first.
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
