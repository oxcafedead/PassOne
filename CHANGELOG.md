# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Tell a stale build that a newer PassOne exists (GH #31).** There was no way
  to learn about a new release from inside the app: nothing printed its own
  version, and the only route to a newer build was finding the releases page by
  hand. A released GUI now asks GitHub once at startup, off the critical path, and
  says so in a toast when the latest published release is newer than the version
  it was stamped with. A **Check for updates** item in the tray menu repeats the
  check and always answers, so "no update" is a result too.

  The check **only tells you**. Nothing is downloaded, verified or installed: a
  password manager that fetched a replacement for a binary that may be holding an
  unlocked vault would be a much larger decision than this, and the decision
  about who may replace the app belongs to the person running it. Fetching the
  update remains what `RELEASES.md` says it is — download a zip, check it against
  `SHA256SUMS.txt`.

  Only *published* releases count, so a draft a maintainer has not finished
  reviewing is never offered, and a `v1.3.0-rc.1` tag is never presented to
  someone on `v1.2.0` as the stable build. Comparison is full SemVer precedence,
  which means someone running a release candidate is still told when the stable
  release it leads to lands.

  A build with the `dev` version — every `wails build` outside the release
  pipeline — makes no request at all and says so when asked, because `dev` is not
  a version a tag can be compared against. The startup check is silent when there
  is nothing newer, and a failed check stays silent too: a toast on every launch
  saying "you are up to date" is news nobody asked for, and a network error is not
  news at all.

- **Move and rename password entries (GH #34).** An entry could be created,
  edited and deleted, but never renamed: changing the last segment of a path
  meant creating a second entry and deleting the first, which re-encrypts the
  secret and drops any TOTP or note detail that was not copied across by hand.
  A **Move** button next to Edit and Delete opens a dialog pre-filled with the
  current path, so the common case is editing the last segment and a longer path
  moves the entry into that folder, creating it. The CLI gains
  `mv <from> <to>` for the same thing.

  The stored `*.gpg` file is **renamed, never re-encrypted**: a move does not
  decrypt, does not re-resolve the store's recipients, and cannot expose or
  alter a secret on the way to its new path. A move onto an existing entry is
  refused rather than replacing it, and a case-only rename (`github/x` →
  `GitHub/x`) is a real rename rather than a no-op, which on Windows needs an
  intermediate file name because the two names are one file on disk.

  In a git store a move is committed as the pair of changes it is — the old path
  leaves the index and the new one enters it in a single commit. Staging only one
  half, as a one-path commit would, leaves the other for the next commit on that
  repository to pick up, so a synced store could bring the entry back under its
  old name. The GUI also opens the folders leading to a moved entry, so a row
  moved into a folder that did not exist a moment ago is not selected-and-hidden
  behind a collapsed folder.

- **Key generation and store creation, without `gpg` or `pass init`.** A user
  with nothing on their machine could previously only clone a store somebody else
  had created, so the app was unusable without an existing `pass` installation
  and an armored key file. `pgp.Generate` now creates an Ed25519/Curve25519 key
  (AES-256, SHA-256) and the setup wizard offers it next to the import, and
  `CreateStore` writes a complete pass store: `.gpg-id` naming the key,
  a git repository on `main`, and a first commit — so the result lists entries,
  syncs, and clones on another machine like any other. A git remote is optional
  and is **recorded but not contacted**; the first Sync is the push, so creating
  a store neither depends on a server being reachable nor publishes an empty
  vault. The CLI gains `gen-pgp-key [name] [email]` and
  `init-store <dir> [remote]` for the same journey.
- The setup wizard now asks for the decryption key **before** the store, because
  a new store is encrypted to that key: the previous order left a first-run user
  with nothing they could do in step 2. It also opens at whichever step still
  needs work, and the create form shows the resolved path before anything is
  written.

### Fixed

- **Auto-lock set to 0 no longer reverts to 5 minutes (GH #42).** The settings
  form offers `0 = never` and `SetAutoLock` documents 0 as disabling the idle
  timer, but loading the configuration repaired `AutoLockMinutes <= 0` to the
  5-minute default — the repair that guards a corrupt file also threw away the
  one value the user had chosen on purpose. The setting took effect, saved as
  `0`, and came back as 5 on the next start, so "never" was unreachable in
  practice. Only a **negative** timeout is repaired now; a config file that
  never mentions the setting still gets the default, because the file is decoded
  onto the defaults before the check. The clipboard delay is unchanged: there 0
  is genuinely invalid (`SetClipboardClear` refuses under a second).

  Turning the auto-lock off also has to stay a deliberate act. Svelte binds an
  emptied `<input type="number">` to `null`, which the bridge turns into the same
  `0` Go cannot tell from a chosen one, so saving a cleared field would have
  silently disarmed the idle lock; the form now refuses that save and says what
  the field expects, and the settings placeholder is the app's default rather
  than 0 so a failed settings read cannot submit "never" either.

- **No more horizontal scrollbar on an entry that has a TOTP (GH #41).** The
  selected entry's actions shared one fixed line, and two of them — **TOTP** and
  **Username** — only appear for entries that carry a seed or a login. A flex item
  cannot shrink below its own label, so an entry with both grew the row past the
  window: the page became scrollable sideways, the scrollbar cut the detail pane
  off, and no width fixed it, because the row wanted more than the screen had.
  The row now wraps and nothing in it shrinks, so the tail drops onto a second
  line instead, and the entry path takes a line of its own and truncates rather
  than competing with the buttons. The default window is 1020px wide, where all
  seven buttons still fit on one line beside the sidebar; the window still
  resizes down to 720px, and a narrow window wraps instead of overflowing.

- **Opening Edit no longer hides an entry's notes, so an edit cannot silently
  drop them (GH #39).** The dialog opened with an empty notes box and an empty
  password box, which is the one state that cannot distinguish "the notes I
  meant to change" from "leave the notes alone" and "delete the notes". Editing
  a password replaced every note the entry had unless they were retyped from the
  view pane by hand, and editing one note replaced the rest. Opening Edit now
  loads the entry's notes into the box, so the field is the notes themselves and
  the common cases — change the password, append a line, fix a typo — do what
  they say. The CLI already did this: `edit` opens the stored entry in
  `$EDITOR`.

  The password is deliberately **not** part of that load. `ShowNotes` returns
  everything below the password line, so the dialog's password field still opens
  empty, an empty field still means "keep the stored secret", and the secret is
  not put in the renderer on the way to the form. A load that fails opens no
  dialog at all, rather than an empty one whose save would read as a deletion.

  Because the box now opens full, an emptied box means the user deleted the
  notes, and `UpdatePassword` takes the body it is given as the entry's whole
  new notes — so a no-op save is decided in the form, which is the only place
  that knows what the field opened with, instead of re-encrypting identical
  plaintext and committing it to git again.

### Security

- A generated OpenPGP key is stored only in the app's sealed vault, so its
  passphrase is unrecoverable if lost. The CLI asks for it twice, the wizard
  confirms it and says so on the form, and `GeneratePGPKey` refuses to run over an
  existing stored or resident key so a store that already names it cannot be
  orphaned.

- Copied secrets can still reach Windows Clipboard History and the cloud
  clipboard, which the auto-clear could never fix: both snapshot an item at
  `SetClipboardData`, and there is no API to delete a snapshot. Every copy is now
  published with `CanIncludeInClipboardHistory`,
  `CanUploadToCloudClipboard` and
  `ExcludeClipboardContentFromMonitorProcessing` (0/0/1), including the empty
  item a clear leaves behind, and `cliputil.Copied` reports whether the marker
  actually went on so the CLI and the GUI can say so instead of implying a
  guarantee. The formats are the only lever and a Windows build may still ignore
  them, which the UI now states in the copy badges and in Settings.
- A clipboard clear that could not read the clipboard treated an unreadable
  clipboard as "the user moved on" and left the secret in place. It now fails
  closed: it wipes unconditionally and reports that it did, through the
  `passone:clipboard-warning` event in the GUI and stderr in the CLI. Failures on
  the timer have no caller left to return to, so they cannot travel back in
  `Copied`'s result.
- The renderer policy allowed `'unsafe-inline'` styles (Sonar Web:S7039). It
  re-opened the one thing the policy exists for: injected markup could restyle
  the app, and a full-screen overlay over the entry list is all it takes to aim
  a click at the wrong row. The build emits a single linked stylesheet, so
  `style-src` is now `'self'`; tree indentation became `.tree-d0` … `.tree-d12`
  and the modal scrims Tailwind's `bg-black/45`, and `tools/checkui` now fails
  on an inline style (`inline-style`) or on `'unsafe-inline'` coming back. Only
  `npm run dev`, where Vite injects CSS as `<style>` elements, still relaxes
  it, and only in serve mode.
- Tree rows lost their indent. The tree indent is a class per depth step
  (`.tree-d0` … `.tree-d12`) rather than an inline `padding-left`, and the
  leaf row was written as `class={sel ? 'row {indentClass(d)}' : 'row …'}` —
  Svelte interpolates `{placeholders}` in quoted attribute *text* but not inside
  a string literal, so the class name reached the DOM verbatim and every leaf
  rendered flush left. `tools/checkui` now fails the build on that shape
  (`dead-interpolation`) and the DOM tests assert the indent class is really on
  the row.

### Added

- `cliputil.HistoryEnabled` reads the four registry values that decide whether
  this account has a Clipboard History and a cloud clipboard (absent or
  unreadable counts as on, so the caveat errs towards warning). The GUI shows a
  settings note with a pointer to the Windows toggle whenever it reports on.

- The GUI trusted the wrong SSH host key. `TrustHost` opened a *second*
  connection to the host and stored the key that connection returned, while the
  fingerprint the user had confirmed came from the first one. An attacker who
  answered the two connections differently got their key written to
  `known_hosts`. The GUI now keeps the key `PrepareClone` captured and stores
  exactly that, with no second probe, and refuses to trust a host that was
  never probed. The CLI already persisted the confirmed key and is unchanged.
- `KnownHostsStore.Add` treated any verification error as "not present" and
  appended, so `App.TrustHost` would overwrite the key of an already-trusted
  host. The two wrappers that tried to prevent this matched on
  `strings.Contains(err.Error(), "host key changed")`, which is why the hole
  survived. `Add` now refuses a changed key with `sshx.ErrHostKeyChanged` and
  the invariant lives in the only writer; both wrappers use `errors.Is`, and the
  error names the stored and the presented fingerprint so a rotation can be
  told apart from an attack.
- Host-key trust is now keyed on `host:port` instead of the bare hostname.
  A key confirmed on `github.com:22` said nothing about `github.com:2222` but
  was accepted there anyway, and any service that answered on a port of an
  already-trusted host was reported as a key change. Records written by earlier
  versions carry a bare host and are read as the default port, so an existing
  `known_hosts` file keeps working. Since `Add` now refuses a second key for a
  host that already has one, storing an extra key type for a host still means
  editing `known_hosts` by hand; hosts that already publish several keys are
  unaffected, see below. Git URLs are read the same way: the port of an
  `ssh://host:port/...` remote is what gets probed and trusted, and the scp-like
  form (`git@host:path`) has no port because there the colon starts the path.
  `passone clone` no longer keeps its own copy of that parser, it asks the app
  for the host:port it is about to connect to.
- `KnownHostsStore.Verify` returned on the first record matching the host, so a
  host that legitimately publishes two keys (ed25519 and rsa, say) was reported
  as changed whenever the negotiated key was not the first one stored. Every
  record for the host is now considered, and a match on any of them verifies.
- The GUI webview now ships a `Content-Security-Policy` in
  `cmd/gui/frontend/index.html`. Wails v2 has no CSP option of its own, so that
  meta tag is the only renderer-side policy the app can have. The webview is
  bound to the full Go bridge (`ShowPassword`, `ImportPGPKeyFile`,
  `ImportSSHKeyFile`, `OpenLocalStore`, `CloneStore`, `ChangeLockPassword`), so
  any script that ran in the renderer would own the vault. The app has no HTML
  injection sink today and stays that way, but the previous safety came from
  the discipline of whoever wrote the component rather than from any control.

### Added

- `tools/checkui` grew the security half of its gate: `raw-html` (`{@html}`),
  `html-sink` (`innerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`,
  `new Function(`), and `missing-csp`/`weak-csp` for the policy in
  `index.html`. A line that has to name one of these without using it is
  suppressed with `// checkui:allow`.

### Fixed

- **Copy username dropped the domain.** Clicking *Username* on an entry named
  `alice@example.com` put `alice` on the clipboard, and the same entry's login
  read as `alice` everywhere else, because `username.FromName` treated the
  domain as a site qualifier to be stripped the way it strips a per-site folder
  from `example.com/alice`. That guess is wrong for the name it was applied to:
  an `@` makes the file name an email address, and the address *is* the login —
  the truncated local part signs in nowhere. An `@` in the file name now yields
  the whole address, in every username-source mode, so *Username* copies
  `alice@example.com` and the button's tooltip reads the same. GH #37.
- A store holding no entries showed "Loading…" forever. The tree placeholder
  keyed on "a listing is running", but rows only ever fill from a listing, so an
  empty store's nav had no branch to reach but the placeholder — and the unlock
  path starts two listings as the vault screen paints. The placeholder now means
  "this store has never been listed", so an empty store says "No entries" and the
  refresh button carries the busy state; a listing that failed counts as
  answered, because the error is on screen.
- Switching stores left the previous store's entries on screen and never
  re-listed. Creating, opening or cloning a store switched the backend's active
  store while the tree kept the old rows and selection, and `expandAll` only ever
  ran once, so the new store's folders rendered collapsed. A switch now clears
  the rows, tree, selection, expanded set and detail pane and re-lists.
- The lock screen cut the paths it exists to show. The Data dir and the store
  were `truncate`d in a narrow column with no `title` and no way to recover what
  was lost. Each is now a row that elides the *middle* of a long path, never the
  tail that identifies it, and carries the full path as its `title`, so a hover
  reads the whole thing out. The keys went back to what they were — the
  fingerprint and the SSH id, not the file they are sealed in: a user confirms
  an identifier and has no reason to point at a sealed key. Directories open in
  File Explorer and keys copy their identifier, one action per row, and `RevealPath`
  only accepts a directory under the PassOne data directory or the configured
  store (case-insensitively, after `filepath.Abs`) and runs `explorer.exe` with
  a bare argv element and no shell. `CopyKeyID` takes the *name* of a key and
  returns that key's own identifier, so the renderer can never use the clipboard
  as a general write-anything channel. GH #36.
- The Open button did nothing. `openExplorer` set `HideWindow`, and
  `explorer.exe` is a client of the shell: it hands its command line to the
  running Explorer and passes its own `STARTUPINFO` on, so `SW_HIDE` asks the
  shell for a hidden window and the folder opens nowhere. The usual reason to
  set `HideWindow` — a console flashing in a GUI app — cannot apply, because
  `explorer.exe` is a GUI-subsystem binary and never allocates one.
- The lock screen's key rows could read "no key" while one was imported.
  `loadSettings` wrote the key *fingerprint* over the value the row shows, which
  is a presence note, so the two meant different things in the same field and the
  row only told the truth after a restart. `AppInfo` now reports the identifier
  itself, and `loadSettings` no longer writes over the lock screen at all.
- Refreshing the entry list reset the sidebar to the top. `refresh()` held
  `listing` for the whole of the `ListPasswords()` call and the template rendered
  that state *instead of* the list, so the `<nav>` scroll container was emptied,
  its `scrollHeight` collapsed and the browser clamped `scrollTop` to 0. The
  placeholder now only appears while there is genuinely nothing to show yet,
  and the list is re-rendered in place: the keyed `{#each}` keeps every surviving
  row's DOM node, so the offset survives. This hit every refresh path, not just
  removal (GH #33).
- Three data races on shared `App` state, all reachable in the GUI because
  Wails dispatches every binding call on its own goroutine: `StorePath()` read
  `cfg.StorePath` unlocked while `OpenLocalStore` wrote it,
  `autoCommit`/`CommitPassword` read the commit author unlocked while
  `SetGitAuthor` wrote it (a 2-word `string` header, so the read can tear), and
  `ImportPGPKey` replaced the OpenPGP entity list unlocked while the idle
  auto-lock goroutine reads it. Config reads now take `a.mu` or go through a
  locked `gitAuthor()` accessor. CI now runs `go test -race ./...` with
  `CGO_ENABLED=1`; the idle timer interval moved from a mutable package global
  to per-`App` state so the test that shortens it cannot race another test's
  timer goroutine.

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