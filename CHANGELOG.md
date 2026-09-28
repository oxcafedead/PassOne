# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

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