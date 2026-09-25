# PassOne

> A self-contained Windows client for the [`pass`](https://www.passwordstore.org/) password store. No GnuPG, Git, or SSH binaries required.

[![CI](https://github.com/oxcafedead/passone/actions/workflows/ci.yml/badge.svg)](https://github.com/oxcafedead/passone/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/oxcafedead/passone)](./go.mod)

PassOne is a native **Windows desktop app** for working with password-store repositories (the `pass` format: `.gpg` files, `.gpg-id` recipients, and git). It is primarily used through its GUI.
Unlike most clients, it does **not** need `gpg.exe`, `git.exe`, or `ssh.exe` installed — all cryptography, git transport, and SSH are implemented in Go and embedded in a single binary.

- **GUI (recommended)** — `passone-ui.exe`, a Wails v2 + Svelte 5 desktop app with a system tray, auto-lock, and light/dark themes.
- **CLI** — `passone.exe`, a small command-line interface kept around for scripting and compatibility. It started as a proof of concept and is not the primary way to use PassOne.

> ⚠️ Windows-only. PassOne uses DPAPI, the system tray, Windows theme registry values, and the Win32 clipboard.

![PassOne Screenshot in light and dark themes](./passone-screenshot.png)

---

## Features

- 🪟 **Native GUI** — system tray, single window, light/dark theme support, single-instance lock.
- 🔐 **OpenPGP built-in** — import private PGP keys and encrypt/decrypt `*.gpg` files via [`ProtonMail/go-crypto`](https://github.com/ProtonMail/go-crypto).
- 🗝️ **SSH built-in** — import OpenSSH private keys (`ed25519`, RSA), verify host keys, manage `known_hosts`, and sync over SSH via [`go-git`](https://github.com/go-git/go-git).
- 📂 **Pass-compatible** — reads and writes standard pass stores: `.gpg-id`, folders, and `*.gpg` files.
- 🔄 **Git sync** — `clone`, `status`, and `sync` (fetch/pull/push) without an external git installation.
- 🔒 **Security-first** — keys are sealed with Windows DPAPI; decrypted key material lives in memory only during an unlocked session; idle auto-lock; best-effort memory zeroing.
- 📋 **Clipboard auto-clear** — copied passwords are removed from the clipboard after a configurable timeout.

---

## Installation

### Download a release

Prebuilt binaries are published as GitHub Releases for every `v*` tag:

- `passone-cli-vX.Y.Z-windows-amd64.zip` — CLI (`passone.exe`)
- `passone-ui-vX.Y.Z-windows-amd64.zip` — GUI (`passone-ui.exe`)
- `passone-all-vX.Y.Z-windows-amd64.zip` — GUI **and** CLI

Releases carry a `SHA256SUMS.txt` checksum file. See
[RELEASES.md](./RELEASES.md) for the full artifact list and verification
commands.

### From source

Requirements:

- Windows 10/11 (x64)
- [Go](https://go.dev/) 1.26+
- [Node.js](https://nodejs.org/) + npm (for the GUI)
- [Wails CLI](https://wails.io/docs/gettingstarted/installation) (for the GUI)

Build the GUI:

```powershell
cd cmd/gui/frontend
npm ci
npm run build
cd ../../..

cd cmd/gui
wails build -skipbindings -s -clean
cd ../..
# The icon/manifest/version resources are only embedded when packaging runs
# (never pass -nopackage). Verify the exe really carries the icon:
go run ./tools/checkicon cmd/gui/build/bin/passone-ui.exe
```

The GUI binary will be at `cmd/gui/build/bin/passone-ui.exe`.

Build the CLI (optional):

```powershell
go build -o passone.exe ./cmd/app
```

---

## Quick start

1. Run `passone-ui.exe`.
2. Import your PGP and SSH keys in the settings screen.
3. Open an existing pass store or clone one over SSH.
4. Unlock the store; browse, copy, add, and edit passwords from the app.
5. PassOne lives in the system tray — closing the window hides it; quit from the tray menu.
6. The session auto-locks after a period of inactivity (configurable).

Data is stored in `%LOCALAPPDATA%\PassOne` by default. You can override this with the `PASSONE_DIR` environment variable.

---

## Security

- **Key storage:** private keys are stored encrypted (AES-256-GCM) in `%LOCALAPPDATA%\PassOne`. The sealing key is protected by Windows DPAPI for the current user.
- **Memory:** decrypted keys exist in memory only during an unlocked session. They are dropped on lock or idle timeout, with best-effort buffer zeroing.
- **Host verification:** SSH host keys are captured on first contact and stored; if a host key changes, the connection is refused.
- **Clipboard:** copied passwords are automatically removed from the clipboard after the configured timeout.
- **Atomic writes:** password files are written to a temporary file and only moved into place after encryption succeeds.

---

## CLI (optional)

The CLI predates the GUI and is kept mainly for scripting; it exposes the same core functionality.

```powershell
.\passone.exe init
.\passone.exe import-pgp-key .\private-key.asc
.\passone.exe open .\pass-store
.\passone.exe unlock
.\passone.exe list
.\passone.exe show github/personal
.\passone.exe copy github/personal
.\passone.exe lock
```

Full command reference:

```text
Usage: passone <command> [arguments]

Store / keys
  init                         Create the application data directory
  import-pgp-key <file>        Import an armored OpenPGP private key
  import-ssh-key <file>        Import an OpenSSH private key
  public-key                   Print the SSH public key (add it to GitHub)
  open <dir>                   Open an existing local pass store
  clone <url> [dir]            Clone a git pass store over SSH
  test-ssh <host>              Verify the host key and test SSH auth
  known-hosts                  List trusted SSH host keys

Passwords
  list [prefix]                List password paths (no decryption required)
  show <path> [--full]         Show the password (first line unless --full)
  copy <path>                  Copy the password to the clipboard (auto-clears)
  save <path> <file>           Save encrypted plaintext from a file ('-' = stdin)
  edit <path> [--no-commit]    Edit, re-encrypt atomically, then commit
  rm   <path>                  Remove a password entry

Git
  status                       Git status of the store
  sync                         Fetch, merge, and push

Session
  unlock                       Unlock stored keys
  lock                         Drop decrypted keys from memory
  state                        Show lock state and configuration
  config                       Show configuration
```

---

## Development

PassOne is written in Go with a Svelte 5 frontend. See [AGENTS.md](./AGENTS.md) for build commands, test instructions, and repository notes for contributors.

---

## Contributing

Issues and pull requests are welcome. Please run the test suite and linter before submitting a PR — details are in [AGENTS.md](./AGENTS.md).

---

## License

See the `LICENSE` file (to be added).
