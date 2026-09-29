package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/oxcafedead/passone/internal/cliputil"
	"github.com/oxcafedead/passone/internal/version"
)

const usage = `PassOne - native Windows pass client (CLI proof of concept)

Usage: passone <command> [arguments]

Store / keys
  init                         Create the application data directory
  gen-pgp-key [name] [email]   Generate a new OpenPGP key (no gpg needed)
  init-store <dir> [remote]    Create a new local pass store (optional SSH git remote)
  import-pgp-key <file>        Import an armored OpenPGP private key
  import-ssh-key <file>        Import an OpenSSH private key (~/.ssh/id_ed25519)
  public-key                   Print the SSH public key (add it to GitHub)
  open <dir>                   Open an existing local pass store
  clone <url> [dir]            Clone a git pass store over SSH (e.g. git@github.com:user/pass.git)
  test-ssh <host>              Verify the host key (trust on first contact) and test SSH auth
  known-hosts                  List trusted SSH host keys

Passwords
  list [prefix]                List password paths (no decryption)
  show <path> [--full]         Show the password (first line unless --full)
  totp <path>                  Copy the current TOTP code to the clipboard
  copy <path>                  Copy the password to the clipboard (auto-clears)
  save <path> <file>           Save encrypted plaintext from a file ('-' = stdin)
  edit <path> [--no-commit]    Edit plaintext, re-encrypt (atomic), then commit

Git
  status                       Git status of the store
  sync                         Fetch, merge and push

Session
  unlock                        Unlock stored keys
  lock                          Lock: drop decrypted keys from memory
  state                         Show lock state and configuration
  config                        Show configuration

Other
  version                        Print the application version
  help                           Show this help

Security notes:
  - Private keys and passphrases are kept in memory only while unlocked.
  - Keys are stored locally sealed with AES-256-GCM; the sealing key is derived
    from the master passphrase (Argon2id) and never stored on disk.
  - 5-minute idle timeout (configurable in config.json) drops all key material.
  - Copied secrets are marked so Windows keeps them out of Clipboard History and
    the cloud clipboard, then removed from the clipboard after a timeout.
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}
	cmd, args := os.Args[1], os.Args[2:]

	if cmd == "--version" || cmd == "-version" || cmd == "-v" {
		_, _ = fmt.Printf("PassOne %s\n", version.Version)
		return
	}

	e := &env{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
	// A clipboard clear happens on a timer after the copy command returned, so
	// its failures are reported here rather than through a return value.
	cliputil.SetWarningFunc(func(msg string) {
		_, _ = fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
	})
	a, err := createApp()
	if err != nil {
		fatal(err)
	}
	e.app = a

	run, ok := commands()[cmd]
	if !ok {
		_, _ = fmt.Fprintf(e.stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
	if err := run(e, args); err != nil {
		fatal(err)
	}
}

func printUsage() { _, _ = fmt.Print(usage) }

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if strings.EqualFold(a, name) || strings.EqualFold(a, "-"+name) || strings.EqualFold(a, "--"+name) {
			return true
		}
	}
	return false
}

func positional(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") && a != "-" {
			continue
		}
		out = append(out, a)
	}
	return out
}
