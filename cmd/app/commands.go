package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/oxcafedead/passone/internal/app"
	"github.com/oxcafedead/passone/internal/cliputil"
	"github.com/oxcafedead/passone/internal/pgp"
	"github.com/oxcafedead/passone/internal/sshx"
	"golang.org/x/term"
)

// env carries the application instance and streams so commands are testable.
type env struct {
	app    *app.App
	stdin  *os.File
	stdout *os.File
	stderr *os.File
}

func createApp() (*app.App, error) {
	return app.New()
}

func commands() map[string]func(*env, []string) error {
	return map[string]func(*env, []string) error{
		"help": func(e *env, _ []string) error { printUsage(); return nil },

		"init":           cmdInit,
		"import-pgp-key": cmdImportPGP,
		"import-ssh-key": cmdImportSSH,
		"public-key":     cmdPublicKey,
		"open":           cmdOpen,
		"clone":          cmdClone,
		"test-ssh":       cmdTestSSH,
		"known-hosts":    cmdKnownHosts,

		"list": cmdList,
		"show": cmdShow,
		"copy": cmdCopy,
		"save": cmdSave,
		"edit": cmdEdit,
		"rm":   cmdRemove,

		"status": cmdStatus,
		"sync":   cmdSync,

		"unlock": cmdUnlock,
		"lock":   cmdLock,
		"state":  cmdState,
		"config": cmdConfig,
	}
}

func cmdInit(e *env, _ []string) error {
	fmt.Fprintf(e.stdout, "Application data directory: %s\n", e.app.DataDir())
	return nil
}

func cmdImportPGP(e *env, args []string) error {
	pos := positional(args)
	if len(pos) < 1 {
		return fmt.Errorf("import-pgp-key requires a file argument (ASCII-armored PGP private key)")
	}
	block, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	defer zero(block)

	fmt.Fprintln(e.stdout, "Parsing key...")
	infos, err := e.app.ImportPGPKey(block, readPassphrase(e, "OpenPGP key passphrase: "))
	if err != nil {
		return err
	}
	printKeyInfos(e, infos)
	fmt.Fprintln(e.stdout, "Key imported and stored locally (sealed with the application key).")
	return nil
}

func cmdImportSSH(e *env, args []string) error {
	pos := positional(args)
	if len(pos) < 1 {
		return fmt.Errorf("import-ssh-key requires a file argument (OpenSSH private key)")
	}
	pem, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	defer zero(pem)

	k, err := e.app.ImportSSHKey(pem, readPassphrase(e, "SSH key passphrase: "))
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "SSH key imported:\n  algorithm: %s\n  fingerprint: %s\n", k.Algorithm(), k.Fingerprint())
	fmt.Fprintln(e.stdout, "Stored locally (sealed with the application key).")
	return nil
}

func cmdPublicKey(e *env, _ []string) error {
	if err := ensureSSHUnlocked(e); err != nil {
		return err
	}
	pub, err := e.app.SSHPublicKey()
	if err != nil {
		return err
	}
	defer zero(pub)
	fmt.Fprint(e.stdout, string(pub))
	return nil
}

func cmdOpen(e *env, args []string) error {
	pos := positional(args)
	if len(pos) < 1 {
		return fmt.Errorf("open requires a directory argument")
	}
	return e.app.OpenLocalStore(pos[0])
}

func cmdClone(e *env, args []string) error {
	pos := positional(args)
	if len(pos) < 1 {
		return fmt.Errorf("clone requires an SSH git URL argument (git@github.com:user/pass.git)")
	}
	url := pos[0]
	dir := ""
	if len(pos) > 1 {
		dir = pos[1]
	}
	// Clone needs both keys: SSH for transport, OpenPGP to validate the store.
	if err := ensureUnlocked(e); err != nil {
		return err
	}
	if err := ensureHostTrusted(e, hostportOf(gitHost(url))); err != nil {
		return err
	}
	if err := e.app.CloneStore(url, dir); err != nil {
		return err
	}
	fmt.Fprintln(e.stdout, "Store cloned and opened.")
	return nil
}

func cmdTestSSH(e *env, args []string) error {
	pos := positional(args)
	if len(pos) < 1 {
		return fmt.Errorf("test-ssh requires a host argument (e.g. github.com)")
	}
	hostport := hostportOf(pos[0])
	if err := ensureSSHUnlocked(e); err != nil {
		return err
	}
	if err := ensureHostTrusted(e, sshx.NormalizeHost(hostport)); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "Authenticating to %s ...\n", hostport)
	if err := e.app.TestSSH(hostport); err != nil {
		return fmt.Errorf("SSH authentication failed: %w", err)
	}
	fmt.Fprintln(e.stdout, "SSH authentication succeeded.")
	return nil
}

func cmdKnownHosts(e *env, _ []string) error {
	lines := e.app.KnownHostsList()
	if len(lines) == 0 {
		fmt.Fprintln(e.stdout, "No trusted SSH hosts yet.")
		return nil
	}
	for _, l := range lines {
		fmt.Fprintln(e.stdout, l)
	}
	return nil
}

func cmdList(e *env, args []string) error {
	prefix := ""
	if p := positional(args); len(p) > 0 {
		prefix = p[0]
	}
	passwords, err := e.app.ListPasswords()
	if err != nil {
		return err
	}
	for _, p := range passwords {
		if prefix == "" || strings.HasPrefix(p, prefix) {
			fmt.Fprintln(e.stdout, p)
		}
	}
	return nil
}

func cmdShow(e *env, args []string) error {
	pos := positional(args)
	if len(pos) < 1 {
		return fmt.Errorf("show requires a password path")
	}
	if err := ensurePGPUnlocked(e); err != nil {
		return err
	}
	plaintext, err := e.app.ShowPassword(pos[0])
	if err != nil {
		return err
	}
	defer zero(plaintext)
	return printPlaintext(e, plaintext, hasFlag(args, "--full") || hasFlag(args, "--all"))
}

func printPlaintext(e *env, plaintext []byte, full bool) error {
	if full {
		fmt.Fprint(e.stdout, string(plaintext))
		if len(plaintext) == 0 || plaintext[len(plaintext)-1] != '\n' {
			fmt.Fprintln(e.stdout)
		}
		return nil
	}
	text := string(plaintext)
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		fmt.Fprintln(e.stdout, text[:i])
	} else {
		fmt.Fprintln(e.stdout, text)
	}
	return nil
}

func cmdCopy(e *env, args []string) error {
	pos := positional(args)
	if len(pos) < 1 {
		return fmt.Errorf("copy requires a password path")
	}
	if err := ensurePGPUnlocked(e); err != nil {
		return err
	}
	plaintext, err := e.app.ShowPassword(pos[0])
	if err != nil {
		return err
	}
	defer zero(plaintext)
	text := string(plaintext)
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	cfg := e.app.Config()
	clearSeconds := cfg.ClipboardClearSeconds
	if err := cliputil.Copied(text, clearSeconds); err != nil {
		return fmt.Errorf("unable to write to the Windows clipboard: %w", err)
	}
	fmt.Fprintf(e.stdout, "Password copied to clipboard for %d seconds.\n", clearSeconds)
	return nil
}

func cmdSave(e *env, args []string) error {
	pos := positional(args)
	if len(pos) < 2 {
		return fmt.Errorf("save requires <path> <file> ('-' reads from stdin)")
	}
	if err := ensurePGPUnlocked(e); err != nil {
		return err
	}
	var plaintext []byte
	var err error
	if pos[1] == "-" {
		plaintext, err = readAllStdin(e)
	} else {
		plaintext, err = os.ReadFile(pos[1])
	}
	if err != nil {
		return err
	}
	defer zero(plaintext)
	if err := e.app.SavePassword(pos[0], plaintext); err != nil {
		return err
	}
	if err := e.app.CommitPassword(pos[0]); err != nil {
		fmt.Fprintf(e.stderr, "warning: encrypted file saved, but commit failed: %v\n", err)
	}
	fmt.Fprintf(e.stdout, "Saved %s (encrypted, atomic replace, committed).\n", pos[0])
	return nil
}

func cmdEdit(e *env, args []string) error {
	pos := positional(args)
	if len(pos) < 1 {
		return fmt.Errorf("edit requires a password path")
	}
	if err := ensurePGPUnlocked(e); err != nil {
		return err
	}
	name := pos[0]
	oldPlaintext, err := e.app.ShowPassword(name)
	if err != nil {
		// Allow creating a new password path.
		if os.IsNotExist(err) || strings.Contains(err.Error(), "password not found") {
			oldPlaintext = nil
		} else {
			return err
		}
	}
	defer zero(oldPlaintext)

	newPlaintext, err := launchEditor(oldPlaintext)
	if err != nil {
		return err
	}
	defer zero(newPlaintext)

	if oldPlaintext != nil && string(newPlaintext) == string(oldPlaintext) {
		fmt.Fprintln(e.stdout, "No changes to edit.")
		return nil
	}
	if err := e.app.SavePassword(name, newPlaintext); err != nil {
		return err
	}
	if !hasFlag(args, "--no-commit") {
		if err := e.app.CommitPassword(name); err != nil {
			fmt.Fprintf(e.stderr, "warning: encrypted file saved, but commit failed: %v\n", err)
		}
	}
	fmt.Fprintf(e.stdout, "Saved %s.\n", name)
	return nil
}

func cmdRemove(e *env, args []string) error {
	pos := positional(args)
	if len(pos) < 1 {
		return fmt.Errorf("rm requires a password path")
	}
	if err := ensureUnlocked(e); err != nil {
		return err
	}
	if err := e.app.RemovePassword(pos[0]); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "Removed %s.\n", pos[0])
	return nil
}

func cmdStatus(e *env, _ []string) error {
	st, err := e.app.Status()
	if err != nil {
		return err
	}
	if strings.TrimSpace(st) == "" {
		fmt.Fprintln(e.stdout, "working tree clean")
		return nil
	}
	fmt.Fprint(e.stdout, st)
	return nil
}

func cmdSync(e *env, _ []string) error {
	if err := ensureSSHUnlocked(e); err != nil {
		return err
	}
	if err := e.app.Sync(); err != nil {
		return err
	}
	fmt.Fprintln(e.stdout, "Sync complete.")
	return nil
}

func cmdUnlock(e *env, _ []string) error {
	if e.app.IsUnlocked() {
		fmt.Fprintln(e.stdout, "Already unlocked.")
		return nil
	}
	return unlockPrompt(e)
}

func cmdLock(e *env, _ []string) error {
	e.app.Lock()
	fmt.Fprintln(e.stdout, "Locked.")
	return nil
}

func cmdState(e *env, _ []string) error {
	cfg := e.app.Config()
	fmt.Fprintf(e.stdout, "Unlocked:         %v\n", e.app.IsUnlocked())
	fmt.Fprintf(e.stdout, "Store:            %s\n", orNone(cfg.StorePath))
	fmt.Fprintf(e.stdout, "Git remote:       %s\n", orNone(cfg.GitRemote))
	fmt.Fprintf(e.stdout, "PGP fingerprint:  %s\n", orNone(cfg.PGPKeyFingerprint))
	fmt.Fprintf(e.stdout, "SSH key id:       %s\n", orNone(cfg.SSHKeyID))
	fmt.Fprintf(e.stdout, "Auto-lock:        %d min\n", cfg.AutoLockMinutes)
	fmt.Fprintf(e.stdout, "Clipboard clear:  %d s\n", cfg.ClipboardClearSeconds)
	fmt.Fprintf(e.stdout, "Data dir:         %s\n", e.app.DataDir())
	return nil
}

func cmdConfig(e *env, _ []string) error {
	cfg := e.app.Config()
	fmt.Fprintf(e.stdout, "storePath             = %q\n", cfg.StorePath)
	fmt.Fprintf(e.stdout, "gitRemote             = %q\n", cfg.GitRemote)
	fmt.Fprintf(e.stdout, "sshKeyId              = %q\n", cfg.SSHKeyID)
	fmt.Fprintf(e.stdout, "pgpKeyFingerprint     = %q\n", cfg.PGPKeyFingerprint)
	fmt.Fprintf(e.stdout, "autoLockMinutes       = %d\n", cfg.AutoLockMinutes)
	fmt.Fprintf(e.stdout, "clipboardClearSeconds = %d\n", cfg.ClipboardClearSeconds)
	fmt.Fprintf(e.stdout, "gitAuthorName         = %q\n", cfg.GitAuthorName)
	fmt.Fprintf(e.stdout, "gitAuthorEmail        = %q\n", cfg.GitAuthorEmail)
	return nil
}

// ---- shared helpers ----

func ensureUnlocked(e *env) error {
	if e.app.IsUnlocked() {
		return nil
	}
	return unlockPrompt(e)
}

// ensurePGPUnlocked unlocks only the OpenPGP key. Used for local operations
// (show/copy/save/edit) that do not touch git.
func ensurePGPUnlocked(e *env) error {
	if e.app.IsUnlocked() {
		return nil
	}
	var pgpPass []byte
	if e.app.HasStoredPGPKey() {
		need, err := e.app.PGPKeyNeedsPassphrase()
		if err != nil {
			return err
		}
		if need {
			pgpPass = readPassphrase(e, "OpenPGP key passphrase: ")
			if len(pgpPass) == 0 {
				return fmt.Errorf("the OpenPGP key is passphrase-protected; a passphrase is required")
			}
		}
	}
	if err := e.app.UnlockPGP(pgpPass); err != nil {
		return err
	}
	return nil
}

// ensureSSHUnlocked unlocks only the SSH key. Used by public-key and to
// prepare SSH-backed commands that already have their OpenPGP key loaded.
func ensureSSHUnlocked(e *env) error {
	if e.app.IsUnlocked() && e.app.HasSSHKeyLoaded() {
		return nil
	}
	var sshPass []byte
	if e.app.HasStoredSSHKey() {
		need, err := e.app.SSHKeyNeedsPassphrase()
		if err != nil {
			return err
		}
		if need {
			sshPass = readPassphrase(e, "SSH key passphrase: ")
			if len(sshPass) == 0 {
				return fmt.Errorf("the SSH key is passphrase-protected; a passphrase is required")
			}
		}
	}
	if err := e.app.UnlockSSH(sshPass); err != nil {
		return err
	}
	return nil
}

func unlockPrompt(e *env) error {
	var pgpPass, sshPass []byte

	if e.app.HasStoredPGPKey() {
		need, err := e.app.PGPKeyNeedsPassphrase()
		if err != nil {
			return err
		}
		if need {
			pgpPass = readPassphrase(e, "OpenPGP key passphrase: ")
		}
	}
	if e.app.HasStoredSSHKey() {
		need, err := e.app.SSHKeyNeedsPassphrase()
		if err != nil {
			return err
		}
		if need {
			sshPass = readPassphrase(e, "SSH key passphrase: ")
			if len(sshPass) == 0 {
				return fmt.Errorf("the SSH key is passphrase-protected; a passphrase is required")
			}
		}
	}
	if err := e.app.Unlock(pgpPass, sshPass); err != nil {
		return err
	}
	return nil
}

func readPassphrase(e *env, prompt string) []byte {
	fmt.Fprint(e.stderr, prompt)
	if term.IsTerminal(int(syscall.Stdin)) {
		p, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintln(e.stdout)
			return nil
		}
		fmt.Fprintln(e.stdout)
		return p
	}
	r := bufio.NewReader(e.stdin)
	line, _ := r.ReadBytes('\n')
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return line
}

// ensureHostTrusted captures the host key, prompting the user on first contact.
func ensureHostTrusted(e *env, hostport string) error {
	pub, known, err := e.app.HostCheck(hostportOf(hostport))
	if err != nil && strings.Contains(err.Error(), "host key changed") {
		return fmt.Errorf("SSH host key CHANGED for %s - possible man-in-the-middle; not trusting automatically", sshx.NormalizeHost(hostport))
	}
	if err != nil {
		return err
	}
	if known {
		fmt.Fprintf(e.stdout, "Host key for %s already verified (%s %s).\n",
			sshx.NormalizeHost(hostport), sshx.KeyAlgorithm(pub), sshx.HostKeyFingerprint(pub))
		return nil
	}
	fmt.Fprintf(e.stdout, "\nUnknown SSH host %s\n\n  algorithm:   %s\n  fingerprint: %s\n\n",
		sshx.NormalizeHost(hostport), sshx.KeyAlgorithm(pub), sshx.HostKeyFingerprint(pub))
	ok, err := askYesNo(e, "Trust this host key? [y/N] ")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("host key not trusted; aborting")
	}
	if err := e.app.TrustHost(hostport, pub); err != nil {
		return err
	}
	fmt.Fprintln(e.stdout, "Host key recorded.")
	return nil
}

func askYesNo(e *env, prompt string) (bool, error) {
	fmt.Fprint(e.stderr, prompt)
	r := bufio.NewReader(e.stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes", nil
}

func hostportOf(host string) string {
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":22"
}

func gitHost(url string) string {
	if i := strings.LastIndex(url, "@"); i >= 0 {
		rest := url[i+1:]
		for _, split := range []string{":", "/"} {
			if j := strings.Index(rest, split); j >= 0 {
				return rest[:j]
			}
		}
		return rest
	}
	return url
}

func printKeyInfos(e *env, infos []*pgp.KeyInfo) {
	for _, info := range infos {
		fmt.Fprintf(e.stdout, "  fingerprint: %s\n", info.Fingerprint)
		for _, uid := range info.UserIDs {
			fmt.Fprintf(e.stdout, "  user id:     %s\n", uid)
		}
	}
}

func readAllStdin(e *env) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := e.stdin.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			break
		}
	}
	return out, nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
