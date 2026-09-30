package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/oxcafedead/passone/internal/app"
	"github.com/oxcafedead/passone/internal/cliputil"
	"github.com/oxcafedead/passone/internal/sshx"
	"github.com/oxcafedead/passone/internal/store"
	"golang.org/x/crypto/ssh"
)

const testPGPPassphrase = "cmd-app-test-pass"
const testLockPass = "cmd-app-test-lock"

// newTestEnv returns an env bound to an isolated PASSONE_DIR and temp stdout/stderr.
// Optional stdinContent is written to a temp file used as stdin.
func newTestEnv(t *testing.T, stdinContent ...string) *env {
	t.Helper()
	t.Setenv("PASSONE_DIR", t.TempDir())
	a, err := app.New()
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	out, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	errFile, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	content := ""
	if len(stdinContent) > 0 {
		content = stdinContent[0]
	}
	in := testFile(t, content)
	t.Cleanup(func() {
		_ = out.Close()
		_ = errFile.Close()
		_ = in.Close()
	})
	return &env{app: a, stdin: in, stdout: out, stderr: errFile}
}

// readOut returns everything written to f since it was opened/reset.
func readOut(t *testing.T, f *os.File) string {
	t.Helper()
	if err := f.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

// armoredPGPTestKey generates a passphrase-protected OpenPGP secret key.
func armoredPGPTestKey(t *testing.T) []byte {
	t.Helper()
	cfg := &packet.Config{}
	e, err := openpgp.NewEntity("Cmd App Tester", "", "cmdapp@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	if err := e.EncryptPrivateKeys([]byte(testPGPPassphrase), cfg); err != nil {
		t.Fatalf("EncryptPrivateKeys: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func pgpFingerprint(t *testing.T, armored []byte) string {
	t.Helper()
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	return strings.ToUpper(hex.EncodeToString(el[0].PrimaryKey.Fingerprint))
}

func sshTestKey(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "cmdapp@example.com")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func sshEncryptedTestKey(t *testing.T, passphrase []byte) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "cmdapp@example.com", passphrase)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// setupStore creates and opens a pass store for the app, importing a PGP key.
// The returned env is still locked; callers must unlock when needed.
func setupStore(t *testing.T, e *env) (storeDir string) {
	t.Helper()
	armored := armoredPGPTestKey(t)
	fp := pgpFingerprint(t, armored)
	if _, err := e.app.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	storeDir = filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := e.app.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	return storeDir
}

// unlock unlocks the app's PGP key using the lock password.
func unlockPGP(t *testing.T, e *env) {
	t.Helper()
	if err := e.app.UnlockPGP([]byte(testLockPass)); err != nil {
		t.Fatalf("UnlockPGP: %v", err)
	}
}

func TestCmdList(t *testing.T) {
	t.Run("no store open", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdList(e, nil); err == nil {
			t.Fatal("expected error when no store is open")
		}
	})

	t.Run("empty store", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		if err := cmdList(e, nil); err != nil {
			t.Fatalf("cmdList: %v", err)
		}
		if got := strings.TrimSpace(readOut(t, e.stdout)); got != "" {
			t.Fatalf("output = %q", got)
		}
	})

	t.Run("lists entries", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := e.app.SavePassword("github/personal", []byte("secret\n")); err != nil {
			t.Fatalf("SavePassword: %v", err)
		}
		if err := e.app.SavePassword("work/jira", []byte("secret\n")); err != nil {
			t.Fatalf("SavePassword: %v", err)
		}
		if err := cmdList(e, nil); err != nil {
			t.Fatalf("cmdList: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "github/personal") || !strings.Contains(out, "work/jira") {
			t.Fatalf("output = %q", out)
		}
	})

	t.Run("filters prefix", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := e.app.SavePassword("github/personal", []byte("secret\n")); err != nil {
			t.Fatalf("SavePassword: %v", err)
		}
		if err := e.app.SavePassword("work/jira", []byte("secret\n")); err != nil {
			t.Fatalf("SavePassword: %v", err)
		}
		if err := cmdList(e, []string{"github"}); err != nil {
			t.Fatalf("cmdList with prefix: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "github/personal") {
			t.Fatalf("output missing github/personal: %q", out)
		}
		if strings.Contains(out, "work/jira") {
			t.Fatalf("output should not contain work/jira: %q", out)
		}
	})
}

func TestCmdShow(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdShow(e, nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("locked without passphrase", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		if err := cmdShow(e, []string{"github/personal"}); err == nil {
			t.Fatal("expected error when locked")
		}
	})

	t.Run("password not found", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := cmdShow(e, []string{"missing"}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("shows first line by default", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := e.app.SavePassword("site", []byte("hunter2\nurl: https://example.com\n")); err != nil {
			t.Fatalf("SavePassword: %v", err)
		}
		if err := cmdShow(e, []string{"site"}); err != nil {
			t.Fatalf("cmdShow: %v", err)
		}
		out := strings.TrimSpace(readOut(t, e.stdout))
		if out != "hunter2" {
			t.Fatalf("output = %q", out)
		}
	})

	t.Run("shows full plaintext", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := e.app.SavePassword("site", []byte("hunter2\nurl: https://example.com\n")); err != nil {
			t.Fatalf("SavePassword: %v", err)
		}
		if err := cmdShow(e, []string{"--full", "site"}); err != nil {
			t.Fatalf("cmdShow: %v", err)
		}
		out := readOut(t, e.stdout)
		want := "hunter2\nurl: https://example.com\n"
		if out != want {
			t.Fatalf("output = %q, want %q", out, want)
		}
	})
}

func TestCmdCopy(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdCopy(e, nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("locked", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		if err := cmdCopy(e, []string{"site"}); err == nil {
			t.Fatal("expected error when locked")
		}
	})

	t.Run("copies first line to clipboard", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := e.app.SavePassword("site", []byte("hunter2\nurl: https://example.com\n")); err != nil {
			t.Fatalf("SavePassword: %v", err)
		}
		if err := cmdCopy(e, []string{"site"}); err != nil {
			t.Fatalf("cmdCopy: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "Password copied to clipboard") {
			t.Fatalf("output = %q", out)
		}
	})

	// The history formats have to be on the item itself, because Windows snapshots
	// it as it is set. When that marker goes on the user is told so, and nothing
	// is left unsaid: an unmarked copy reaches Clipboard History and the cloud.
	t.Run("reports the history exclusion when the marker went on", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := e.app.SavePassword("site", []byte("hunter2\n")); err != nil {
			t.Fatalf("SavePassword: %v", err)
		}
		var warned []string
		cliputil.SetWarningFunc(func(msg string) { warned = append(warned, msg) })
		t.Cleanup(func() { cliputil.SetWarningFunc(nil) })

		if err := cmdCopy(e, []string{"site"}); err != nil {
			t.Fatalf("cmdCopy: %v", err)
		}
		if out := readOut(t, e.stdout); !strings.Contains(out, "Marked to be kept out of Windows Clipboard History") {
			t.Fatalf("output = %q, want the exclusion reported", out)
		}
		if errOut := readOut(t, e.stderr); strings.Contains(errOut, "Clipboard History") {
			t.Fatalf("stderr = %q, want no caveat when the marker went on", errOut)
		}
		if len(warned) != 0 {
			t.Fatalf("warnings = %v, want none", warned)
		}
	})
}

func TestCmdSave(t *testing.T) {
	t.Run("missing args", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdSave(e, []string{"site"}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("locked", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		if err := cmdSave(e, []string{"site", "-"}); err == nil {
			t.Fatal("expected error when locked")
		}
	})

	t.Run("from file", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		plainFile := filepath.Join(t.TempDir(), "plain.txt")
		if err := os.WriteFile(plainFile, []byte("fromfile\nurl: x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cmdSave(e, []string{"site", plainFile}); err != nil {
			t.Fatalf("cmdSave: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "Saved site") {
			t.Fatalf("output = %q", out)
		}
		got, err := e.app.ShowPassword("site")
		if err != nil {
			t.Fatalf("ShowPassword: %v", err)
		}
		if string(got) != "fromfile\nurl: x\n" {
			t.Fatalf("plaintext = %q", got)
		}
	})

	t.Run("from stdin", func(t *testing.T) {
		e := newTestEnv(t, "fromstdin\nurl: y\n")
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := cmdSave(e, []string{"site", "-"}); err != nil {
			t.Fatalf("cmdSave: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "Saved site") {
			t.Fatalf("output = %q", out)
		}
		got, err := e.app.ShowPassword("site")
		if err != nil {
			t.Fatalf("ShowPassword: %v", err)
		}
		if string(got) != "fromstdin\nurl: y\n" {
			t.Fatalf("plaintext = %q", got)
		}
	})

	t.Run("missing source file", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := cmdSave(e, []string{"site", filepath.Join(t.TempDir(), "missing.txt")}); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestCmdEditValidation(t *testing.T) {
	e := newTestEnv(t)
	if err := cmdEdit(e, nil); err == nil {
		t.Fatal("expected error when no path given")
	}
}

func TestCmdRemove(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdRemove(e, nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("locked", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		if err := cmdRemove(e, []string{"site"}); err == nil {
			t.Fatal("expected error when locked")
		}
	})

	t.Run("removes password", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := e.app.SavePassword("site", []byte("secret\n")); err != nil {
			t.Fatalf("SavePassword: %v", err)
		}
		if err := cmdRemove(e, []string{"site"}); err != nil {
			t.Fatalf("cmdRemove: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "Removed site") {
			t.Fatalf("output = %q", out)
		}
		if _, err := e.app.ShowPassword("site"); err == nil {
			t.Fatal("expected password to be gone")
		}
	})
}

func TestCmdMove(t *testing.T) {
	t.Run("missing paths", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdMove(e, nil); err == nil {
			t.Fatal("expected error")
		}
		if err := cmdMove(e, []string{"site"}); err == nil {
			t.Fatal("expected error with only one path")
		}
	})

	t.Run("locked", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		if err := cmdMove(e, []string{"site", "work/site"}); err == nil {
			t.Fatal("expected error when locked")
		}
	})

	t.Run("moves password", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := e.app.SavePassword("site", []byte("secret\nnotes\n")); err != nil {
			t.Fatalf("SavePassword: %v", err)
		}
		if err := cmdMove(e, []string{"site", "work/site"}); err != nil {
			t.Fatalf("cmdMove: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "Moved site to work/site") {
			t.Fatalf("output = %q", out)
		}
		// The entry moved with its content intact.
		plain, err := e.app.ShowPassword("work/site")
		if err != nil {
			t.Fatalf("ShowPassword: %v", err)
		}
		if string(plain) != "secret\nnotes\n" {
			t.Fatalf("moved entry = %q", plain)
		}
		if _, err := e.app.ShowPassword("site"); err == nil {
			t.Fatal("expected the old path to be gone")
		}
	})

	t.Run("refuses an occupied target", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		for _, n := range []string{"a", "b"} {
			if err := e.app.SavePassword(n, []byte("secret-"+n)); err != nil {
				t.Fatalf("SavePassword: %v", err)
			}
		}
		if err := cmdMove(e, []string{"a", "b"}); err == nil {
			t.Fatal("expected a move onto an existing password to fail")
		}
		// Both entries survive the refusal.
		for _, n := range []string{"a", "b"} {
			if _, err := e.app.ShowPassword(n); err != nil {
				t.Fatalf("%s was lost: %v", n, err)
			}
		}
	})
}

func TestCmdStatus(t *testing.T) {
	t.Run("no store open", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdStatus(e, nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("not a git repo", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		if err := cmdStatus(e, nil); err != nil {
			t.Fatalf("cmdStatus: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "Store is not a git repository") {
			t.Fatalf("output = %q", out)
		}
	})

	t.Run("clean git repo", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		storeDir := e.app.StorePath()
		initGitRepo(t, storeDir)
		if err := cmdStatus(e, nil); err != nil {
			t.Fatalf("cmdStatus: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "Working tree: clean") && !strings.Contains(out, "working tree clean") {
			t.Fatalf("output = %q", out)
		}
	})
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	gitx, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not in PATH")
	}
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "t@x.com"},
		{"config", "user.name", "T"},
		{"add", "."},
		{"commit", "-m", "init"},
	} {
		cmd := exec.Command(gitx, append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestCmdLock(t *testing.T) {
	e := newTestEnv(t)
	_ = setupStore(t, e)
	unlockPGP(t, e)
	if err := cmdLock(e, nil); err != nil {
		t.Fatalf("cmdLock: %v", err)
	}
	if e.app.IsUnlocked() {
		t.Fatal("expected locked")
	}
	out := readOut(t, e.stdout)
	if !strings.Contains(out, "Locked.") {
		t.Fatalf("output = %q", out)
	}
}

func TestCmdState(t *testing.T) {
	e := newTestEnv(t)
	if err := cmdState(e, nil); err != nil {
		t.Fatalf("cmdState: %v", err)
	}
	out := readOut(t, e.stdout)
	for _, want := range []string{"Unlocked:", "Store:", "Git remote:", "PGP fingerprint:", "SSH key id:", "Data dir:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %q", want, out)
		}
	}
}

func TestCmdConfig(t *testing.T) {
	e := newTestEnv(t)
	if err := cmdConfig(e, nil); err != nil {
		t.Fatalf("cmdConfig: %v", err)
	}
	out := readOut(t, e.stdout)
	for _, want := range []string{"storePath", "gitRemote", "sshKeyId", "pgpKeyFingerprint", "autoLockMinutes", "clipboardClearSeconds"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %q", want, out)
		}
	}
}

func TestCmdOpen(t *testing.T) {
	t.Run("missing directory", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdOpen(e, nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("opens store", func(t *testing.T) {
		e := newTestEnv(t)
		storeDir := filepath.Join(t.TempDir(), "pass")
		if _, err := store.Create(storeDir, []string{"AABBCCDD"}); err != nil {
			t.Fatal(err)
		}
		if err := cmdOpen(e, []string{storeDir}); err != nil {
			t.Fatalf("cmdOpen: %v", err)
		}
		if e.app.StorePath() != storeDir {
			t.Fatalf("store path = %q", e.app.StorePath())
		}
	})
}

func TestCmdKnownHosts(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdKnownHosts(e, nil); err != nil {
			t.Fatalf("cmdKnownHosts: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "No trusted SSH hosts yet") {
			t.Fatalf("output = %q", out)
		}
	})

	t.Run("lists hosts", func(t *testing.T) {
		e := newTestEnv(t)
		_, pub, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.app.TrustHost("github.com", signer.PublicKey()); err != nil {
			t.Fatalf("TrustHost: %v", err)
		}
		if err := cmdKnownHosts(e, nil); err != nil {
			t.Fatalf("cmdKnownHosts: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "github.com") {
			t.Fatalf("output = %q", out)
		}
	})
}

func TestEnsureHostTrustedUnreachable(t *testing.T) {
	e := newTestEnv(t)
	err := ensureHostTrusted(e, "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected ensureHostTrusted to fail for an unreachable host")
	}
	if hosts := e.app.KnownHostsList(); len(hosts) != 0 {
		t.Fatalf("KnownHostsList = %v, want nothing trusted", hosts)
	}
}

// TestCmdTestSSHKeepsPort pins that the port the user typed reaches the host
// check. Trust is keyed on host:port, so probing "127.0.0.1" instead of
// "127.0.0.1:1" would check, and later record, a different host.
func TestCmdTestSSHKeepsPort(t *testing.T) {
	e := newTestEnv(t, testLockPass+"\n")
	if _, err := e.app.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	err := cmdTestSSH(e, []string{"127.0.0.1:1"})
	if err == nil {
		t.Fatal("expected cmdTestSSH to fail for an unreachable host")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("error = %v, want the requested host:port", err)
	}
}

func TestEnsureHostTrustedChangedKey(t *testing.T) {
	e := newTestEnv(t)
	hostport, _ := startTestSSHHost(t)
	// Trust a key the server does not present, as a previous run would have.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.app.TrustHost(hostport, signer.PublicKey()); err != nil {
		t.Fatalf("TrustHost: %v", err)
	}

	err = ensureHostTrusted(e, hostport)
	if err == nil {
		t.Fatal("expected ensureHostTrusted to refuse a changed host key")
	}
	if !errors.Is(err, sshx.ErrHostKeyChanged) {
		t.Fatalf("error = %v, want it to wrap sshx.ErrHostKeyChanged", err)
	}
	if !strings.Contains(err.Error(), "man-in-the-middle") {
		t.Fatalf("error = %v, want a man-in-the-middle warning", err)
	}
	// The trusted key is untouched.
	if hosts := e.app.KnownHostsList(); len(hosts) != 1 ||
		!strings.Contains(hosts[0], ssh.FingerprintSHA256(signer.PublicKey())) {
		t.Fatalf("KnownHostsList = %v", hosts)
	}
}

// startTestSSHHost starts an in-process SSH server with a fresh host key. It
// serves nothing: the host key is captured during the handshake, which is all
// the trust flow needs.
func startTestSSHHost(t *testing.T) (hostport string, hostKey ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	// NoClientAuth: the host key is captured during the handshake, before any
	// authentication, and a ServerConfig without an auth callback refuses to
	// start a handshake at all.
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _, _, _ = ssh.NewServerConn(conn, cfg)
				_ = conn.Close()
			}()
		}
	}()
	return listener.Addr().String(), signer.PublicKey()
}

func TestCmdPublicKey(t *testing.T) {
	t.Run("locked", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdPublicKey(e, nil); err == nil {
			t.Fatal("expected error when locked")
		}
	})

	t.Run("no SSH key", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := cmdPublicKey(e, nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("success", func(t *testing.T) {
		e := newTestEnv(t)
		if _, err := e.app.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
			t.Fatalf("ImportSSHKey: %v", err)
		}
		if err := e.app.UnlockSSH([]byte(testLockPass)); err != nil {
			t.Fatalf("UnlockSSH: %v", err)
		}
		if err := cmdPublicKey(e, nil); err != nil {
			t.Fatalf("cmdPublicKey: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.HasPrefix(out, "ssh-ed25519") {
			t.Fatalf("output = %q", out)
		}
	})
}

func TestCmdImportPGP(t *testing.T) {
	t.Run("missing file arg", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdImportPGP(e, nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("missing file on disk", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdImportPGP(e, []string{filepath.Join(t.TempDir(), "missing.asc")}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("success", func(t *testing.T) {
		e := newTestEnv(t, testLockPass+"\n"+testPGPPassphrase+"\n")
		keyFile := filepath.Join(t.TempDir(), "key.asc")
		if err := os.WriteFile(keyFile, armoredPGPTestKey(t), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cmdImportPGP(e, []string{keyFile}); err != nil {
			t.Fatalf("cmdImportPGP: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "Key imported and stored locally") {
			t.Fatalf("output = %q", out)
		}
		if !e.app.HasStoredPGPKey() {
			t.Fatal("expected PGP key to be stored")
		}
	})
}

func TestCmdImportSSH(t *testing.T) {
	t.Run("missing file arg", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdImportSSH(e, nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("missing file on disk", func(t *testing.T) {
		e := newTestEnv(t)
		if err := cmdImportSSH(e, []string{filepath.Join(t.TempDir(), "missing")}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("success", func(t *testing.T) {
		e := newTestEnv(t, testLockPass+"\n\n")
		keyFile := filepath.Join(t.TempDir(), "id_ed25519")
		if err := os.WriteFile(keyFile, sshTestKey(t), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cmdImportSSH(e, []string{keyFile}); err != nil {
			t.Fatalf("cmdImportSSH: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "SSH key imported") {
			t.Fatalf("output = %q", out)
		}
		if !e.app.HasStoredSSHKey() {
			t.Fatal("expected SSH key to be stored")
		}
	})
}

func TestEnsureUnlocked(t *testing.T) {
	t.Run("already unlocked", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := ensureUnlocked(e); err != nil {
			t.Fatalf("ensureUnlocked: %v", err)
		}
	})

	t.Run("unlocks from stdin", func(t *testing.T) {
		e := newTestEnv(t, testLockPass+"\n")
		_ = setupStore(t, e)
		if err := ensureUnlocked(e); err != nil {
			t.Fatalf("ensureUnlocked: %v", err)
		}
		if !e.app.IsUnlocked() {
			t.Fatal("expected unlocked")
		}
	})
}

func TestEnsurePGPUnlocked(t *testing.T) {
	t.Run("already unlocked", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := ensurePGPUnlocked(e); err != nil {
			t.Fatalf("ensurePGPUnlocked: %v", err)
		}
	})

	t.Run("unlocks from stdin", func(t *testing.T) {
		e := newTestEnv(t, testLockPass+"\n")
		_ = setupStore(t, e)
		if err := ensurePGPUnlocked(e); err != nil {
			t.Fatalf("ensurePGPUnlocked: %v", err)
		}
		if !e.app.IsUnlocked() {
			t.Fatal("expected unlocked")
		}
	})
}

func TestEnsureSSHUnlocked(t *testing.T) {
	t.Run("already loaded", func(t *testing.T) {
		e := newTestEnv(t)
		if _, err := e.app.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
			t.Fatalf("ImportSSHKey: %v", err)
		}
		if err := e.app.UnlockSSH([]byte(testLockPass)); err != nil {
			t.Fatalf("UnlockSSH: %v", err)
		}
		if err := ensureSSHUnlocked(e); err != nil {
			t.Fatalf("ensureSSHUnlocked: %v", err)
		}
	})

	t.Run("unlocks from stdin", func(t *testing.T) {
		e := newTestEnv(t, testLockPass+"\n")
		if _, err := e.app.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
			t.Fatalf("ImportSSHKey: %v", err)
		}
		if err := ensureSSHUnlocked(e); err != nil {
			t.Fatalf("ensureSSHUnlocked: %v", err)
		}
		if !e.app.HasSSHKeyLoaded() {
			t.Fatal("expected SSH key loaded")
		}
	})

	t.Run("unlocks encrypted key from stdin", func(t *testing.T) {
		const pass = "ssh-pass"
		e := newTestEnv(t, testLockPass+"\n")
		key := sshEncryptedTestKey(t, []byte(pass))
		if _, err := e.app.ImportSSHKey(key, []byte(pass), []byte(testLockPass)); err != nil {
			t.Fatalf("ImportSSHKey: %v", err)
		}
		if err := ensureSSHUnlocked(e); err != nil {
			t.Fatalf("ensureSSHUnlocked: %v", err)
		}
		if !e.app.HasSSHKeyLoaded() {
			t.Fatal("expected SSH key loaded")
		}
	})
}

func TestPrintPlaintext(t *testing.T) {
	cases := []struct {
		name      string
		plaintext string
		full      bool
		want      string
	}{
		{"full with trailing newline", "line1\nline2\n", true, "line1\nline2\n"},
		{"full without trailing newline", "line1\nline2", true, "line1\nline2\n"},
		{"first line only", "line1\nline2\n", false, "line1\n"},
		{"single line no newline", "line1", false, "line1\n"},
		{"empty", "", true, "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			if err := printPlaintext(e, []byte(tc.plaintext), tc.full); err != nil {
				t.Fatalf("printPlaintext: %v", err)
			}
			if got := readOut(t, e.stdout); got != tc.want {
				t.Fatalf("output = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAskYesNo(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"y\n", true},
		{"Y\n", true},
		{"yes\n", true},
		{"YES\n", true},
		{"n\n", false},
		{"\n", false},
		{"maybe\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			e := newTestEnv(t, tc.in)
			got, err := askYesNo(e, "ok? ")
			if err != nil {
				t.Fatalf("askYesNo: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAskYesNoError(t *testing.T) {
	e := newTestEnv(t)
	_ = e.stdin.Close()
	_, err := askYesNo(e, "ok? ")
	if err == nil {
		t.Fatal("expected error on closed stdin")
	}
}

func TestUnlockPrompt(t *testing.T) {
	const sshPass = "ssh-pass"
	e := newTestEnv(t, testLockPass+"\n")
	if _, err := e.app.ImportSSHKey(sshEncryptedTestKey(t, []byte(sshPass)), []byte(sshPass), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	if err := unlockPrompt(e); err != nil {
		t.Fatalf("unlockPrompt: %v", err)
	}
	if !e.app.IsUnlocked() {
		t.Fatal("expected unlocked")
	}
	if !e.app.HasSSHKeyLoaded() {
		t.Fatal("expected SSH key loaded")
	}
}

// TestCmdCloneKeepsURLPort pins that the port in the URL reaches the host-key
// check. Trust is keyed on host:port, so probing the default port for a remote
// that lives on another one would check, and later record, a different host.
func TestCmdCloneKeepsURLPort(t *testing.T) {
	e := newTestEnv(t)
	_ = setupStore(t, e)
	unlockPGP(t, e)
	err := cmdClone(e, []string{"ssh://git@127.0.0.1:1/user/pass.git"})
	if err == nil {
		t.Fatal("expected cmdClone to fail for an unreachable host")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("error = %v, want the URL's host:port", err)
	}
	if hosts := e.app.KnownHostsList(); len(hosts) != 0 {
		t.Fatalf("KnownHostsList = %v, want nothing trusted", hosts)
	}
}

func TestCmdUnlock(t *testing.T) {
	t.Run("already unlocked", func(t *testing.T) {
		e := newTestEnv(t)
		_ = setupStore(t, e)
		unlockPGP(t, e)
		if err := cmdUnlock(e, nil); err != nil {
			t.Fatalf("cmdUnlock: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "Already unlocked") {
			t.Fatalf("output = %q", out)
		}
	})

	t.Run("unlocks from stdin", func(t *testing.T) {
		e := newTestEnv(t, testLockPass+"\n")
		_ = setupStore(t, e)
		if err := cmdUnlock(e, nil); err != nil {
			t.Fatalf("cmdUnlock: %v", err)
		}
		if !e.app.IsUnlocked() {
			t.Fatal("expected unlocked")
		}
	})
}

func TestEditorCommand(t *testing.T) {
	origVisual := os.Getenv("VISUAL")
	origEditor := os.Getenv("EDITOR")
	defer func() {
		_ = os.Setenv("VISUAL", origVisual)
		_ = os.Setenv("EDITOR", origEditor)
	}()

	_ = os.Unsetenv("VISUAL")
	_ = os.Unsetenv("EDITOR")
	if got := editorCommand(); !strings.Contains(got, "notepad.exe") {
		t.Fatalf("default editor = %q", got)
	}

	_ = os.Setenv("EDITOR", "code")
	if got := editorCommand(); got != "code" {
		t.Fatalf("EDITOR = %q", got)
	}

	_ = os.Setenv("VISUAL", "vim")
	if got := editorCommand(); got != "vim" {
		t.Fatalf("VISUAL = %q", got)
	}
}
