package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oxcafedead/passone/internal/app"
	"github.com/oxcafedead/passone/internal/gitx"
	"github.com/oxcafedead/passone/internal/store"
)

const genPass = "cli-generated-key-pass"

// genKeyStdin is what cmdGenPGPKey reads when name and email are passed as
// arguments: the key passphrase twice, then the lock password.
func genKeyStdin() string {
	return genPass + "\n" + genPass + "\n" + testLockPass + "\n"
}

// TestCmdGenPGPKeyThenInitStore walks the whole from-scratch path the two new
// commands exist for: no gpg, no existing store, no repository. A user who has
// never run the app before should be able to reach a working password store with
// these two commands alone.
func TestCmdGenPGPKeyThenInitStore(t *testing.T) {
	e := newTestEnv(t, genKeyStdin())
	if err := cmdGenPGPKey(e, []string{"CLI User", "cli@example.com"}); err != nil {
		t.Fatalf("cmdGenPGPKey: %v", err)
	}
	out := readOut(t, e.stdout)
	if !strings.Contains(out, "Key generated and sealed locally") {
		t.Fatalf("output = %q", out)
	}
	if !e.app.HasStoredPGPKey() {
		t.Fatal("the generated key was not stored")
	}
	fp := e.app.PGPKeyFingerprint()
	if !strings.Contains(out, fp) {
		t.Errorf("output does not name the fingerprint %q: %q", fp, out)
	}

	// init-store needs the key in memory; in a fresh process that means the
	// lock password first, exactly as the prompt says.
	dir := filepath.Join(t.TempDir(), "store")
	e2 := newTestEnvIn(t, e.app.DataDir(), testLockPass+"\n")
	if err := cmdInitStore(e2, []string{dir}); err != nil {
		t.Fatalf("cmdInitStore: %v", err)
	}
	out = readOut(t, e2.stdout)
	if !strings.Contains(out, "Store created and opened") {
		t.Errorf("output = %q", out)
	}
	if !strings.Contains(out, "No remote configured") {
		t.Errorf("output = %q, want it to say there is no remote", out)
	}
	if e2.app.StorePath() != dir {
		t.Errorf("StorePath = %q, want %q", e2.app.StorePath(), dir)
	}

	// The store has to be a real one: encrypted to the generated key, and
	// readable through the ordinary save/show path.
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	ids := st.GPGIDs()
	if len(ids) != 1 || ids[0] != fp {
		t.Errorf(".gpg-id = %v, want the generated fingerprint %q", ids, fp)
	}
	if err := e2.app.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := e2.app.SavePassword("github/personal", []byte("hunter2\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	plain, err := e2.app.ShowPassword("github/personal")
	if err != nil {
		t.Fatalf("ShowPassword: %v", err)
	}
	if string(plain) != "hunter2\n" {
		t.Errorf("ShowPassword = %q", plain)
	}
}

func TestCmdGenPGPKeyRefusesBadInput(t *testing.T) {
	t.Run("missing email", func(t *testing.T) {
		e := newTestEnv(t, genKeyStdin())
		if err := cmdGenPGPKey(e, []string{"No Email", "  "}); err == nil {
			t.Fatal("cmdGenPGPKey accepted a blank email")
		}
		if e.app.HasStoredPGPKey() {
			t.Error("a refused generation stored a key anyway")
		}
	})

	t.Run("mismatched passphrases", func(t *testing.T) {
		// The confirmation is the point: a generated key has no other copy.
		e := newTestEnv(t, "one\ntwo\n"+testLockPass+"\n")
		err := cmdGenPGPKey(e, []string{"A", "a@example.com"})
		if err == nil {
			t.Fatal("cmdGenPGPKey accepted two different passphrases")
		}
		if !strings.Contains(err.Error(), "do not match") {
			t.Errorf("error = %v, want it to report the mismatch", err)
		}
		if e.app.HasStoredPGPKey() {
			t.Error("a refused generation stored a key anyway")
		}
	})

	t.Run("empty key passphrase", func(t *testing.T) {
		e := newTestEnv(t, "\n\n"+testLockPass+"\n")
		if err := cmdGenPGPKey(e, []string{"A", "a@example.com"}); err == nil {
			t.Fatal("cmdGenPGPKey accepted an empty key passphrase")
		}
	})

	t.Run("empty lock password", func(t *testing.T) {
		e := newTestEnv(t, genPass+"\n"+genPass+"\n\n")
		if err := cmdGenPGPKey(e, []string{"A", "a@example.com"}); err == nil {
			t.Fatal("cmdGenPGPKey accepted an empty lock password")
		}
		if e.app.HasStoredPGPKey() {
			t.Error("a refused generation stored a key anyway")
		}
	})

	t.Run("too many arguments", func(t *testing.T) {
		e := newTestEnv(t, genKeyStdin())
		if err := cmdGenPGPKey(e, []string{"A", "a@example.com", "extra"}); err == nil {
			t.Fatal("cmdGenPGPKey accepted three positional arguments")
		}
	})
}

func TestCmdGenPGPKeyRefusesWhenAKeyExists(t *testing.T) {
	e := newTestEnv(t, genKeyStdin())
	if _, err := e.app.ImportPGPKey(armoredPGPTestKey(t), []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	err := cmdGenPGPKey(e, []string{"Second", "second@example.com"})
	if err == nil {
		t.Fatal("cmdGenPGPKey generated a second key")
	}
	if !strings.Contains(err.Error(), "already") {
		t.Errorf("error = %v, want it to say a key already exists", err)
	}
	// The original key must survive untouched: a store may already name it.
	if e.app.PGPKeyFingerprint() == "" {
		t.Error("the existing fingerprint was lost")
	}
}

func TestCmdInitStore(t *testing.T) {
	withKey := func(t *testing.T) *env {
		t.Helper()
		// init-store asks for the lock password: the key has to be in memory,
		// and in a fresh process only the lock password loads it.
		e := newTestEnv(t, testLockPass+"\n")
		if _, err := e.app.ImportPGPKey(armoredPGPTestKey(t), []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
			t.Fatalf("ImportPGPKey: %v", err)
		}
		return e
	}

	t.Run("missing directory argument", func(t *testing.T) {
		e := withKey(t)
		if err := cmdInitStore(e, nil); err == nil {
			t.Fatal("cmdInitStore accepted no directory")
		}
	})

	t.Run("records the remote without contacting it", func(t *testing.T) {
		e := withKey(t)
		dir := filepath.Join(t.TempDir(), "store")
		if err := cmdInitStore(e, []string{dir, "git@github.com:user/store.git"}); err != nil {
			t.Fatalf("cmdInitStore: %v", err)
		}
		out := readOut(t, e.stdout)
		if !strings.Contains(out, "Run 'sync' to push it") {
			t.Errorf("output = %q, want it to say the first sync is the push", out)
		}
		got, err := gitx.RemoteURL(dir)
		if err != nil {
			t.Fatalf("RemoteURL: %v", err)
		}
		if got != "git@github.com:user/store.git" {
			t.Errorf("origin = %q", got)
		}
	})

	t.Run("refuses a directory that is not empty", func(t *testing.T) {
		e := withKey(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := cmdInitStore(e, []string{dir})
		if err == nil {
			t.Fatal("cmdInitStore wrote into a directory holding unrelated files")
		}
		if !strings.Contains(err.Error(), "not empty") {
			t.Errorf("error = %v, want it to mention the directory is not empty", err)
		}
	})

	t.Run("refuses to overwrite an existing store", func(t *testing.T) {
		e := withKey(t)
		dir := filepath.Join(t.TempDir(), "store")
		if err := cmdInitStore(e, []string{dir}); err != nil {
			t.Fatalf("cmdInitStore: %v", err)
		}
		before, err := os.ReadFile(filepath.Join(dir, ".gpg-id"))
		if err != nil {
			t.Fatal(err)
		}
		if err := cmdInitStore(e, []string{dir}); err == nil {
			t.Fatal("cmdInitStore overwrote an existing store")
		}
		after, err := os.ReadFile(filepath.Join(dir, ".gpg-id"))
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Error("a refused cmdInitStore rewrote .gpg-id")
		}
	})
}

// newTestEnvIn returns an env over an existing data directory, standing in for
// a second CLI process: the sealed key is on disk, nothing is in memory.
func newTestEnvIn(t *testing.T, dataDir, stdinContent string) *env {
	t.Helper()
	t.Setenv("PASSONE_DIR", dataDir)
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
	in := testFile(t, stdinContent)
	t.Cleanup(func() {
		_ = out.Close()
		_ = errFile.Close()
		_ = in.Close()
	})
	return &env{app: a, stdin: in, stdout: out, stderr: errFile}
}
