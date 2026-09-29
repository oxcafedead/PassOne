package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	goGit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/oxcafedead/passone/internal/gitx"
	"github.com/oxcafedead/passone/internal/store"
)

const genKeyPass = "generated-key-pass"

// withPGPKey returns an app with a usable OpenPGP key in memory, which is the
// precondition every store-creation test starts from.
func withPGPKey(t *testing.T) *App {
	t.Helper()
	a := newTestApp(t)
	armored := armoredTestKey(t)
	if _, err := a.ImportPGPKey(armored, []byte(testPGPPassphrase), []byte(testLockPass)); err != nil {
		t.Fatalf("ImportPGPKey: %v", err)
	}
	return a
}

func TestGeneratePGPKeyThenCreateStore(t *testing.T) {
	a := newTestApp(t)
	infos, err := a.GeneratePGPKey("Wizard User", "wizard@example.com", []byte(genKeyPass), []byte(testLockPass))
	if err != nil {
		t.Fatalf("GeneratePGPKey: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("infos = %+v, want one key", infos)
	}
	fp := infos[0].Fingerprint
	if !a.HasStoredPGPKey() {
		t.Error("HasStoredPGPKey = false after GeneratePGPKey; the key was not sealed")
	}
	if got := a.PGPKeyFingerprint(); got != fp {
		t.Errorf("PGPKeyFingerprint = %q, want %q", got, fp)
	}
	// Generating must not start an unlocked session: local secrets stay gated
	// on an explicit Unlock, exactly as an import leaves them.
	if a.IsUnlocked() {
		t.Error("GeneratePGPKey left the session unlocked")
	}

	dir := filepath.Join(t.TempDir(), "store")
	if err := a.CreateStore(dir, ""); err != nil {
		t.Fatalf("CreateStore: %v", err)
	}

	// The store is encrypted to the generated key, so it only opens once the
	// user unlocks and saves an entry.
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.SavePassword("github/personal", []byte("hunter2\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}
	plain, err := a.ShowPassword("github/personal")
	if err != nil {
		t.Fatalf("ShowPassword: %v", err)
	}
	if string(plain) != "hunter2\n" {
		t.Errorf("ShowPassword = %q", plain)
	}

	// The .gpg-id has to name the generated key, or nothing else can ever read
	// this store.
	ids, err := os.ReadFile(filepath.Join(dir, ".gpg-id"))
	if err != nil {
		t.Fatalf("read .gpg-id: %v", err)
	}
	if strings.TrimSpace(string(ids)) != fp {
		t.Errorf(".gpg-id = %q, want the generated fingerprint %q", strings.TrimSpace(string(ids)), fp)
	}
}

// TestGeneratedKeySurvivesARestart is the property that makes generation safe
// to offer as an alternative to importing: the key is sealed exactly like an
// imported one, so a new process can unlock with the same lock password and
// read the store.
func TestGeneratedKeySurvivesARestart(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("PASSONE_DIR", dataDir)
	a, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.GeneratePGPKey("Restart User", "restart@example.com", []byte(genKeyPass), []byte(testLockPass)); err != nil {
		t.Fatalf("GeneratePGPKey: %v", err)
	}
	fp := a.PGPKeyFingerprint()
	dir := filepath.Join(t.TempDir(), "store")
	if err := a.CreateStore(dir, ""); err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := a.SavePassword("bank/card", []byte("4111\n")); err != nil {
		t.Fatalf("SavePassword: %v", err)
	}

	// A fresh App over the same data directory stands in for an app restart.
	restarted, err := New()
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	if !restarted.HasStoredPGPKey() {
		t.Fatal("the generated key was not found after a restart")
	}
	if err := restarted.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock after restart: %v", err)
	}
	if got := restarted.PGPKeyFingerprint(); got != fp {
		t.Errorf("fingerprint after restart = %q, want %q", got, fp)
	}
	if err := restarted.OpenLocalStore(dir); err != nil {
		t.Fatalf("OpenLocalStore after restart: %v", err)
	}
	if err := restarted.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock after restart: %v", err)
	}
	plain, err := restarted.ShowPassword("bank/card")
	if err != nil {
		t.Fatalf("ShowPassword after restart: %v", err)
	}
	if string(plain) != "4111\n" {
		t.Errorf("ShowPassword after restart = %q", plain)
	}
}

func TestGeneratePGPKeyRefusesWhenAKeyExists(t *testing.T) {
	t.Run("stored key", func(t *testing.T) {
		a := withPGPKey(t)
		if _, err := a.GeneratePGPKey("Second", "second@example.com", []byte(genKeyPass), []byte(testLockPass)); !errors.Is(err, ErrKeyExists) {
			t.Fatalf("GeneratePGPKey = %v, want ErrKeyExists", err)
		}
		// The original key must still be the one in use: a store it encrypts to
		// has to keep working.
		dir := filepath.Join(t.TempDir(), "store")
		if err := a.CreateStore(dir, ""); err != nil {
			t.Fatalf("CreateStore after a refused generate: %v", err)
		}
		ids, err := os.ReadFile(filepath.Join(dir, ".gpg-id"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(ids)) != a.PGPKeyFingerprint() {
			t.Errorf(".gpg-id = %q, want the original fingerprint %q", strings.TrimSpace(string(ids)), a.PGPKeyFingerprint())
		}
	})

	t.Run("key resident in memory only", func(t *testing.T) {
		a := newTestApp(t)
		armored := armoredTestKey(t)
		a.mu.Lock()
		_, err := a.pgpSvc.ImportSecret(armored, []byte(testPGPPassphrase))
		a.mu.Unlock()
		if err != nil {
			t.Fatalf("ImportSecret: %v", err)
		}
		if a.HasStoredPGPKey() {
			t.Fatal("test setup: nothing should be sealed yet")
		}
		if _, err := a.GeneratePGPKey("Second", "second@example.com", []byte(genKeyPass), []byte(testLockPass)); !errors.Is(err, ErrKeyExists) {
			t.Fatalf("GeneratePGPKey = %v, want ErrKeyExists", err)
		}
	})
}

func TestGeneratePGPKeyRequiresAnEmail(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.GeneratePGPKey("No Email", "  ", []byte(genKeyPass), []byte(testLockPass)); err == nil {
		t.Fatal("GeneratePGPKey accepted a blank email")
	}
	if a.HasStoredPGPKey() {
		t.Error("a failed generation left a sealed key behind")
	}
}

// TestGeneratePGPKeyRequiresALockPassword keeps the generated key on the same
// footing as an imported one: a vault is only ever created with a password
// that can open it.
func TestGeneratePGPKeyRequiresALockPassword(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.GeneratePGPKey("No Lock", "nolock@example.com", []byte(genKeyPass), nil); err == nil {
		t.Fatal("GeneratePGPKey accepted an empty lock password")
	}
	if a.HasStoredPGPKey() {
		t.Error("a refused generation still sealed a key")
	}
}

func TestCreateStoreRequiresAPGPKey(t *testing.T) {
	a := newTestApp(t)
	dir := filepath.Join(t.TempDir(), "store")
	err := a.CreateStore(dir, "")
	if !errors.Is(err, ErrNoPGPKey) {
		t.Fatalf("CreateStore = %v, want ErrNoPGPKey", err)
	}
	// Nothing may have been written: a store with no recipient is not a store.
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("CreateStore created %s despite refusing", dir)
	}
}

func TestCreateStoreProducesAValidStore(t *testing.T) {
	a := withPGPKey(t)
	dir := filepath.Join(t.TempDir(), "store")
	if err := a.CreateStore(dir, ""); err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if got := a.StorePath(); got != dir {
		t.Errorf("StorePath = %q, want %q", got, dir)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open on the created store: %v", err)
	}
	if len(st.GPGIDs()) != 1 || st.GPGIDs()[0] != a.PGPKeyFingerprint() {
		t.Errorf("GPGIDs = %v, want just the loaded key", st.GPGIDs())
	}

	// A created store has to report usable status, not an error, or the vault
	// screen opens on a failure the user cannot act on.
	status, err := a.Status()
	if err != nil {
		t.Fatalf("Status on a freshly created store: %v", err)
	}
	if !strings.Contains(status, gitx.DefaultBranch) {
		t.Errorf("Status = %q, want it to name the %s branch", status, gitx.DefaultBranch)
	}
	if !strings.Contains(status, "No remote configured") {
		t.Errorf("Status = %q, want it to report no remote", status)
	}

	// The created store is the one the vault screen will open, and a restart
	// has to find it again from the config alone.
	if a.StorePath() != dir {
		t.Errorf("StorePath = %q, want the created store %q", a.StorePath(), dir)
	}
	restarted := newTestAppOver(t, a.DataDir())
	if got := restarted.StorePath(); got != dir {
		t.Errorf("StorePath after restart = %q, want %q", got, dir)
	}
}

// newTestAppOver boots a second app over an existing data directory, standing
// in for a restart: nothing is carried over in memory.
func newTestAppOver(t *testing.T, dataDir string) *App {
	t.Helper()
	t.Setenv("PASSONE_DIR", dataDir)
	a, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestCreateStoreRecordsTheRemoteWithoutContactingIt(t *testing.T) {
	a := withPGPKey(t)
	dir := filepath.Join(t.TempDir(), "store")
	const remote = "git@github.com:user/store.git"
	// Nothing is listening on this host: recording a remote must not dial out.
	if err := a.CreateStore(dir, remote); err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if got := a.StoreRemoteURL(); got != remote {
		t.Errorf("StoreRemoteURL = %q, want %q", got, remote)
	}
	got, err := gitx.RemoteURL(dir)
	if err != nil {
		t.Fatalf("RemoteURL: %v", err)
	}
	if got != remote {
		t.Errorf("repository origin = %q, want %q", got, remote)
	}
	status, err := a.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(status, remote) {
		t.Errorf("Status = %q, want it to name the remote", status)
	}
	// Nothing has been pushed and there is no tracking ref, so the zero
	// ahead/behind counts must not read as "in sync": the vault's only copy is
	// on this machine.
	if strings.Contains(status, "In sync with origin") {
		t.Errorf("Status = %q, want it to say nothing is pushed yet", status)
	}
	if !strings.Contains(status, "Nothing pushed to origin yet") {
		t.Errorf("Status = %q, want it to say nothing is pushed yet", status)
	}
}

func TestCreateStoreMakesAnInitialCommit(t *testing.T) {
	a := withPGPKey(t)
	dir := filepath.Join(t.TempDir(), "store")
	if err := a.CreateStore(dir, ""); err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	has, err := gitx.HasCommits(dir)
	if err != nil {
		t.Fatalf("HasCommits: %v", err)
	}
	if !has {
		t.Fatal("the created store has no commit; the first sync would have nothing to push")
	}
	branch, err := gitx.CurrentBranch(dir)
	if err != nil {
		t.Fatalf("CurrentBranch: %v", err)
	}
	if branch != gitx.DefaultBranch {
		t.Errorf("branch = %q, want %q", branch, gitx.DefaultBranch)
	}
	// The initial commit has to contain .gpg-id, or the store is only a working
	// directory that happens to be a repository.
	if _, err := gitx.Status(dir); err != nil {
		t.Fatalf("Status: %v", err)
	}
	state, err := gitx.GetRepoState(dir)
	if err != nil {
		t.Fatalf("GetRepoState: %v", err)
	}
	if !state.IsClean {
		t.Errorf("the created store is not clean: %+v", state)
	}
	if state.Head == "" {
		t.Error("no HEAD after the initial commit")
	}
}

func TestCreateStoreRefusesToClobber(t *testing.T) {
	t.Run("already a store", func(t *testing.T) {
		a := withPGPKey(t)
		dir := filepath.Join(t.TempDir(), "store")
		if err := a.CreateStore(dir, ""); err != nil {
			t.Fatalf("CreateStore: %v", err)
		}
		before, err := os.ReadFile(filepath.Join(dir, ".gpg-id"))
		if err != nil {
			t.Fatal(err)
		}
		err = a.CreateStore(dir, "")
		if err == nil {
			t.Fatal("CreateStore overwrote an existing store")
		}
		if !strings.Contains(err.Error(), "already a pass store") {
			t.Errorf("error = %v, want it to say the directory is already a store", err)
		}
		after, err := os.ReadFile(filepath.Join(dir, ".gpg-id"))
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Error("a refused CreateStore rewrote .gpg-id")
		}
	})

	t.Run("directory with other files", func(t *testing.T) {
		a := withPGPKey(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "holiday.jpg"), []byte("mine"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := a.CreateStore(dir, "")
		if err == nil {
			t.Fatal("CreateStore wrote into a directory holding unrelated files")
		}
		if !strings.Contains(err.Error(), "not empty") {
			t.Errorf("error = %v, want it to mention the directory is not empty", err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, ".gpg-id")); !os.IsNotExist(statErr) {
			t.Error("a refused CreateStore left a .gpg-id behind")
		}
		if _, statErr := os.Stat(filepath.Join(dir, "holiday.jpg")); statErr != nil {
			t.Error("a refused CreateStore removed an unrelated file")
		}
	})

	t.Run("empty directory name", func(t *testing.T) {
		a := withPGPKey(t)
		if err := a.CreateStore("   ", ""); err == nil {
			t.Fatal("CreateStore accepted a blank folder")
		}
	})
}

// TestCreateStoreLeavesNoHalfBuiltStore pins the failure path: whatever a
// creation attempt trips over, the target directory is not left holding a .git
// and a .gpg-id that do not describe a working store.
func TestCreateStoreLeavesNoHalfBuiltStore(t *testing.T) {
	a := withPGPKey(t)
	dir := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A path that cannot hold a repository: a file where the folder should be
	// makes Open/Create fail after the point of no return.
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateStore(blocked, ""); err == nil {
		t.Fatal("CreateStore accepted a path that is a file")
	}
	// The unrelated directory the user made must still be empty, not filled
	// with a repository this attempt abandoned.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the prepared directory holds %v after a refused CreateStore", entries)
	}
	if _, err := os.Stat(filepath.Join(blocked, ".gpg-id")); err == nil {
		t.Error("a refused CreateStore wrote into a file path")
	}
}

// TestSyncOfACreatedStoreIsAPush covers the first sync of a store created here
// with a remote: the remote holds no branches, so there is nothing to fetch or
// pull and the whole operation is the initial push. Reporting that as a
// failure would leave the "remote" field the wizard just collected unusable.
func TestSyncOfACreatedStoreIsAPush(t *testing.T) {
	a := withPGPKey(t)
	if _, err := a.ImportSSHKey(sshTestKey(t), nil, []byte(testLockPass)); err != nil {
		t.Fatalf("ImportSSHKey: %v", err)
	}
	bareDir := filepath.Join(t.TempDir(), "remote.git")
	if _, err := goGit.PlainInit(bareDir, true); err != nil {
		t.Fatalf("PlainInit bare: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "store")
	if err := a.CreateStore(dir, fileURL(bareDir)); err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if err := a.Unlock([]byte(testLockPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	summary, err := a.Sync()
	if err != nil {
		t.Fatalf("first Sync of a created store: %v", err)
	}
	if !strings.Contains(summary, "pushed local commits") {
		t.Errorf("first Sync summary = %q, want it to report a push", summary)
	}

	// The pushed branch has to be the store's, carrying .gpg-id, or a second
	// machine would clone something that is not a pass store. A bare repository
	// created by `git init --bare` still points its HEAD at master, so a clone
	// has to name the branch explicitly; what matters here is that main exists
	// on the remote with the store's .gpg-id on it.
	remote, err := goGit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare remote: %v", err)
	}
	if _, err := remote.Reference(plumbing.NewBranchReferenceName(gitx.DefaultBranch), true); err != nil {
		t.Errorf("the remote has no %s branch after the first sync: %v", gitx.DefaultBranch, err)
	}
	other := filepath.Join(t.TempDir(), "clone")
	if _, err := goGit.PlainClone(other, false, &goGit.CloneOptions{
		URL:           fileURL(bareDir),
		ReferenceName: plumbing.NewBranchReferenceName(gitx.DefaultBranch),
	}); err != nil {
		t.Fatalf("Clone after push: %v", err)
	}
	if _, err := store.Open(other); err != nil {
		t.Fatalf("the pushed store is not a pass store: %v", err)
	}

	// And a second sync has to report up to date, not repeat the push.
	summary, err = a.Sync()
	if err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	if !strings.Contains(summary, "Already up to date") {
		t.Errorf("second Sync summary = %q, want up to date", summary)
	}
}

func TestDefaultStoreDir(t *testing.T) {
	a := newTestApp(t)
	stores := filepath.Join(a.DataDir(), "stores")

	if got := a.DefaultStoreDir(""); got != stores {
		t.Errorf("DefaultStoreDir(\"\") = %q, want %q", got, stores)
	}
	if got, want := a.DefaultStoreDir("work"), filepath.Join(stores, "work"); got != want {
		t.Errorf("DefaultStoreDir(work) = %q, want %q", got, want)
	}
	abs := filepath.Join(t.TempDir(), "elsewhere")
	if got := a.DefaultStoreDir(abs); got != abs {
		t.Errorf("DefaultStoreDir(%q) = %q, want the path passed through", abs, got)
	}
	// A name is not a path: a stray separator must not place a store somewhere
	// the wizard never showed.
	for _, bad := range []string{"..", ".", "a/b", `a\b`} {
		if got := a.DefaultStoreDir(bad); got != "" {
			t.Errorf("DefaultStoreDir(%q) = %q, want it rejected", bad, got)
		}
	}
}

// TestDefaultStoreDirIsUsable ties the suggestion to the thing it suggests: the
// path has to be one CreateStore accepts.
func TestDefaultStoreDirIsUsable(t *testing.T) {
	a := withPGPKey(t)
	dir := a.DefaultStoreDir("fresh")
	if err := a.CreateStore(dir, ""); err != nil {
		t.Fatalf("CreateStore(%q): %v", dir, err)
	}
	if !contains(a.StoredStores(), dir) {
		t.Errorf("StoredStores = %v, want %s", a.StoredStores(), dir)
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
