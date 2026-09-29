package gitx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	goGit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

func TestInitCreatesARepositoryOnMain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	if err := Init(dir, ""); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		t.Fatalf("Init did not create .git: %v", err)
	}
	// Status is what the settings panel calls, so an initialised store must not
	// fail there just because nothing has been committed yet.
	if _, err := Status(dir); err != nil {
		t.Errorf("Status on a freshly initialised store: %v", err)
	}
	repo, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := repo.Head(); err == nil {
		t.Error("Init created a commit; the first commit belongs to the store's first entry")
	}
	// HEAD is symbolic and points at an unborn branch, so the commit the user
	// makes first lands on main rather than on go-git's master default.
	head, err := repo.Reference(plumbing.HEAD, false)
	if err != nil {
		t.Fatalf("reading HEAD: %v", err)
	}
	if head.Type() != plumbing.SymbolicReference {
		t.Fatalf("HEAD is detached (%s)", head.Hash())
	}
	if got := head.Target().Short(); got != DefaultBranch {
		t.Errorf("HEAD targets %s, want the unborn %s branch", head.Target(), DefaultBranch)
	}
	if _, err := repo.Remote("origin"); err == nil {
		t.Error("Init with no remote created an origin remote")
	}
}

// TestInitCommitsOnMain is the property the branch default exists for: the
// first real commit of a new store has to land on main, or the store's history
// starts on a branch the app never asked for.
func TestInitCommitsOnMain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	if err := Init(dir, ""); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := writeRel(dir, ".gpg-id", "FINGERPRINT\n"); err != nil {
		t.Fatal(err)
	}
	if err := Add(dir, ".gpg-id"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := Commit(dir, "initialise store", "Owner", "owner@example.com"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got, err := CurrentBranch(dir); err != nil {
		t.Fatalf("CurrentBranch: %v", err)
	} else if got != DefaultBranch {
		t.Errorf("CurrentBranch = %q, want %q", got, DefaultBranch)
	}
}

func TestInitRecordsTheRemoteWithoutContactingIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	// A URL that could not be reached: recording it must not dial out, or
	// creating a store offline would hang on the network.
	url := remoteURL("never-contacted")
	if err := Init(dir, url); err != nil {
		t.Fatalf("Init: %v", err)
	}
	got, err := RemoteURL(dir)
	if err != nil {
		t.Fatalf("RemoteURL: %v", err)
	}
	if got != url {
		t.Errorf("RemoteURL = %q, want %q", got, url)
	}
}

func TestInitIgnoresABlankRemote(t *testing.T) {
	for _, remote := range []string{"", "   ", "\t"} {
		dir := filepath.Join(t.TempDir(), "store")
		if err := Init(dir, remote); err != nil {
			t.Fatalf("Init(%q): %v", remote, err)
		}
		if _, err := RemoteURL(dir); err == nil {
			t.Errorf("Init(%q) recorded a remote", remote)
		}
	}
}

func TestInitRefusesANonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, ""); err == nil {
		t.Fatal("Init initialised a repository in a directory that already had files")
	} else if !strings.Contains(err.Error(), "not empty") {
		t.Errorf("error = %v, want it to mention the directory is not empty", err)
	}
	if _, err := goGit.PlainOpen(dir); err == nil {
		t.Error("a refused Init still left a repository behind")
	}
}

func TestInitCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "store")
	if err := Init(dir, ""); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := Open(dir); err != nil {
		t.Errorf("Open after Init created the directory: %v", err)
	}
}

// TestRepoStateOfAnEmptyRepository pins the case a brand new store is in:
// the repository exists, HEAD points at a branch, and there is no commit yet.
// GetRepoState used to fail on repo.Head() there, which broke Status and Sync
// for exactly the store a user had just created.
func TestRepoStateOfAnEmptyRepository(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	if err := Init(dir, remoteURL("fresh")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	state, err := GetRepoState(dir)
	if err != nil {
		t.Fatalf("GetRepoState on a repository with no commits: %v", err)
	}
	if state.Branch != DefaultBranch {
		t.Errorf("Branch = %q, want %q", state.Branch, DefaultBranch)
	}
	if state.Head != "" || state.LastCommit != "" {
		t.Errorf("Head/LastCommit = %q/%q, want both empty before the first commit", state.Head, state.LastCommit)
	}
	if !state.HasRemote {
		t.Error("HasRemote = false after Init recorded a remote")
	}
	if state.Ahead != 0 || state.Behind != 0 || state.IsDiverged {
		t.Errorf("ahead/behind/diverged = %d/%d/%v, want 0/0/false", state.Ahead, state.Behind, state.IsDiverged)
	}
	// The zero counts above are indistinguishable from "in sync" unless the
	// report also says whether the remote's branch is known at all. Without it a
	// caller reads a brand new store as backed up, which it is not.
	if state.HasRemoteBranch {
		t.Error("HasRemoteBranch = true for a store whose remote has never been fetched")
	}

	// Once the store's first entry has been committed, the report has to grow a
	// HEAD and stop claiming the repository is dirty.
	if err := writeRel(dir, ".gpg-id", "FINGERPRINT\n"); err != nil {
		t.Fatal(err)
	}
	if err := Add(dir, ".gpg-id"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := Commit(dir, "initialise store", "Owner", "owner@example.com"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	state, err = GetRepoState(dir)
	if err != nil {
		t.Fatalf("GetRepoState after the first commit: %v", err)
	}
	if state.Head == "" {
		t.Error("Head is still empty after the first commit")
	}
	if !state.IsClean {
		t.Error("IsClean = false right after committing the only change")
	}
}

func TestHasCommits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	if err := Init(dir, ""); err != nil {
		t.Fatalf("Init: %v", err)
	}
	has, err := HasCommits(dir)
	if err != nil {
		t.Fatalf("HasCommits: %v", err)
	}
	if has {
		t.Error("HasCommits = true right after Init")
	}
	if err := writeRel(dir, ".gpg-id", "FINGERPRINT\n"); err != nil {
		t.Fatal(err)
	}
	if err := Add(dir, ".gpg-id"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := Commit(dir, "initialise", "Owner", "owner@example.com"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if has, err = HasCommits(dir); err != nil || !has {
		t.Errorf("HasCommits = %v (%v), want true after the first commit", has, err)
	}
}

func TestHasRemoteBranch(t *testing.T) {
	// A store created locally with a remote recorded but never pushed to:
	// there is no origin/main yet, which is what makes the first Sync a push.
	local := filepath.Join(t.TempDir(), "local")
	if err := Init(local, remoteURL("empty-remote")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	makeRemote(t, "empty-remote")
	// An empty remote is a normal state, not a failure: it is what a store that
	// was created here and never pushed points at.
	if err := Fetch(local, nil); err != nil && !errors.Is(err, ErrRemoteEmpty) {
		t.Fatalf("Fetch: %v", err)
	}
	if has, err := HasRemoteBranch(local, DefaultBranch); err != nil || has {
		t.Errorf("HasRemoteBranch = %v (%v), want false for an empty remote", has, err)
	}

	// A local-only store has no origin at all, which is not an error.
	noRemote := filepath.Join(t.TempDir(), "noremote")
	if err := Init(noRemote, ""); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if has, err := HasRemoteBranch(noRemote, DefaultBranch); err != nil || has {
		t.Errorf("HasRemoteBranch with no origin = %v (%v), want false and no error", has, err)
	}
	// A directory that is not a repository at all is a different thing.
	if _, err := HasRemoteBranch(filepath.Join(t.TempDir(), "missing"), DefaultBranch); err == nil {
		t.Error("HasRemoteBranch on a directory that is not a repository should fail")
	}
}

// TestInitPushesToAnEmptyRemote covers the first sync of a store that was
// created here: the remote holds nothing, so the local commit has to create
// the branch rather than fail.
func TestInitPushesToAnEmptyRemote(t *testing.T) {
	makeRemote(t, "brand-new")
	dir := filepath.Join(t.TempDir(), "store")
	if err := Init(dir, remoteURL("brand-new")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := writeRel(dir, ".gpg-id", "FINGERPRINT\n"); err != nil {
		t.Fatal(err)
	}
	if err := Add(dir, ".gpg-id"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := Commit(dir, "initialise store", "Owner", "owner@example.com"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := Push(dir, nil); err != nil {
		t.Fatalf("Push to an empty remote: %v", err)
	}
	// The branch now exists on the remote, which is what a later fetch or a
	// second machine's sync will look for.
	if err := Fetch(dir, nil); err != nil && !errors.Is(err, ErrUpToDate) {
		t.Fatalf("Fetch after Push: %v", err)
	}
	if has, err := HasRemoteBranch(dir, DefaultBranch); err != nil || !has {
		t.Errorf("HasRemoteBranch after Push = %v (%v), want true", has, err)
	}
	// With the tracking ref present the report can say something true about the
	// remote, and it must agree with the branch-level answer above.
	state, err := GetRepoState(dir)
	if err != nil {
		t.Fatalf("GetRepoState after Push: %v", err)
	}
	if !state.HasRemoteBranch {
		t.Error("RepoState.HasRemoteBranch = false after Push and Fetch")
	}
	if state.Ahead != 0 || state.Behind != 0 {
		t.Errorf("ahead/behind right after a push = %d/%d, want 0/0", state.Ahead, state.Behind)
	}

	// A bare remote created by `git init --bare` still points its HEAD at
	// master, so a clone of it would not find main until the server's default
	// branch is set. Point it at main here to check the second-machine path.
	remoteRepo := testProtocol.repos["brand-new"]
	if err := remoteRepo.Storer.SetReference(plumbing.NewSymbolicReference(
		plumbing.HEAD, plumbing.NewBranchReferenceName(DefaultBranch))); err != nil {
		t.Fatalf("set remote HEAD: %v", err)
	}

	other := filepath.Join(t.TempDir(), "clone")
	if err := Clone(remoteURL("brand-new"), other, nil); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if got, err := CurrentBranch(other); err != nil {
		t.Errorf("CurrentBranch on the clone: %v", err)
	} else if got != DefaultBranch {
		t.Errorf("cloned branch = %q, want %q", got, DefaultBranch)
	}
	if got := readFile(t, filepath.Join(other, ".gpg-id")); got != "FINGERPRINT\n" {
		t.Errorf("cloned .gpg-id = %q", got)
	}
}

// TestPullTakesTheStoreBranchNotTheRemoteHEAD pins the reason Pull names the
// branch explicitly. A bare repository created by `git init --bare` points its
// HEAD at master; a store created here is on main. Following the remote's HEAD
// would fail with "reference not found" on the second sync, long after the
// first push looked like it worked.
func TestPullTakesTheStoreBranchNotTheRemoteHEAD(t *testing.T) {
	makeRemote(t, "stale-head")
	// Advertise master, which does not exist, as the remote's default branch —
	// the state a repository created before main was the default is left in.
	if err := testProtocol.repos["stale-head"].Storer.SetReference(plumbing.NewSymbolicReference(
		plumbing.HEAD, plumbing.NewBranchReferenceName(plumbing.Master.Short()))); err != nil {
		t.Fatalf("SetReference: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "store")
	if err := Init(dir, remoteURL("stale-head")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := writeRel(dir, ".gpg-id", "FINGERPRINT\n"); err != nil {
		t.Fatal(err)
	}
	if err := Add(dir, ".gpg-id"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := Commit(dir, "initialise store", "Owner", "owner@example.com"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := Push(dir, nil); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if err := Fetch(dir, nil); err != nil && !errors.Is(err, ErrUpToDate) {
		t.Fatalf("Fetch: %v", err)
	}
	if err := Pull(dir, nil); !errors.Is(err, ErrUpToDate) {
		t.Fatalf("Pull = %v, want ErrUpToDate on a store that is already up to date", err)
	}
	if got, err := CurrentBranch(dir); err != nil || got != DefaultBranch {
		t.Errorf("CurrentBranch = %q (%v), want %q", got, err, DefaultBranch)
	}
}

func TestSetRemote(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	if err := Init(dir, ""); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := SetRemote(dir, remoteURL("a")); err != nil {
		t.Fatalf("SetRemote: %v", err)
	}
	if got, _ := RemoteURL(dir); got != remoteURL("a") {
		t.Errorf("RemoteURL = %q", got)
	}
	// Setting it again must replace, not fail: the settings panel edits the
	// same remote the wizard may have recorded.
	if err := SetRemote(dir, remoteURL("b")); err != nil {
		t.Fatalf("SetRemote (replace): %v", err)
	}
	if got, _ := RemoteURL(dir); got != remoteURL("b") {
		t.Errorf("RemoteURL after replace = %q, want %q", got, remoteURL("b"))
	}
	if err := SetRemote(dir, "  "); err == nil {
		t.Error("SetRemote accepted an empty URL")
	}
}
