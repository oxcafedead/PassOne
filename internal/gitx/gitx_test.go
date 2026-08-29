package gitx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	goGit "github.com/go-git/go-git/v5"
	goGitConfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/server"
	"golang.org/x/crypto/ssh"
)

// The standard file:// transport shells out to a real `git` binary, which the
// app intentionally must not depend on. These tests therefore register an
// in-process transport backed by an in-memory repository loader, exercising
// the exact same clone/fetch/push/pull protocol paths go-git uses.
const testScheme = "gitxtest"

type testLoader struct {
	mu    sync.Mutex
	repos map[string]*goGit.Repository
}

func (l *testLoader) Load(ep *transport.Endpoint) (storer.Storer, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.repos[ep.Host]
	if !ok {
		return nil, transport.ErrRepositoryNotFound
	}
	return r.Storer, nil
}

var testProtocol = newTestLoader()

func newTestLoader() *testLoader {
	l := &testLoader{repos: make(map[string]*goGit.Repository)}
	client.InstallProtocol(testScheme, server.NewClient(l))
	return l
}

func remoteURL(name string) string {
	return testScheme + "://" + name
}

// makeRemote registers a bare remote repository under the test protocol.
func makeRemote(t *testing.T, name string) {
	t.Helper()
	repo, err := goGit.PlainInit(filepath.Join(t.TempDir(), name+".git"), true)
	if err != nil {
		t.Fatalf("PlainInit(bare): %v", err)
	}
	testProtocol.mu.Lock()
	testProtocol.repos[name] = repo
	testProtocol.mu.Unlock()
	t.Cleanup(func() {
		testProtocol.mu.Lock()
		delete(testProtocol.repos, name)
		testProtocol.mu.Unlock()
	})
}

// seedRemote commits the given files to a worktree and pushes them to a remote
// that was created with makeRemote.
func seedRemote(t *testing.T, name string, files map[string]string) {
	t.Helper()
	work := t.TempDir()
	repo, err := goGit.PlainInit(work, false)
	if err != nil {
		t.Fatalf("seed PlainInit: %v", err)
	}
	if _, err := repo.CreateRemote(&goGitConfig.RemoteConfig{Name: "origin", URLs: []string{remoteURL(name)}}); err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}
	for file, content := range files {
		if err := writeRel(work, file, content); err != nil {
			t.Fatalf("seed write %s: %v", file, err)
		}
		if err := Add(work, file); err != nil {
			t.Fatalf("seed add %s: %v", file, err)
		}
	}
	if _, err := Commit(work, "seed", "Seed", "seed@example.com"); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	if err := Push(work, nil); err != nil {
		t.Fatalf("seed push: %v", err)
	}
}

func writeRel(root, name, content string) error {
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, name), []byte(content), 0o600)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// pushSideRef pushes the current branch of work to a distinct ref on origin,
// leaving the local/normal branch untouched.
func pushSideRef(t *testing.T, work, ref string) error {
	t.Helper()
	repo, err := goGit.PlainOpen(work)
	if err != nil {
		return err
	}
	head, err := repo.Head()
	if err != nil {
		return err
	}
	return repo.Push(&goGit.PushOptions{
		RemoteName: "origin",
		RefSpecs: []goGitConfig.RefSpec{
			goGitConfig.RefSpec(head.Name().String() + ":refs/heads/" + ref),
		},
	})
}

func TestCloneCommitPushPull(t *testing.T) {
	name := "repo1"
	makeRemote(t, name)
	seedRemote(t, name, map[string]string{"a.txt": "one", "b.txt": "two"})

	workA := filepath.Join(t.TempDir(), "worka")
	if err := Clone(remoteURL(name), workA, nil); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if st, err := Status(workA); err != nil || strings.TrimSpace(st) != "" {
		t.Fatalf("expected clean tree, got status %q err %v", st, err)
	}

	// Second clone happens before A pushes, so its pull has real work to do.
	workB := filepath.Join(t.TempDir(), "workb")
	if err := Clone(remoteURL(name), workB, nil); err != nil {
		t.Fatalf("Clone B: %v", err)
	}

	if err := writeRel(workA, "a.txt", "one-updated"); err != nil {
		t.Fatal(err)
	}
	if err := Add(workA, "a.txt"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := Commit(workA, "update a", "Tester", "t@example.com"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := Push(workA, nil); err != nil {
		t.Fatalf("Push: %v", err)
	}

	if err := Pull(workB, nil); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if got := readFile(t, filepath.Join(workB, "a.txt")); got != "one-updated" {
		t.Fatalf("a.txt after pull = %q, want one-updated", got)
	}
}

func TestPullConflictDetected(t *testing.T) {
	name := "repo2"
	makeRemote(t, name)
	seedRemote(t, name, map[string]string{"a.txt": "base"})

	workA := filepath.Join(t.TempDir(), "worka")
	workB := filepath.Join(t.TempDir(), "workb")
	if err := Clone(remoteURL(name), workA, nil); err != nil {
		t.Fatal(err)
	}
	if err := Clone(remoteURL(name), workB, nil); err != nil {
		t.Fatal(err)
	}

	commitBoth := func(dir string) {
		if err := writeRel(dir, "a.txt", filepath.Base(dir)); err != nil {
			t.Fatal(err)
		}
		if err := Add(dir, "a.txt"); err != nil {
			t.Fatal(err)
		}
		if _, err := Commit(dir, "divergence from "+filepath.Base(dir), "T", "t@x"); err != nil {
			t.Fatal(err)
		}
	}
	commitBoth(workA)
	commitBoth(workB)
	if err := Push(workA, nil); err != nil {
		t.Fatalf("Push A: %v", err)
	}
	// The in-process server must know B's divergent objects for the haves walk,
	// so mirror B's tip to a side ref (a real git server would already have it).
	if err := pushSideRef(t, workB, "conflict-b"); err != nil {
		t.Fatalf("push side ref: %v", err)
	}

	err := Pull(workB, nil)
	if err == nil {
		t.Fatal("expected pull to report a conflict")
	}
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got: %v", err)
	}
	if got := readFile(t, filepath.Join(workB, "a.txt")); got != "workb" {
		t.Fatalf("conflict clobbered local work: a.txt = %q", got)
	}
}

func TestRemoteURLAndBranch(t *testing.T) {
	name := "repo3"
	makeRemote(t, name)
	seedRemote(t, name, map[string]string{"a.txt": "x"})

	work := filepath.Join(t.TempDir(), "work")
	if err := Clone(remoteURL(name), work, nil); err != nil {
		t.Fatal(err)
	}
	got, err := RemoteURL(work)
	if err != nil {
		t.Fatalf("RemoteURL: %v", err)
	}
	if got != remoteURL(name) {
		t.Fatalf("RemoteURL = %q, want %q", got, remoteURL(name))
	}
	branch, err := CurrentBranch(work)
	if err != nil {
		t.Fatalf("CurrentBranch: %v", err)
	}
	if branch != "master" && branch != "main" {
		t.Fatalf("unexpected branch %q", branch)
	}
}

func TestCloneRefusesNonEmptyDir(t *testing.T) {
	name := "repo4"
	makeRemote(t, name)
	seedRemote(t, name, map[string]string{"a.txt": "x"})

	target := filepath.Join(t.TempDir(), "existing")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep.txt"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Clone(remoteURL(name), target, nil); err == nil {
		t.Fatal("expected clone into a non-empty directory to fail")
	}
}

func TestCommitUpToDate(t *testing.T) {
	name := "repo5"
	makeRemote(t, name)
	seedRemote(t, name, map[string]string{"a.txt": "x"})

	work := filepath.Join(t.TempDir(), "work")
	if err := Clone(remoteURL(name), work, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(work, "nothing to commit", "T", "t@x"); !errors.Is(err, ErrUpToDate) {
		t.Fatalf("expected ErrUpToDate for an empty commit, got %v", err)
	}
}

func TestOriginRemoteConfig(t *testing.T) {
	name := "repo6"
	makeRemote(t, name)
	seedRemote(t, name, map[string]string{"a.txt": "x"})

	work := filepath.Join(t.TempDir(), "work")
	if err := Clone(remoteURL(name), work, nil); err != nil {
		t.Fatal(err)
	}
	repo, err := Open(work)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rem, err := repo.Remote("origin")
	if err != nil {
		t.Fatalf("Remote origin: %v", err)
	}
	if len(rem.Config().URLs) == 0 || rem.Config().URLs[0] != remoteURL(name) {
		t.Fatalf("origin URLs = %v", rem.Config().URLs)
	}
}

func TestRemoveAndCommit(t *testing.T) {
	name := "repo7"
	makeRemote(t, name)
	seedRemote(t, name, map[string]string{"a.txt": "x", "b.txt": "y"})

	work := filepath.Join(t.TempDir(), "work")
	if err := Clone(remoteURL(name), work, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(work, "a.txt")); err != nil {
		t.Fatal(err)
	}
	if err := Remove(work, "a.txt"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := Commit(work, "remove a.txt", "T", "t@x"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	st, err := Status(work)
	if err != nil || strings.TrimSpace(st) != "" {
		t.Fatalf("expected clean tree after commit, got status %q err %v", st, err)
	}
}

func TestRepoStateAheadBehind(t *testing.T) {
	name := "repo8"
	makeRemote(t, name)
	seedRemote(t, name, map[string]string{"a.txt": "x"})

	work := filepath.Join(t.TempDir(), "work")
	if err := Clone(remoteURL(name), work, nil); err != nil {
		t.Fatal(err)
	}

	state, err := GetRepoState(work)
	if err != nil {
		t.Fatalf("GetRepoState: %v", err)
	}
	if state.Branch == "" {
		t.Fatal("expected a branch name")
	}
	if !state.HasRemote {
		t.Fatal("expected remote to be present")
	}
	if state.Ahead != 0 || state.Behind != 0 {
		t.Fatalf("expected in sync, got ahead=%d behind=%d", state.Ahead, state.Behind)
	}
	if !state.IsClean {
		t.Fatal("expected clean working tree")
	}

	if err := writeRel(work, "b.txt", "y"); err != nil {
		t.Fatal(err)
	}
	if err := Add(work, "b.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(work, "add b", "T", "t@x"); err != nil {
		t.Fatal(err)
	}

	state, err = GetRepoState(work)
	if err != nil {
		t.Fatalf("GetRepoState after local commit: %v", err)
	}
	if state.Ahead != 1 {
		t.Fatalf("ahead = %d, want 1", state.Ahead)
	}
	if state.Behind != 0 {
		t.Fatalf("behind = %d, want 0", state.Behind)
	}
	if !state.IsClean {
		t.Fatal("expected clean working tree after commit")
	}

	if err := Push(work, nil); err != nil {
		t.Fatalf("Push: %v", err)
	}
	state, err = GetRepoState(work)
	if err != nil {
		t.Fatalf("GetRepoState after push: %v", err)
	}
	if state.Ahead != 0 || state.Behind != 0 {
		t.Fatalf("expected in sync after push, got ahead=%d behind=%d", state.Ahead, state.Behind)
	}
}

// mockSigner implements the sshx.Signer interface for PublicKeys tests.
type mockSigner struct{ signer ssh.Signer }

func (m *mockSigner) Signer() ssh.Signer { return m.signer }

func TestPublicKeysBuildsAuth(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	auth := PublicKeys("git", &mockSigner{signer: signer}, func(_ string, _ net.Addr, _ ssh.PublicKey) error { return nil })
	if auth == nil {
		t.Fatal("PublicKeys returned nil")
	}
}

func TestFetchUpToDate(t *testing.T) {
	name := "repo-fetch"
	makeRemote(t, name)
	seedRemote(t, name, map[string]string{"a.txt": "x"})

	work := filepath.Join(t.TempDir(), "work")
	if err := Clone(remoteURL(name), work, nil); err != nil {
		t.Fatal(err)
	}
	if err := Fetch(work, nil); !errors.Is(err, ErrUpToDate) {
		t.Fatalf("expected ErrUpToDate, got %v", err)
	}
}

func TestGetRepoStateWithoutRemote(t *testing.T) {
	work := t.TempDir()
	if _, err := goGit.PlainInit(work, false); err != nil {
		t.Fatal(err)
	}
	if err := writeRel(work, "a.txt", "x"); err != nil {
		t.Fatal(err)
	}
	if err := Add(work, "a.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(work, "init", "T", "t@x"); err != nil {
		t.Fatal(err)
	}
	state, err := GetRepoState(work)
	if err != nil {
		t.Fatalf("GetRepoState: %v", err)
	}
	if state.HasRemote {
		t.Fatal("expected no remote")
	}
	if state.Branch == "" {
		t.Fatal("expected a branch name")
	}
}
