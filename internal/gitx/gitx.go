package gitx

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	goGit "github.com/go-git/go-git/v5"
	goGitConfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	goGitSSH "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/oxcafedead/passone/internal/config"
	"golang.org/x/crypto/ssh"
)

// ErrConflict is returned when pull/merge cannot integrate remote changes
// automatically. The caller must surface it to the user.
var ErrConflict = errors.New("sync conflict")

// ErrUpToDate is returned when pull finds nothing new.
var ErrUpToDate = errors.New("already up to date")

// ErrRemoteEmpty is returned when the origin remote exists but carries no refs
// yet. A store created locally with a remote URL configured is in that state
// until its first push, so callers treat it as "nothing to fetch" rather than as
// a failure.
var ErrRemoteEmpty = errors.New("the remote repository is empty")

// Signer wraps the application SSH key for use by go-git.
type Signer interface {
	Signer() ssh.Signer
}

// PublicKeys builds a go-git SSH auth method using our in-memory signer and
// our own host-key callback. This is the only SSH path go-git uses; nothing
// is shelled out and no system SSH configuration is consulted.
func PublicKeys(user string, s Signer, hostKeyCallback ssh.HostKeyCallback) transport.AuthMethod {
	return &goGitSSH.PublicKeys{
		User:   user,
		Signer: s.Signer(),
		HostKeyCallbackHelper: goGitSSH.HostKeyCallbackHelper{
			HostKeyCallback: hostKeyCallback,
		},
	}
}

// Clone clones an SSH git repository into dir using the given auth method.
func Clone(url, dir string, auth transport.AuthMethod) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	empty, err := config.DirIsEmpty(dir)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("target directory %q is not empty; refusing to clone into it", dir)
	}
	_, err = goGit.PlainClone(dir, false, &goGit.CloneOptions{
		URL:   url,
		Auth:  auth,
		Depth: 0,
	})
	if err != nil {
		return fmt.Errorf("clone failed: %v", err)
	}
	return nil
}

// DefaultBranch is the branch name a store is created on. gpg-agent-era
// tooling has moved to main, and pinning it here keeps a store created today
// consistent with one cloned from a remote whose default branch is main.
const DefaultBranch = "main"

// Init turns dir into a git repository with no commits, checked out on
// DefaultBranch. An empty remote (or one containing only whitespace) is
// accepted and means "no remote"; any other value is recorded as origin.
//
// This is the counterpart of Clone for the case where there is nothing to
// clone yet: a store the user just made is a plain directory until something
// turns it into a repository, and until then Status, Sync and the tray's git
// indicators have nothing to report.
//
// The repository is left without a commit on purpose. The first commit should
// be the one that records the store's real initial state, and Commit already
// falls back to a usable author when none is configured.
func Init(dir, remote string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	empty, err := config.DirIsEmpty(dir)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("directory %q is not empty; refusing to initialise a repository in it", dir)
	}
	repo, err := goGit.PlainInitWithOptions(dir, &goGit.PlainInitOptions{
		InitOptions: goGit.InitOptions{DefaultBranch: plumbing.NewBranchReferenceName(DefaultBranch)},
		Bare:        false,
	})
	if err != nil {
		return fmt.Errorf("git init failed: %v", err)
	}
	if url := strings.TrimSpace(remote); url != "" {
		if _, err := repo.CreateRemote(&goGitConfig.RemoteConfig{
			Name: "origin",
			URLs: []string{url},
		}); err != nil {
			return fmt.Errorf("unable to record the remote: %v", err)
		}
	}
	return nil
}

// SetRemote records url as the origin remote of the repository in dir,
// replacing any remote already configured under that name.
func SetRemote(dir, url string) error {
	url = strings.TrimSpace(url)
	if url == "" {
		return errors.New("remote URL is empty")
	}
	repo, err := Open(dir)
	if err != nil {
		return err
	}
	if _, err := repo.CreateRemote(&goGitConfig.RemoteConfig{
		Name: "origin",
		URLs: []string{url},
	}); err != nil {
		if !errors.Is(err, goGit.ErrRemoteExists) {
			return fmt.Errorf("unable to record the remote: %v", err)
		}
		if err := repo.DeleteRemote("origin"); err != nil {
			return fmt.Errorf("unable to replace the existing remote: %v", err)
		}
		if _, err := repo.CreateRemote(&goGitConfig.RemoteConfig{
			Name: "origin",
			URLs: []string{url},
		}); err != nil {
			return fmt.Errorf("unable to record the remote: %v", err)
		}
	}
	return nil
}

// Open opens an existing git repository in dir.
func Open(dir string) (*goGit.Repository, error) {
	return goGit.PlainOpen(dir)
}

// RemoteURL returns the origin remote URL, if any.
func RemoteURL(dir string) (string, error) {
	repo, err := Open(dir)
	if err != nil {
		return "", err
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		return "", err
	}
	urls := remote.Config().URLs
	if len(urls) == 0 {
		return "", errors.New("origin remote has no URL")
	}
	return urls[0], nil
}

// Status returns the porcelain-ish status of the worktree.
func Status(dir string) (string, error) {
	repo, err := Open(dir)
	if err != nil {
		return "", err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return "", err
	}
	st, err := wt.Status()
	if err != nil {
		return "", err
	}
	return st.String(), nil
}

// RepoState is a snapshot of the local git repository useful for UI status
// panels.
type RepoState struct {
	Branch     string
	RemoteURL  string
	Head       string
	LastCommit string
	IsClean    bool
	Ahead      int
	Behind     int
	HasRemote  bool
	IsDiverged bool
	// HasRemoteBranch reports whether refs/remotes/origin/<branch> exists,
	// which is only true after a fetch from a remote that actually has this
	// branch. It separates "in sync" from "never pushed", which are otherwise
	// the same zero counts: a store created with init-store and a remote is
	// ahead of nothing in particular until the first push.
	HasRemoteBranch bool
}

// GetRepoState collects branch, remote, last commit and ahead/behind counts.
//
// A repository that exists but has no commit yet is not an error: that is
// exactly the state a freshly created store is in, and reporting it as a
// failure would make Status and Sync unusable for a brand new store. In that
// case the branch comes from the symbolic HEAD, Head and LastCommit stay empty
// and the ahead/behind counts are zero.
func GetRepoState(dir string) (RepoState, error) {
	repo, err := Open(dir)
	if err != nil {
		return RepoState{}, err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return RepoState{}, err
	}
	st, err := wt.Status()
	if err != nil {
		return RepoState{}, err
	}

	state := RepoState{
		IsClean:   st.IsClean(),
		HasRemote: false,
	}

	head, err := repo.Head()
	switch {
	case err == nil:
		state.Branch = head.Name().Short()
		state.Head = head.Hash().String()[:7]
		if commit, err := repo.CommitObject(head.Hash()); err == nil {
			state.LastCommit = strings.Split(commit.Message, "\n")[0]
		}
	case errors.Is(err, plumbing.ErrReferenceNotFound):
		// Unborn HEAD: the branch exists as a name only.
		state.Branch = currentBranchName(repo)
	default:
		return RepoState{}, err
	}

	remote, err := repo.Remote("origin")
	if err != nil || len(remote.Config().URLs) == 0 {
		return state, nil
	}
	state.RemoteURL = remote.Config().URLs[0]
	state.HasRemote = true

	// Without a local commit there is nothing to compare against the remote.
	if state.Head == "" {
		return state, nil
	}

	remoteRef, err := repo.Reference(plumbing.NewRemoteReferenceName("origin", state.Branch), true)
	if err != nil {
		return state, nil
	}
	state.HasRemoteBranch = true

	ahead, _ := countCommitsUntil(repo, head.Hash(), remoteRef.Hash())
	behind, _ := countCommitsUntil(repo, remoteRef.Hash(), head.Hash())

	switch {
	case ahead == 0 && behind == 0:
		// in sync
	case ahead > 0 && behind < 0:
		state.Ahead = ahead
	case behind > 0 && ahead < 0:
		state.Behind = behind
	default:
		state.IsDiverged = true
	}
	return state, nil
}

// currentBranchName returns the branch a symbolic HEAD points at, e.g. "main"
// for a repository whose first commit has not been made yet. It returns
// plumbing.Master.Reference().Short() as a last resort so callers always get a
// usable name.
func currentBranchName(repo *goGit.Repository) string {
	ref, err := repo.Reference(plumbing.HEAD, false)
	if err != nil || ref == nil || ref.Type() != plumbing.SymbolicReference {
		return plumbing.Master.Short()
	}
	return ref.Target().Short()
}

// HasCommits reports whether the repository in dir has at least one commit on
// the current branch. A newly initialised store has none, and callers that
// would otherwise pull or diff have to know that first.
func HasCommits(dir string) (bool, error) {
	repo, err := Open(dir)
	if err != nil {
		return false, err
	}
	if _, err := repo.Head(); err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// HasRemoteBranch reports whether the origin remote already carries a branch of
// that name. A store created locally with a remote recorded but nothing pushed
// yet is the case this exists for: there is nothing to pull from, but there is
// everything to push.
func HasRemoteBranch(dir, branch string) (bool, error) {
	repo, err := Open(dir)
	if err != nil {
		return false, err
	}
	if _, err := repo.Remote("origin"); err != nil {
		// A missing origin is a normal state for a local-only store, not an
		// error to report, whatever go-git names it.
		return false, nil
	}
	remoteRef := plumbing.NewRemoteReferenceName("origin", branch)
	if _, err := repo.Reference(remoteRef, true); err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func countCommitsUntil(repo *goGit.Repository, from, to plumbing.Hash) (int, error) {
	if from == to {
		return 0, nil
	}
	seen := make(map[plumbing.Hash]bool)
	current := from
	count := 0
	for current != to {
		if seen[current] {
			return -1, nil
		}
		seen[current] = true
		commit, err := repo.CommitObject(current)
		if err != nil {
			return 0, err
		}
		if commit.NumParents() == 0 {
			return -1, nil
		}
		current = commit.ParentHashes[0]
		count++
		if count > 10000 {
			return -1, nil
		}
	}
	return count, nil
}

// Fetch contacts the origin remote and updates refs without merging.
func Fetch(dir string, auth transport.AuthMethod) error {
	repo, err := Open(dir)
	if err != nil {
		return err
	}
	err = repo.Fetch(&goGit.FetchOptions{
		RemoteName: "origin",
		Auth:       auth,
	})
	if err != nil {
		switch {
		case errors.Is(err, goGit.NoErrAlreadyUpToDate):
			return ErrUpToDate
		case errors.Is(err, transport.ErrEmptyRemoteRepository):
			// The remote exists but holds no refs yet. For a store created here
			// with a remote recorded but nothing pushed, that is the normal
			// first-sync state, not a failure.
			return ErrRemoteEmpty
		default:
			return fmt.Errorf("fetch failed: %v", err)
		}
	}
	return nil
}

// Pull fetches and integrates remote changes for the current branch.
func Pull(dir string, auth transport.AuthMethod) error {
	repo, err := Open(dir)
	if err != nil {
		return err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}
	opts := &goGit.PullOptions{
		RemoteName: "origin",
		Auth:       auth,
		Force:      true,
	}
	// Pull the branch the worktree is actually on. With ReferenceName left empty,
	// go-git resolves HEAD, and a bare repository created before main became
	// the default still points HEAD at master — so a store on main would fail to
	// pull with "reference not found". The name has to be a plain branch name,
	// not refs/remotes/origin/...: go-git resolves it against the refs the
	// server advertised, and only those exist there. A store with no commit yet
	// has no branch to name and takes go-git's own resolution.
	if branch, err := CurrentBranch(dir); err == nil && branch != "" {
		opts.ReferenceName = plumbing.NewBranchReferenceName(branch)
	}
	err = wt.Pull(opts)
	if err != nil {
		switch {
		case errors.Is(err, goGit.NoErrAlreadyUpToDate):
			return ErrUpToDate
		case errors.Is(err, transport.ErrEmptyRemoteRepository):
			return ErrRemoteEmpty
		case errors.Is(err, goGit.ErrNonFastForwardUpdate):
			return fmt.Errorf("%w: local and remote histories have diverged; refusing to overwrite remote data", ErrConflict)
		default:
			return fmt.Errorf("pull failed: %v", err)
		}
	}
	return nil
}

// Add stages one or more paths in the worktree.
func Add(dir string, paths ...string) error {
	repo, err := Open(dir)
	if err != nil {
		return err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}
	for _, p := range paths {
		if _, err := wt.Add(p); err != nil {
			return err
		}
	}
	return nil
}

// Remove stages the removal of one or more paths in the worktree.
func Remove(dir string, paths ...string) error {
	repo, err := Open(dir)
	if err != nil {
		return err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}
	for _, p := range paths {
		if _, err := wt.Remove(p); err != nil {
			return err
		}
	}
	return nil
}

// Commit commits staged changes with the given message.
func Commit(dir, message string, authorName, authorEmail string) (string, error) {
	repo, err := Open(dir)
	if err != nil {
		return "", err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return "", err
	}
	if authorName == "" {
		authorName = "Gopass Desktop"
	}
	if authorEmail == "" {
		authorEmail = "passone@localhost"
	}
	h, err := wt.Commit(message, &goGit.CommitOptions{
		Author: &object.Signature{
			Name:  authorName,
			Email: authorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		if errors.Is(err, goGit.ErrEmptyCommit) {
			return "", ErrUpToDate
		}
		return "", fmt.Errorf("commit failed: %v", err)
	}
	return h.String(), nil
}

// Push uploads local commits to origin.
func Push(dir string, auth transport.AuthMethod) error {
	repo, err := Open(dir)
	if err != nil {
		return err
	}
	err = repo.Push(&goGit.PushOptions{
		RemoteName: "origin",
		Auth:       auth,
	})
	if err != nil {
		if errors.Is(err, goGit.NoErrAlreadyUpToDate) {
			return ErrUpToDate
		}
		return fmt.Errorf("push failed: %v", err)
	}
	return nil
}

// CurrentBranch returns the name of the currently checked-out branch.
func CurrentBranch(dir string) (string, error) {
	repo, err := Open(dir)
	if err != nil {
		return "", err
	}
	head, err := repo.Head()
	if err != nil {
		return "", err
	}
	if head.Name().IsBranch() {
		return head.Name().Short(), nil
	}
	return "", errors.New("HEAD is detached")
}
