package gitx

import (
	"errors"
	"fmt"
	"os"
	"time"

	goGit "github.com/go-git/go-git/v5"
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
		if errors.Is(err, goGit.NoErrAlreadyUpToDate) {
			return ErrUpToDate
		}
		return fmt.Errorf("fetch failed: %v", err)
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
	force := true
	err = wt.Pull(&goGit.PullOptions{
		RemoteName: "origin",
		Auth:       auth,
		Force:      force,
	})
	if err != nil {
		switch {
		case errors.Is(err, goGit.NoErrAlreadyUpToDate):
			return ErrUpToDate
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
