package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oxcafedead/passone/internal/gitx"
	"github.com/oxcafedead/passone/internal/pgp"
	"github.com/oxcafedead/passone/internal/security"
	"github.com/oxcafedead/passone/internal/store"
)

// ErrKeyExists reports that an OpenPGP key is already held, so a second one
// would either replace the key every existing store's .gpg-id names or be
// orphaned on disk. Generating is a first-run action; rotating the key of a
// live vault is a different job, and one that has to re-encrypt every entry.
var ErrKeyExists = errors.New("an OpenPGP key is already loaded; use the existing key, or remove it before generating a new one")

// ErrNoPGPKey reports that store creation was attempted with no OpenPGP key in
// memory. A new store is encrypted to a key, and the only key the app can
// guarantee it can read back later is the one it holds.
var ErrNoPGPKey = errors.New("no OpenPGP key is loaded: generate or import one first, because a new store is encrypted to it")

// GeneratePGPKey creates a new OpenPGP key pair and takes it through exactly the
// same path as an imported one: keyPassphrase protects the key itself,
// lockPassword seals the resulting blob in the vault, and the fingerprint is
// recorded so a store created next has a default recipient.
//
// Handing the block to ImportPGPKey rather than storing it a second way is
// deliberate. Sealing, config, the auto-lock timer and the arming of key
// material in memory all live on the import path; a parallel "generated" path
// would be a second implementation of the vault lifecycle, and the two would
// drift. The generated key also exists nowhere but the sealed vault, so the
// user is responsible for the passphrase: nothing can be re-derived from a
// fingerprint.
//
// It refuses when a key is already loaded (ErrKeyExists) rather than replacing
// it. Every store names the current fingerprint in its .gpg-id, so quietly
// generating a replacement would leave those stores undecryptable with no
// obvious cause.
func (a *App) GeneratePGPKey(name, email string, keyPassphrase, lockPassword []byte) ([]*pgp.KeyInfo, error) {
	if a.HasStoredPGPKey() {
		return nil, ErrKeyExists
	}
	// Key material resident but not yet sealed (an import that was interrupted,
	// or a key still in memory from this session) counts too: generating over it
	// would lose it.
	a.mu.Lock()
	resident := len(a.pgpSvc.DescribeOwn()) > 0
	a.mu.Unlock()
	if resident {
		return nil, ErrKeyExists
	}

	block, err := pgp.Generate(pgp.GenerateOptions{
		Name:       name,
		Email:      email,
		Passphrase: keyPassphrase,
	})
	if err != nil {
		return nil, err
	}
	defer security.Zero(block)
	return a.ImportPGPKey(block, keyPassphrase, lockPassword)
}

// CreateStore creates a new pass store at dir, encrypted to the single OpenPGP
// key the app holds, and makes it the active store.
//
// The directory becomes a git repository on main whose first commit records
// .gpg-id, so a created store is a complete pass store from the first second:
// it lists entries, syncs, and clones on another machine. A remote is optional
// and is recorded as origin without being contacted. Pushing is left to an
// explicit Sync, for two reasons: creating a store must not depend on a server
// being reachable, and it must not publish a vault before the user has decided
// what goes in it. The first Sync of such a store is a pure push, which is why
// gitx reports an empty remote as a state rather than a failure.
//
// dir must be empty. A directory that is already a pass store is reported as
// such, so the user opens it instead of creating a second one over it, and a
// directory holding anything else is refused outright: this writes a .gpg-id and
// a whole .git into whatever path it is handed.
func (a *App) CreateStore(dir, remote string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return errors.New("a folder is required to create a store")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	remote = strings.TrimSpace(remote)

	// Resolve the recipient before touching the filesystem: a store created
	// with no key to encrypt to would be unreadable, and the user would only
	// find out when they tried to read their first entry.
	a.mu.Lock()
	fp, err := a.pgpSvc.SinglePrimaryFingerprint()
	a.mu.Unlock()
	if err != nil {
		return ErrNoPGPKey
	}

	if _, err := store.Open(abs); err == nil {
		return fmt.Errorf("%s is already a pass store; open it instead of creating a new one", abs)
	}
	entries, err := os.ReadDir(abs)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s is not empty and is not a pass store; refusing to create a store in it", abs)
	}
	// Remember whether the folder already existed so a failure below can leave
	// the filesystem as it found it rather than dropping a directory the user
	// made themselves.
	_, statErr := os.Stat(abs)
	preexisting := statErr == nil

	if err := a.buildStore(abs, fp, remote); err != nil {
		discardPartialStore(abs, preexisting)
		return err
	}

	st, err := store.Open(abs)
	if err != nil {
		discardPartialStore(abs, preexisting)
		return fmt.Errorf("the store could not be read back after creation: %v", err)
	}
	a.mu.Lock()
	a.store = st
	a.cfg.StorePath = st.Root()
	if remote != "" {
		a.cfg.GitRemote = remote
	}
	a.mu.Unlock()
	return a.saveConfig()
}

// buildStore writes a new store: repository, .gpg-id, and the initial commit
// that ties them together.
func (a *App) buildStore(abs, fingerprint, remote string) error {
	if err := gitx.Init(abs, remote); err != nil {
		return err
	}
	if _, err := store.Create(abs, []string{fingerprint}); err != nil {
		return err
	}
	if err := gitx.Add(abs, ".gpg-id"); err != nil {
		return err
	}
	author, email := a.gitAuthor()
	if _, err := gitx.Commit(abs, "Initialise password store", author, email); err != nil {
		return err
	}
	return nil
}

// discardPartialStore removes what a failed creation left behind, and nothing
// else. A directory that existed and was empty before the attempt keeps its
// name; a directory this process created is removed entirely.
func discardPartialStore(abs string, preexisting bool) {
	_ = os.RemoveAll(filepath.Join(abs, ".git"))
	_ = os.Remove(filepath.Join(abs, ".gpg-id"))
	if !preexisting {
		_ = os.Remove(abs)
	}
}

// DefaultStoreDir turns a name typed into the wizard's folder field into a path
// under the application stores directory, so a created store is listed by
// StoredStores and sits beside the cloned ones. A name is a name, not a path: a
// value carrying a separator is rejected ("" tells the UI the field is invalid)
// so a stray slash cannot quietly create a store in an unexpected place. An
// absolute path is passed through, because a user who pasted one means it.
func (a *App) DefaultStoreDir(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return a.paths.StoresDir
	}
	if filepath.IsAbs(name) {
		return name
	}
	if strings.ContainsAny(name, `/\`) {
		return ""
	}
	if name == "." || name == ".." {
		return ""
	}
	return filepath.Join(a.paths.StoresDir, name)
}
