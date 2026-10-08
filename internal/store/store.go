package store

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/oxcafedead/passone/internal/config"
)

// ErrNoGPGID is returned when a directory does not look like a pass store.
var ErrNoGPGID = errors.New("not a pass store: no .gpg-id file found")

// Store manages a pass-format password store rooted at a directory.
type Store struct {
	root   string
	gpgIDs []string
}

// Open validates that dir is a pass store and loads the .gpg-id recipients.
func Open(dir string) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	ids, err := readGPGID(filepath.Join(abs, ".gpg-id"))
	if err != nil {
		return nil, ErrNoGPGID
	}
	return &Store{root: abs, gpgIDs: ids}, nil
}

// Root returns the absolute store root directory.
func (s *Store) Root() string { return s.root }

// GPGIDs returns the parsed encryption recipients from .gpg-id.
func (s *Store) GPGIDs() []string { return append([]string(nil), s.gpgIDs...) }

// Create initializes a new pass store at dir with the given recipients.
func Create(dir string, gpgIDs []string) (*Store, error) {
	if len(gpgIDs) == 0 {
		return nil, errors.New("cannot initialize a store without recipients")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	if err := writeGPGID(filepath.Join(abs, ".gpg-id"), gpgIDs); err != nil {
		return nil, err
	}
	return Open(abs)
}

// readGPGID parses a .gpg-id file into its non-empty lines.
func readGPGID(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var ids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ids = append(ids, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, ErrNoGPGID
	}
	return ids, nil
}

func writeGPGID(file string, ids []string) error {
	content := strings.Join(ids, "\n") + "\n"
	return os.WriteFile(file, []byte(content), 0o600)
}

// relSafe converts a virtual password path (e.g. "github/personal") into a
// safe relative filesystem path inside the store, rejecting attempts to
// escape the store root. It returns the full target path and the name of the
// .gpg file as pass would name it.
func (s *Store) relSafe(p string) (string, error) {
	cleaned := path.Clean(strings.ReplaceAll(p, "\\", "/"))
	if cleaned == "." || cleaned == "" {
		return "", errors.New("invalid password path")
	}
	if strings.HasPrefix(cleaned, "/") || strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, "../") {
		return "", errors.New("invalid password path: must stay inside the store")
	}
	rel := filepath.FromSlash(cleaned)
	full := filepath.Join(s.root, rel)
	// Belt and braces: ensure the resolved path is still inside the root.
	rootAbs, _ := filepath.Abs(s.root)
	fullAbs, _ := filepath.Abs(full)
	if rel != "" && !strings.HasPrefix(fullAbs+string(os.PathSeparator), rootAbs+string(os.PathSeparator)) {
		return "", errors.New("password path escapes the store")
	}
	return full, nil
}

// ListPasswords recursively lists all passwords as virtual paths without the
// .gpg extension, using forward slashes. It does not decrypt anything.
func (s *Store) ListPasswords() ([]string, error) {
	var out []string
	err := filepath.Walk(s.root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(p) != ".gpg" {
			return nil
		}
		rel, err := filepath.Rel(s.root, p)
		if err != nil {
			return err
		}
		virtual := filepath.ToSlash(rel)
		virtual = strings.TrimSuffix(virtual, ".gpg")
		out = append(out, virtual)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// Read returns the raw encrypted bytes of a password file. A missing password
// is reported as an error containing ErrNotExist wrapped by os.
func (s *Store) Read(p string) ([]byte, error) {
	full, err := s.relSafe(p)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(full + ".gpg")
}

// WriteEncrypted atomically replaces the .gpg file for password p. The
// previous file is only touched after the new ciphertext is fully written.
func (s *Store) WriteEncrypted(p string, ciphertext []byte) error {
	full, err := s.relSafe(p)
	if err != nil {
		return err
	}
	target := full + ".gpg"
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, ciphertext, 0o600); err != nil {
		return err
	}
	if err := config.MoveFile(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Remove deletes the encrypted .gpg file for password p. Removing a password
// that does not exist reports an error.
func (s *Store) Remove(p string) error {
	full, err := s.relSafe(p)
	if err != nil {
		return err
	}
	target := full + ".gpg"
	if err := os.Remove(target); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("password not found: %s", p)
		}
		return err
	}
	return nil
}

// Move renames the encrypted .gpg file for password from to to, creating any
// missing parent directory of the new path. The ciphertext is moved as-is: a
// rename never decrypts and never re-encrypts, so it cannot alter a secret or
// depend on the recipients still being resolvable. Moving onto an existing
// password is refused rather than overwriting it, and a missing source is
// reported like Remove reports one.
func (s *Store) Move(from, to string) error {
	srcFull, err := s.relSafe(from)
	if err != nil {
		return err
	}
	dstFull, err := s.relSafe(to)
	if err != nil {
		return err
	}
	if srcFull == dstFull {
		return fmt.Errorf("password is already named %s", to)
	}
	src := srcFull + ".gpg"
	dst := dstFull + ".gpg"
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("password not found: %s", from)
		}
		return err
	}
	// A case-only rename names the same file on a case-insensitive filesystem,
	// so it has to skip the "already there" refusal below and take the
	// two-step path in renameCase.
	caseOnly := strings.EqualFold(srcFull, dstFull)
	if !caseOnly {
		if _, err := os.Stat(dst); err == nil {
			return fmt.Errorf("password already exists: %s", to)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if caseOnly {
		return renameCase(src, dst)
	}
	return config.MoveFile(src, dst)
}

// renameCase renames src to dst when the two differ only in case. Windows
// resolves such a pair to one file, and whether a single replace-existing
// rename settles the new casing depends on the filesystem, so the file is
// parked under a scratch name first. A failure of the second step puts it back
// rather than leaving the entry with no file at all.
func renameCase(src, dst string) error {
	scratch := src + ".renaming"
	if err := config.MoveFile(src, scratch); err != nil {
		return err
	}
	if err := config.MoveFile(scratch, dst); err != nil {
		_ = config.MoveFile(scratch, src)
		return err
	}
	return nil
}

// Delete removes a password file. It returns os.ErrNotExist behavior wrapped
// for the caller to distinguish.
func (s *Store) Delete(p string) error {
	full, err := s.relSafe(p)
	if err != nil {
		return err
	}
	return os.Remove(full + ".gpg")
}

// Exists reports whether a password file exists.
func (s *Store) Exists(p string) (bool, error) {
	full, err := s.relSafe(p)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(full + ".gpg")
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ModTime reports when the password file for p was last written. The pass
// format keeps no timestamp inside the file, so the encrypted file's own
// modification time is the only record of when an entry changed: every save
// replaces the file wholesale, and a rename carries the source file's times
// over, so moving an entry does not pretend it was edited.
func (s *Store) ModTime(p string) (time.Time, error) {
	full, err := s.relSafe(p)
	if err != nil {
		return time.Time{}, err
	}
	info, err := os.Stat(full + ".gpg")
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, fmt.Errorf("password not found: %s", p)
		}
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// ValidateName returns a normalized virtual path for a new password.
func ValidateName(p string) (string, error) {
	cleaned := path.Clean(strings.ReplaceAll(p, "\\", "/"))
	if cleaned == "." || cleaned == "" || strings.HasPrefix(cleaned, "/") || strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("invalid password path %q", p)
	}
	for _, c := range cleaned {
		if c < 32 {
			return "", fmt.Errorf("invalid character in password path %q", p)
		}
	}
	return cleaned, nil
}
