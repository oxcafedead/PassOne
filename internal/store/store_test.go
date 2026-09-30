package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateAndOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "passwords")
	st, err := Create(dir, []string{"AAAA-BBBB-CCCC", "another-user"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := st.GPGIDs()
	if len(got) != 2 || got[0] != "AAAA-BBBB-CCCC" {
		t.Fatalf("GPGIDs = %v", got)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !reopened.ExistsOnDisk() {
		t.Fatal("Open result should be backed by the on-disk store")
	}
	if len(reopened.GPGIDs()) != 2 {
		t.Fatalf("reopened GPGIDs = %v", reopened.GPGIDs())
	}
}

func (s *Store) ExistsOnDisk() bool {
	_, err := os.Stat(filepath.Join(s.root, ".gpg-id"))
	return err == nil
}

func TestOpenRejectsNonStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "empty")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err != ErrNoGPGID {
		t.Fatalf("expected ErrNoGPGID, got %v", err)
	}
}

func TestGPGIDSkipsCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	content := "# comment\n\n  AABBCCDD\n  \n# another\nFF000011\n"
	if err := os.WriteFile(filepath.Join(dir, ".gpg-id"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ids := st.GPGIDs()
	if len(ids) != 2 || ids[0] != "AABBCCDD" || ids[1] != "FF000011" {
		t.Fatalf("GPGIDs = %v", ids)
	}
}

func TestListPasswords(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gpg-id"), []byte("AA"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustWrite := func(name, data string) {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".gpg"), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("github/personal", "cipher1")
	mustWrite("github/fromapp", "cipher2")
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gpg-id.tmp"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	listed, err := st.ListPasswords()
	if err != nil {
		t.Fatalf("ListPasswords: %v", err)
	}
	want := []string{"github/fromapp", "github/personal"}
	if len(listed) != len(want) {
		t.Fatalf("ListPasswords = %v, want %v", listed, want)
	}
	for i := range want {
		if listed[i] != want[i] {
			t.Fatalf("ListPasswords = %v, want %v", listed, want)
		}
	}
}

func TestWriteReadDelete(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.WriteEncrypted("github/personal", []byte("CIPHER")); err != nil {
		t.Fatalf("WriteEncrypted: %v", err)
	}
	exists, err := st.Exists("github/personal")
	if err != nil || !exists {
		t.Fatalf("Exists: %v %v", exists, err)
	}
	data, err := st.Read("github/personal")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(data) != "CIPHER" {
		t.Fatalf("Read = %q", data)
	}
	if err := st.Delete("github/personal"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Read("github/personal"); !os.IsNotExist(err) {
		t.Fatalf("expected not-exist after delete, got %v", err)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	bad := []string{"../evil", "../../etc/passwd", "/abs/path", "..", "a/../../b"}
	for _, p := range bad {
		if _, err := st.Read(p); err == nil {
			t.Fatalf("expected traversal %q to be rejected", p)
		}
		if err := st.WriteEncrypted(p, []byte("x")); err == nil {
			t.Fatalf("expected traversal write %q to be rejected", p)
		}
	}
	// Ensure nothing escaped the store.
	evil := filepath.Join(filepath.Dir(dir), "evil.gpg")
	if _, err := os.Stat(evil); !os.IsNotExist(err) {
		t.Fatal("traversal write escaped the store root")
	}
}

func TestRelativeShorthandNormalizesInStore(t *testing.T) {
	// Backslash shorthand like a\..\evil is normalized (path.Clean) to a safe
	// in-store name and must never write outside the root.
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.WriteEncrypted("a\\..\\evil", []byte("x")); err != nil {
		t.Fatalf("WriteEncrypted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil.gpg")); err != nil {
		t.Fatalf("expected normalized evil.gpg inside store: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil.gpg")); !os.IsNotExist(err) {
		t.Fatal("write escaped the store root")
	}
}

func TestValidateName(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../x", "/abs", "a\x00b"} {
		if _, err := ValidateName(bad); err == nil {
			t.Fatalf("expected %q to be invalid", bad)
		}
	}
	got, err := ValidateName("github\\My Password")
	if err != nil {
		t.Fatalf("ValidateName: %v", err)
	}
	if !strings.Contains(got, " ") || !strings.Contains(got, "/") {
		t.Fatalf("ValidateName normalized = %q", got)
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.WriteEncrypted("a/b", []byte("CIPHER")); err != nil {
		t.Fatalf("WriteEncrypted: %v", err)
	}
	if err := st.Remove("a/b"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a", "b.gpg")); !os.IsNotExist(err) {
		t.Fatal("expected file to be gone after Remove")
	}
	if err := st.Remove("a/b"); err == nil {
		t.Fatal("expected a second Remove to fail")
	}
	if err := st.Remove("a/../evil"); err == nil {
		t.Fatal("expected traversal Remove to be rejected")
	}
}

func TestMove(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.WriteEncrypted("github/personal", []byte("CIPHER")); err != nil {
		t.Fatalf("WriteEncrypted: %v", err)
	}

	// A move into a folder that does not exist yet has to create it, and the
	// ciphertext has to arrive byte for byte: a move never re-encrypts, so
	// anything else would mean the secret was decrypted on the way.
	if err := st.Move("github/personal", "work/archive/github"); err != nil {
		t.Fatalf("Move: %v", err)
	}
	moved, err := st.Read("work/archive/github")
	if err != nil {
		t.Fatalf("Read after Move: %v", err)
	}
	if string(moved) != "CIPHER" {
		t.Fatalf("Move altered the ciphertext: %q", moved)
	}
	if _, err := st.Read("github/personal"); !os.IsNotExist(err) {
		t.Fatalf("expected the old path to be gone, got %v", err)
	}
	// The empty source folder is harmless, but it must not appear in the
	// listing: a directory with no entries is not a password.
	listed, err := st.ListPasswords()
	if err != nil {
		t.Fatalf("ListPasswords: %v", err)
	}
	if len(listed) != 1 || listed[0] != "work/archive/github" {
		t.Fatalf("ListPasswords = %v, want [work/archive/github]", listed)
	}
}

func TestMoveRenamesInPlace(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.WriteEncrypted("github/personal", []byte("CIPHER")); err != nil {
		t.Fatalf("WriteEncrypted: %v", err)
	}
	if err := st.Move("github/personal", "github/work"); err != nil {
		t.Fatalf("Move: %v", err)
	}
	if _, err := st.Read("github/work"); err != nil {
		t.Fatalf("Read after Move: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "github", "personal.gpg")); !os.IsNotExist(err) {
		t.Fatal("expected the old file to be gone after a rename in place")
	}
}

func TestMoveRefuses(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, p := range []string{"github/personal", "github/work"} {
		if err := st.WriteEncrypted(p, []byte("CIPHER-"+p)); err != nil {
			t.Fatalf("WriteEncrypted %q: %v", p, err)
		}
	}

	// Moving onto a live entry would destroy it, so it is refused and both
	// files keep their own contents.
	if err := st.Move("github/personal", "github/work"); err == nil {
		t.Fatal("expected a move onto an existing password to be refused")
	}
	for _, p := range []string{"github/personal", "github/work"} {
		data, err := st.Read(p)
		if err != nil {
			t.Fatalf("Read %q: %v", p, err)
		}
		if string(data) != "CIPHER-"+p {
			t.Fatalf("%q was overwritten by a refused move: %q", p, data)
		}
	}

	if err := st.Move("github/missing", "github/new"); err == nil {
		t.Fatal("expected a move of a missing password to fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "github", "new.gpg")); !os.IsNotExist(err) {
		t.Fatal("a failed move created the destination file")
	}

	if err := st.Move("github/personal", "github/personal"); err == nil {
		t.Fatal("expected a move onto itself to be refused")
	}
	// Backslash shorthand and . segments normalize the same way they do on a
	// read, so "a" and "a/" and "x\..\a" are all the same entry.
	if err := st.Move("x\\..\\github/personal", "github/./personal/../personal"); err == nil {
		t.Fatal("expected a normalized move onto itself to be refused")
	}
	for _, bad := range []struct{ from, to string }{
		{"../evil", "github/personal"},
		{"github/personal", "../evil"},
		{"github/personal", "/abs/path"},
	} {
		if err := st.Move(bad.from, bad.to); err == nil {
			t.Fatalf("expected move %q -> %q to be rejected", bad.from, bad.to)
		}
	}
	evil := filepath.Join(filepath.Dir(dir), "evil.gpg")
	if _, err := os.Stat(evil); !os.IsNotExist(err) {
		t.Fatal("a move escaped the store root")
	}
}

func TestMoveCaseOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.WriteEncrypted("github/personal", []byte("CIPHER")); err != nil {
		t.Fatalf("WriteEncrypted: %v", err)
	}
	// On a case-insensitive filesystem the two names are one file, so this
	// rename has to go through a scratch name rather than be refused as a
	// move onto an existing password.
	if err := st.Move("github/personal", "GitHub/Personal"); err != nil {
		t.Fatalf("Move (case only): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "GitHub", "Personal.gpg")); err != nil {
		t.Fatalf("expected the renamed casing on disk: %v", err)
	}
	// The scratch name must not be left behind: ListPasswords only reports
	// *.gpg files, so a leftover would sit in the store until the next move.
	entries, err := os.ReadDir(filepath.Join(dir, "github"))
	if err == nil {
		for _, e := range entries {
			if strings.Contains(e.Name(), "renaming") {
				t.Fatalf("Move left its scratch file behind: %s", e.Name())
			}
		}
	}
}

func TestMoveMkdirAllError(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.WriteEncrypted("a", []byte("CIPHER")); err != nil {
		t.Fatalf("WriteEncrypted: %v", err)
	}
	// "a" is a file, so it cannot also be the folder a move into "a/b" needs.
	if err := os.WriteFile(filepath.Join(dir, "blocker"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.Move("a", "blocker/b"); err == nil {
		t.Fatal("expected MkdirAll error when the new parent is a file")
	}
	if _, err := st.Read("a"); err != nil {
		t.Fatalf("a failed move lost the source entry: %v", err)
	}
}

func TestMoveCaseOnlyFailureLeavesTheEntry(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.WriteEncrypted("github/personal", []byte("CIPHER")); err != nil {
		t.Fatalf("WriteEncrypted: %v", err)
	}
	// The scratch name a case-only rename parks the file under is already
	// taken by a non-empty directory, so the first step cannot move onto it.
	scratch := filepath.Join(dir, "github", "personal.gpg.renaming")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratch, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.Move("github/personal", "GitHub/Personal"); err == nil {
		t.Fatal("expected a case-only rename onto an occupied scratch name to fail")
	}
	// A failed rename must not leave the entry with no file at all.
	data, err := st.Read("github/personal")
	if err != nil {
		t.Fatalf("a failed case-only rename lost the entry: %v", err)
	}
	if string(data) != "CIPHER" {
		t.Fatalf("a failed case-only rename altered the entry: %q", data)
	}
}

func TestStoreRoot(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if st.Root() == "" {
		t.Fatal("Root returned empty")
	}
	if !strings.HasSuffix(st.Root(), string(filepath.Separator)+filepath.Base(dir)) {
		t.Fatalf("Root = %q", st.Root())
	}
}

func TestCreateWithoutRecipients(t *testing.T) {
	if _, err := Create(t.TempDir(), nil); err == nil {
		t.Fatal("expected Create without recipients to fail")
	}
}

func TestWriteEncryptedCreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.WriteEncrypted("deep/nested/entry", []byte("CIPHER")); err != nil {
		t.Fatalf("WriteEncrypted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "deep", "nested", "entry.gpg")); err != nil {
		t.Fatalf("expected nested file: %v", err)
	}
}

func TestExistsAndDelete(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	exists, err := st.Exists("missing")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("expected Exists false")
	}
	if err := st.WriteEncrypted("present", []byte("CIPHER")); err != nil {
		t.Fatalf("WriteEncrypted: %v", err)
	}
	exists, err = st.Exists("present")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected Exists true")
	}
	if err := st.Delete("present"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := st.Delete("present"); err == nil {
		t.Fatal("expected Delete of missing file to report error")
	}
}

func TestOpenRejectsBadGPGID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gpg-id"), []byte("# only comments\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err != ErrNoGPGID {
		t.Fatalf("expected ErrNoGPGID, got %v", err)
	}
}

func TestReadRejectsInvalidPath(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := st.Read(""); err == nil {
		t.Fatal("expected empty path to be rejected")
	}
}

func TestOpenGPGIDReadError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".gpg-id"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err != ErrNoGPGID {
		t.Fatalf("expected ErrNoGPGID, got %v", err)
	}
}

func TestCreateMkdirAllError(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(filepath.Join(parent, "store"), []string{"AA"}); err == nil {
		t.Fatal("expected MkdirAll error when parent is a file")
	}
}

func TestCreateWriteGPGIDError(t *testing.T) {
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := os.Mkdir(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Pre-create .gpg-id as a directory so writeGPGID cannot write a file.
	if err := os.Mkdir(filepath.Join(storeDir, ".gpg-id"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(storeDir, []string{"AA"}); err == nil {
		t.Fatal("expected writeGPGID error when .gpg-id is a directory")
	}
}

func TestWriteEncryptedMkdirAllError(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.WriteEncrypted("a/b", []byte("x")); err == nil {
		t.Fatal("expected MkdirAll error when parent is a file")
	}
}

func TestWriteEncryptedMoveFileError(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	target := filepath.Join(dir, "x.gpg")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.WriteEncrypted("x", []byte("y")); err == nil {
		t.Fatal("expected MoveFile error when target is a non-empty directory")
	}
}

func TestRemoveDirectoryError(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	target := filepath.Join(dir, "x.gpg")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.Remove("x"); err == nil {
		t.Fatal("expected remove error when target is a non-empty directory")
	}
}

func TestDeleteDirectoryError(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	target := filepath.Join(dir, "x.gpg")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete("x"); err == nil {
		t.Fatal("expected delete error when target is a non-empty directory")
	}
}

func TestExistsRejectsInvalidPath(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := st.Exists(""); err == nil {
		t.Fatal("expected empty path to be rejected")
	}
	if _, err := st.Exists("../outside"); err == nil {
		t.Fatal("expected traversal path to be rejected")
	}
}

func TestDeleteRejectsInvalidPath(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Delete(""); err == nil {
		t.Fatal("expected empty path to be rejected")
	}
	if err := st.Delete("../outside"); err == nil {
		t.Fatal("expected traversal path to be rejected")
	}
}

func TestRemoveRejectsInvalidPath(t *testing.T) {
	dir := t.TempDir()
	st, err := Create(dir, []string{"AA"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Remove(""); err == nil {
		t.Fatal("expected empty path to be rejected")
	}
	if err := st.Remove("../outside"); err == nil {
		t.Fatal("expected traversal path to be rejected")
	}
}
