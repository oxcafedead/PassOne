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
