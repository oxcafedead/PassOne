package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// `passone edit` hands the entry's plaintext to the user's editor in a
// temporary file. Two properties follow, and both are about what happens to
// that plaintext rather than about the editing itself:
//
//   - the editor's output is what gets re-encrypted, so a failure to launch has
//     to be an error rather than an empty body silently replacing the entry;
//   - the temporary file holds decrypted secrets in %TEMP%, so it has to be
//     removed on every path out, including the failing ones.

// editorTempPrefix and editorTempSuffix are the pattern launchEditor creates its
// temporary file with. TestMain uses them to recognise an editor invocation, so
// the two must stay in step.
const (
	editorTempPrefix = "gopass-edit-"
	editorTempSuffix = ".txt"

	editorReplaceEnv = "PASSONE_TEST_EDITOR_REPLACE"
	editorAppendEnv  = "PASSONE_TEST_EDITOR_APPEND"
	editorExitEnv    = "PASSONE_TEST_EDITOR_EXIT"
)

// TestMain doubles as the fake editor. launchEditor runs the editor as a child
// process, so testing it needs one that terminates on its own instead of
// notepad.exe waiting for a human. Rather than build a helper binary, this test
// binary plays the part: it recognises its own temp-file argument and acts as an
// editor instead of running tests. Neither condition can hold during a real
// `go test` run, which always passes flags and never a gopass-edit-*.txt path.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 {
		name := filepath.Base(os.Args[1])
		if strings.HasPrefix(name, editorTempPrefix) && strings.HasSuffix(name, editorTempSuffix) {
			os.Exit(runFakeEditor(os.Args[1]))
		}
	}
	os.Exit(m.Run())
}

// runFakeEditor applies the edit the test asked for and reports the exit code
// the test asked for. The instructions travel in the environment because
// launchEditor runs the editor with the environment it inherited.
func runFakeEditor(path string) int {
	if code := os.Getenv(editorExitEnv); code != "" {
		n, err := strconv.Atoi(code)
		if err == nil && n != 0 {
			return n
		}
	}
	if replace, ok := os.LookupEnv(editorReplaceEnv); ok {
		if err := os.WriteFile(path, []byte(replace), 0o600); err != nil {
			return 4
		}
		return 0
	}
	appendText, ok := os.LookupEnv(editorAppendEnv)
	if !ok {
		return 0
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 4
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(appendText); err != nil {
		return 4
	}
	return 0
}

// editorBinary returns the path to use as $EDITOR: this test binary, which
// TestMain turns into a terminating editor.
func editorBinary(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

// tempDirEnv points os.CreateTemp at a directory the test owns, so the files
// launchEditor creates are observable afterwards. Without this the only way to
// see them is to watch the whole system temp directory.
func tempDirEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	return dir
}

// tempFileCount is how many files are left in dir.
func tempFileCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading temp dir: %v", err)
	}
	return len(entries)
}

// TestEditorCommandIgnoresEmptyVisual: an empty $VISUAL is not an override.
// A shell that exports VISUAL with nothing in it is common enough that falling
// through to $EDITOR is the difference between the user's editor and notepad.
// TestEditorCommand covers the unset and both-set cases.
func TestEditorCommandIgnoresEmptyVisual(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "code")
	if got := editorCommand(); got != "code" {
		t.Errorf("editorCommand() = %q, want %q", got, "code")
	}
}

// TestLaunchEditorReturnsEditedPlaintext: the editor's output is the entry's new
// plaintext, so a replacement has to come back verbatim.
func TestLaunchEditorReturnsEditedPlaintext(t *testing.T) {
	dir := tempDirEnv(t)
	t.Setenv("VISUAL", editorBinary(t))
	t.Setenv("EDITOR", "")
	t.Setenv(editorReplaceEnv, "the new secret")

	got, err := launchEditor([]byte("the old secret"))
	if err != nil {
		t.Fatalf("launchEditor: %v", err)
	}
	if string(got) != "the new secret" {
		t.Errorf("got %q, want %q", got, "the new secret")
	}
	if n := tempFileCount(t, dir); n != 0 {
		t.Errorf("%d file(s) left in the temp dir; the plaintext is still on disk", n)
	}
}

// TestLaunchEditorKeepsUnchangedContent covers the edit that changes nothing,
// which is the common case and must not come back as an empty entry.
func TestLaunchEditorKeepsUnchangedContent(t *testing.T) {
	tempDirEnv(t)
	t.Setenv("VISUAL", editorBinary(t))
	t.Setenv("EDITOR", "")

	got, err := launchEditor([]byte("unchanged secret\nwith a second line"))
	if err != nil {
		t.Fatalf("launchEditor: %v", err)
	}
	if string(got) != "unchanged secret\nwith a second line" {
		t.Errorf("got %q, want the initial plaintext back", got)
	}
}

func TestLaunchEditorReturnsAppendedEdits(t *testing.T) {
	tempDirEnv(t)
	t.Setenv("VISUAL", editorBinary(t))
	t.Setenv("EDITOR", "")
	t.Setenv(editorAppendEnv, "\nan appended line")

	got, err := launchEditor([]byte("first line"))
	if err != nil {
		t.Fatalf("launchEditor: %v", err)
	}
	if string(got) != "first line\nan appended line" {
		t.Errorf("got %q, want the appended text", got)
	}
}

// TestLaunchEditorFailsWhenEditorFails: an editor that exits non-zero must be an
// error. Reading the untouched file back instead would silently discard the
// edit, and reading an empty file would destroy the entry.
func TestLaunchEditorFailsWhenEditorFails(t *testing.T) {
	dir := tempDirEnv(t)
	t.Setenv("VISUAL", editorBinary(t))
	t.Setenv("EDITOR", "")
	t.Setenv(editorExitEnv, "3")

	got, err := launchEditor([]byte("the old secret"))
	if err == nil {
		t.Fatalf("launchEditor returned %q and no error for a failing editor", got)
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("got %q, want it to report the editor as having failed", err)
	}
	if n := tempFileCount(t, dir); n != 0 {
		t.Errorf("%d file(s) left in the temp dir after the editor failed", n)
	}
}

// TestLaunchEditorFailsWhenEditorIsMissing covers the other way an editor goes
// away: the command is not on disk at all.
func TestLaunchEditorFailsWhenEditorIsMissing(t *testing.T) {
	dir := tempDirEnv(t)
	missing := filepath.Join(dir, "no-such-editor.exe")
	t.Setenv("VISUAL", missing)
	t.Setenv("EDITOR", "")

	got, err := launchEditor([]byte("the old secret"))
	if err == nil {
		t.Fatalf("launchEditor returned %q and no error for a missing editor", got)
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("got %q, want it to report the editor as having failed", err)
	}
	if n := tempFileCount(t, dir); n != 0 {
		t.Errorf("%d file(s) left in the temp dir after the editor failed to start", n)
	}
}

// TestLaunchEditorFailsWhenTempFileCannotBeCreated: with no usable temp
// directory there is nowhere to put plaintext, and the command must say so
// rather than open an editor on a path that does not exist.
func TestLaunchEditorFailsWhenTempFileCannotBeCreated(t *testing.T) {
	t.Setenv("TMP", filepath.Join(t.TempDir(), "no-such-dir"))
	t.Setenv("TEMP", filepath.Join(t.TempDir(), "no-such-dir"))
	t.Setenv("VISUAL", editorBinary(t))
	t.Setenv("EDITOR", "")

	got, err := launchEditor([]byte("the old secret"))
	if err == nil {
		t.Fatalf("launchEditor returned %q and no error with no usable temp dir", got)
	}
	if got != nil {
		t.Errorf("got %d bytes alongside the error, want none", len(got))
	}
}

// TestLaunchEditorReturnsEmptiedBody: an editor that empties the file yields an
// empty body and no error. That is the editor's decision, faithfully reported —
// launchEditor must not invent an error here, and must not substitute the old
// plaintext for it either. What happens to an empty body belongs to the caller,
// which is what decides whether an emptied entry is a deletion or a no-op.
func TestLaunchEditorReturnsEmptiedBody(t *testing.T) {
	dir := tempDirEnv(t)
	t.Setenv("VISUAL", editorBinary(t))
	t.Setenv("EDITOR", "")
	t.Setenv(editorReplaceEnv, "")

	got, err := launchEditor([]byte("the old secret"))
	if err != nil {
		t.Fatalf("launchEditor: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %q, want an empty body for an emptied file", got)
	}
	if n := tempFileCount(t, dir); n != 0 {
		t.Errorf("%d file(s) left in the temp dir", n)
	}
}
