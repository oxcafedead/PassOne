package main

import (
	"path/filepath"
	"testing"

	"github.com/oxcafedead/passone/internal/ui"
)

func newTestAppGUI(t *testing.T) *App {
	t.Helper()
	t.Setenv("PASSONE_DIR", t.TempDir())
	gui, err := ui.New()
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	return NewApp(gui)
}

func TestAppInfoAndPresence(t *testing.T) {
	a := newTestAppGUI(t)
	info := a.AppInfo()
	if info["dataDir"] == "" {
		t.Fatal("expected dataDir")
	}
	if info["storePath"] != "(none)" {
		t.Fatalf("storePath = %q", info["storePath"])
	}
	// A key is named by the identifier the user confirms, and by nothing else.
	// With no key imported there is no identifier, and the row reads "not
	// imported" from the empty value rather than from a second field.
	if info["pgpKey"] != "" {
		t.Fatalf("pgpKey = %q, want empty before a key is imported", info["pgpKey"])
	}
	if info["sshKey"] != "" {
		t.Fatalf("sshKey = %q, want empty before a key is imported", info["sshKey"])
	}
	// The files the keys are sealed in are deliberately absent: the lock screen
	// shows a key, not a path into the data directory.
	for _, gone := range []string{"pgpKeyFile", "sshKeyFile"} {
		if _, ok := info[gone]; ok {
			t.Errorf("AppInfo still reports %q", gone)
		}
	}
	if info["autoLock"] != "5 min" {
		t.Fatalf("autoLock = %q", info["autoLock"])
	}
}

func TestAppRevealPathRefusesOutsideTheAppDirectories(t *testing.T) {
	a := newTestAppGUI(t)
	dataDir := a.AppInfo()["dataDir"]

	// No store is configured, so the data dir is the only directory the app
	// would hand to Explorer, and a path is only ever revealed if it is inside
	// one of them. Nothing here reaches the shell, which is why the refusals are
	// asserted here and the argv is asserted in internal/ui, where the launcher
	// is injected.
	for _, path := range []string{
		"",
		"   ",
		"C:\\Windows",
		filepath.Join(dataDir, "..", "..", "..", "Windows"),
		// A sibling that only shares a prefix with the data dir.
		dataDir + "-other",
	} {
		if err := a.RevealPath(path); err == nil {
			t.Errorf("RevealPath(%q) = nil, want a refusal", path)
		}
	}
}

func TestAppCopyKeyIDOnlyTakesAKeyTheAppStores(t *testing.T) {
	a := newTestAppGUI(t)

	// The text comes from the app's own config, so the only thing the renderer
	// gets to choose is which of the two keys it wants. An unknown name, and a
	// key that has not been imported, both have to be refused here rather than
	// putting something unexpected on the clipboard.
	for _, kind := range []string{"", "gpg", "PGP", "../../etc/passwd", "pgp ", "ssh; rm"} {
		if err := a.CopyKeyID(kind); err == nil {
			t.Errorf("CopyKeyID(%q) = nil, want a refusal", kind)
		}
	}
	for _, kind := range []string{"pgp", "ssh"} {
		if err := a.CopyKeyID(kind); err == nil {
			t.Errorf("CopyKeyID(%q) = nil, want a refusal before a key is imported", kind)
		}
	}
}

func TestPresenceHelpers(t *testing.T) {
	if got := presence(""); got != "(none)" {
		t.Fatalf("presence(\"\") = %q", got)
	}
	if got := presence("x"); got != "x" {
		t.Fatalf("presence(\"x\") = %q", got)
	}
}

func TestAutoLockText(t *testing.T) {
	cases := []struct {
		min  int
		want string
	}{
		{0, "off"},
		{-1, "off"},
		{5, "5 min"},
		{60, "1 h"},
		{90, "1h 30m"},
	}
	for _, tc := range cases {
		if got := autoLockText(tc.min); got != tc.want {
			t.Fatalf("autoLockText(%d) = %q, want %q", tc.min, got, tc.want)
		}
	}
}

func TestAppCurrentSettings(t *testing.T) {
	a := newTestAppGUI(t)
	s := a.CurrentSettings()
	if s.DataDir == "" {
		t.Fatal("expected DataDir")
	}
}

func TestAppPassThroughMethods(t *testing.T) {
	a := newTestAppGUI(t)

	// Lock/unlock lifecycle.
	if a.IsUnlocked() {
		t.Fatal("expected locked initially")
	}
	// With no keys imported, Unlock succeeds trivially.
	if err := a.Unlock("testpass"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	a.Lock()

	// Other simple getters/setters should not panic.
	if _, err := a.ListPasswords(); err == nil {
		t.Fatal("expected ListPasswords without store to fail")
	}
	if _, err := a.ShowPassword("x"); err == nil {
		t.Fatal("expected ShowPassword without store to fail")
	}
	if err := a.CopyPassword("x"); err == nil {
		t.Fatal("expected CopyPassword without store to fail")
	}
	if err := a.CopyUsername("x"); err == nil {
		t.Fatal("expected CopyUsername without store to fail")
	}
	if _, err := a.Username("x"); err == nil {
		t.Fatal("expected Username without store to fail")
	}
	if _, err := a.HasTOTP("x"); err == nil {
		t.Fatal("expected HasTOTP without store to fail")
	}
	if _, err := a.UpdatedAt("x"); err == nil {
		t.Fatal("expected UpdatedAt without store to fail")
	}
	_ = a.ClipboardClearSeconds()
	_ = a.ClipboardHistoryEnabled()
	if a.UsernameSource() != "auto" {
		t.Fatalf("UsernameSource = %q", a.UsernameSource())
	}
	if err := a.SetUsernameSource("body"); err != nil {
		t.Fatalf("SetUsernameSource: %v", err)
	}
	if a.UsernameSource() != "body" {
		t.Fatalf("UsernameSource = %q after set", a.UsernameSource())
	}
	if err := a.SetUsernameSource("bogus"); err == nil {
		t.Fatal("expected SetUsernameSource to reject an unknown mode")
	}
	if _, err := a.CreatePassword("x", "p", "p", ""); err == nil {
		t.Fatal("expected CreatePassword without store to fail")
	}
	if _, err := a.UpdatePassword("x", "p", "", false); err == nil {
		t.Fatal("expected UpdatePassword without store to fail")
	}
	if err := a.RemovePassword("x"); err == nil {
		t.Fatal("expected RemovePassword without store to fail")
	}
	if _, err := a.MovePassword("x", "y"); err == nil {
		t.Fatal("expected MovePassword without store to fail")
	}
	if _, err := a.PickPrivateKey(""); err == nil {
		t.Fatal("expected PickPrivateKey without context to fail")
	}
	if _, err := a.PickStoreDir(); err == nil {
		t.Fatal("expected PickStoreDir without context to fail")
	}
	if _, err := a.ImportPGPKeyFile("missing.asc", "", "testpass"); err == nil {
		t.Fatal("expected ImportPGPKeyFile missing file to fail")
	}
	if _, err := a.ImportSSHKeyFile("missing.key", "", "testpass"); err == nil {
		t.Fatal("expected ImportSSHKeyFile missing file to fail")
	}
	if a.HasSSHKeyLoaded() {
		t.Fatal("expected no SSH key loaded")
	}
	if err := a.LoadSSHKey(""); err == nil {
		t.Fatal("expected LoadSSHKey without imported key to fail")
	}
	if err := a.OpenLocalStore("missing"); err == nil {
		t.Fatal("expected OpenLocalStore missing dir to fail")
	}
	if stores := a.StoredStores(); len(stores) != 0 {
		t.Fatalf("StoredStores = %v", stores)
	}
	if _, err := a.PrepareClone("bad"); err == nil {
		t.Fatal("expected PrepareClone bad URL to fail")
	}
	if err := a.TrustHost("bad"); err == nil {
		t.Fatal("expected TrustHost bad hostport to fail")
	}
	if err := a.CloneStore("bad", ""); err == nil {
		t.Fatal("expected CloneStore bad URL to fail")
	}
	if err := a.SetAutoLock(10); err != nil {
		t.Fatalf("SetAutoLock: %v", err)
	}
	if err := a.SetClipboardClear(60); err != nil {
		t.Fatalf("SetClipboardClear: %v", err)
	}
	if err := a.SetGitAuthor("Name", "email@example.com"); err != nil {
		t.Fatalf("SetGitAuthor: %v", err)
	}
	if _, err := a.Status(); err == nil {
		t.Fatal("expected Status without store to fail")
	}
	if _, err := a.Sync(); err == nil {
		t.Fatal("expected Sync without store to fail")
	}
	if hosts := a.KnownHosts(); len(hosts) != 0 {
		t.Fatalf("KnownHosts = %v", hosts)
	}
	// The tests build without a stamped version, so the check answers from that
	// alone and makes no request: a test run must never reach api.github.com.
	update, err := a.CheckForUpdates()
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if update.Available {
		t.Errorf("CheckForUpdates = %+v, want no update from a development build", update)
	}
}
