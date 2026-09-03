package main

import (
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
	if info["pgpKey"] != "not imported" {
		t.Fatalf("pgpKey = %q", info["pgpKey"])
	}
	if info["autoLock"] != "5 min" {
		t.Fatalf("autoLock = %q", info["autoLock"])
	}
}

func TestPresenceHelpers(t *testing.T) {
	if got := presence(""); got != "(none)" {
		t.Fatalf("presence(\"\") = %q", got)
	}
	if got := presence("x"); got != "x" {
		t.Fatalf("presence(\"x\") = %q", got)
	}
	if got := presenceBool(true); got != "imported" {
		t.Fatalf("presenceBool(true) = %q", got)
	}
	if got := presenceBool(false); got != "not imported" {
		t.Fatalf("presenceBool(false) = %q", got)
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
	_ = a.ClipboardClearSeconds()
	if _, err := a.CreatePassword("x", "p", "p", ""); err == nil {
		t.Fatal("expected CreatePassword without store to fail")
	}
	if _, err := a.UpdatePassword("x", "p", "", false); err == nil {
		t.Fatal("expected UpdatePassword without store to fail")
	}
	if err := a.RemovePassword("x"); err == nil {
		t.Fatal("expected RemovePassword without store to fail")
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
}
