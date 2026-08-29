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
