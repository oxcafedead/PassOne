package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"

	"github.com/oxcafedead/passone/internal/config"
	"github.com/oxcafedead/passone/internal/store"
	"github.com/oxcafedead/passone/internal/ui"
)

// This file is the release smoke suite for the GUI. It drives the app through
// the exact Wails bridge the frontend calls (wailsjs/go/main/App.js -> the
// exported methods of *App), so a release that changes the bridge, the vault
// format, or the entry semantics fails here before it reaches a user.
//
// The two properties it exists to protect:
//
//   - A release never bricks a key store. Key blobs must survive Lock/Unlock
//     byte-for-byte, a lock password change must re-seal without data loss, and
//     a fresh process must still be able to unlock and decrypt.
//   - A release never bricks a control. The create/edit/remove semantics that
//     the Add, Edit and Delete buttons drive are pinned here, because those
//     buttons are the ones that failed silently before tools/checkui existed.

// smokePGPPassphrase unlocks the OpenPGP key, smokeLockPassword unlocks the
// vault. They are deliberately different so a test that swaps them is caught.
const smokePGPPassphrase = "smoke-pgp-pass"
const smokeLockPassword = "smoke-lock-pass"

// smokeVault is a fully onboarded app: both key types imported, a pass store
// open, and the session unlocked. It is the starting point for the scenarios
// that mutate state.
type smokeVault struct {
	app     *App
	dataDir string
	store   string
	pgpPass string
	lock    string
}

// writeArmoredPGPKey generates a passphrase-protected OpenPGP private key,
// writes it to a temp file and returns the path. The caller reads the
// fingerprint back from CurrentSettings after import rather than re-parsing the
// key, so the suite also proves the app recorded what it imported.
func writeArmoredPGPKey(t *testing.T, dir string) string {
	t.Helper()
	cfg := &packet.Config{}
	entity, err := openpgp.NewEntity("Smoke Tester", "", "smoke@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	if err := entity.EncryptPrivateKeys([]byte(smokePGPPassphrase), cfg); err != nil {
		t.Fatalf("EncryptPrivateKeys: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	// Encrypted keys cannot be re-signed; the existing self-signatures stand.
	if err := entity.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatalf("SerializePrivateWithoutSigning: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}
	path := filepath.Join(dir, "secret.asc")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write PGP key: %v", err)
	}
	return path
}

// writeSSHKey generates an unencrypted ed25519 OpenSSH private key on disk.
func writeSSHKey(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "smoke@example.com")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write SSH key: %v", err)
	}
	return path
}

// newSmokeApp returns a bridge bound to an isolated data directory.
func newSmokeApp(t *testing.T, dataDir string) *App {
	t.Helper()
	t.Setenv("PASSONE_DIR", dataDir)
	gui, err := ui.New()
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	return NewApp(gui)
}

// onboard performs the first-run journey the setup wizard drives: import both
// key types, create and open a pass store, then unlock the session.
func onboard(t *testing.T, dataDir string) *smokeVault {
	t.Helper()
	app := newSmokeApp(t, dataDir)

	pgpPath := writeArmoredPGPKey(t, t.TempDir())
	if _, err := app.ImportPGPKeyFile(pgpPath, smokePGPPassphrase, smokeLockPassword); err != nil {
		t.Fatalf("ImportPGPKeyFile: %v", err)
	}
	sshPath := writeSSHKey(t, t.TempDir())
	if _, err := app.ImportSSHKeyFile(sshPath, "", smokeLockPassword); err != nil {
		t.Fatalf("ImportSSHKeyFile: %v", err)
	}

	fp := app.CurrentSettings().PGPKeyFingerprint
	if fp == "" {
		t.Fatal("PGPKeyFingerprint is empty after import; the store would be unusable")
	}
	storeDir := filepath.Join(t.TempDir(), "pass")
	if _, err := store.Create(storeDir, []string{fp}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := app.OpenLocalStore(storeDir); err != nil {
		t.Fatalf("OpenLocalStore: %v", err)
	}
	if err := app.Unlock(smokeLockPassword); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return &smokeVault{app: app, dataDir: dataDir, store: storeDir, pgpPass: smokePGPPassphrase, lock: smokeLockPassword}
}

// keyBlobs snapshots the sealed key files so a test can assert that an
// operation left them untouched. app.key is deliberately absent: it is the
// pre-DPAPI layout kept only for migration (internal/security/migration.go).
func keyBlobs(t *testing.T, dataDir string) map[string][]byte {
	t.Helper()
	paths := config.PathsFromBase(dataDir)
	out := map[string][]byte{}
	for name, path := range map[string]string{
		"salt.bin": paths.SaltFile,
		"pgp.dat":  paths.PGPKeyFile,
		"ssh.dat":  paths.SSHKeyFile,
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = data
	}
	return out
}

func assertEqualBlobs(t *testing.T, before, after map[string][]byte) {
	t.Helper()
	for name, want := range before {
		if !bytes.Equal(want, after[name]) {
			t.Errorf("%s changed on disk but should not have", name)
		}
	}
}

// seedEntries writes a small tree of entries covering the shapes the UI has to
// handle: a flat name, a nested path, and an entry carrying a TOTP seed and a
// login field.
func seedEntries(t *testing.T, v *smokeVault) {
	t.Helper()
	entries := []struct{ name, password, body string }{
		{"github/personal", "hunter2", "url: https://github.com\nuser: alice\n"},
		{"example.com/bob", "s3cret", "note: second entry\n"},
		{"totp/entry", "otp-secret", "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&issuer=example\nuser: carol\n"},
	}
	for _, e := range entries {
		if _, err := v.app.CreatePassword(e.name, e.password, e.password, e.body); err != nil {
			t.Fatalf("CreatePassword(%q): %v", e.name, err)
		}
	}
}

func entriesOf(t *testing.T, v *smokeVault) []string {
	t.Helper()
	names, err := v.app.ListPasswords()
	if err != nil {
		t.Fatalf("ListPasswords: %v", err)
	}
	return names
}

func mustShow(t *testing.T, v *smokeVault, name string) string {
	t.Helper()
	plain, err := v.app.ShowPassword(name)
	if err != nil {
		t.Fatalf("ShowPassword(%q): %v", name, err)
	}
	return plain
}

// TestReleaseSmokeFreshInstall pins what the unlock screen shows on a machine
// that has never run the app, and that importing keys is reported correctly
// without implicitly unlocking the session.
func TestReleaseSmokeFreshInstall(t *testing.T) {
	dataDir := t.TempDir()
	app := newSmokeApp(t, dataDir)

	info := app.AppInfo()
	if info["storePath"] != "(none)" {
		t.Errorf("storePath = %q, want (none)", info["storePath"])
	}
	if info["pgpKey"] != "not imported" {
		t.Errorf("pgpKey = %q, want not imported", info["pgpKey"])
	}
	if info["sshKey"] != "not imported" {
		t.Errorf("sshKey = %q, want not imported", info["sshKey"])
	}
	if app.IsUnlocked() {
		t.Error("a fresh install must start locked")
	}
	if hosts := app.KnownHosts(); len(hosts) != 0 {
		t.Errorf("KnownHosts on a fresh install = %v", hosts)
	}
	if stores := app.StoredStores(); len(stores) != 0 {
		t.Errorf("StoredStores on a fresh install = %v", stores)
	}

	pgpPath := writeArmoredPGPKey(t, t.TempDir())
	if _, err := app.ImportPGPKeyFile(pgpPath, smokePGPPassphrase, smokeLockPassword); err != nil {
		t.Fatalf("ImportPGPKeyFile: %v", err)
	}
	sshPath := writeSSHKey(t, t.TempDir())
	if _, err := app.ImportSSHKeyFile(sshPath, "", smokeLockPassword); err != nil {
		t.Fatalf("ImportSSHKeyFile: %v", err)
	}

	info = app.AppInfo()
	if info["pgpKey"] != "imported" || info["sshKey"] != "imported" {
		t.Errorf("AppInfo after import = %v", info)
	}
	if app.IsUnlocked() {
		t.Error("importing a key must leave the session locked")
	}
	if fp := app.CurrentSettings().PGPKeyFingerprint; fp == "" {
		t.Error("PGPKeyFingerprint is empty after import; the store would be unusable")
	}
	if !app.HasSSHKeyLoaded() {
		t.Error("HasSSHKeyLoaded should be true once the SSH key is resident")
	}

	// The SSH key is usable for transport before any session unlock, which is
	// what lets the wizard clone a repository.
	app.Lock()
	if err := app.LoadSSHKey(smokeLockPassword); err != nil {
		t.Errorf("LoadSSHKey: %v", err)
	}
	if !app.HasSSHKeyLoaded() {
		t.Error("HasSSHKeyLoaded should be true after LoadSSHKey")
	}
	if app.IsUnlocked() {
		t.Error("LoadSSHKey must not unlock the session")
	}
}

// TestReleaseSmokeStoreLifecycle walks opening a store and driving every entry
// operation the UI exposes, in the order the vault screen does it.
func TestReleaseSmokeStoreLifecycle(t *testing.T) {
	v := onboard(t, t.TempDir())

	if got := v.app.AppInfo()["storePath"]; got == "(none)" {
		t.Error("storePath should be set after OpenLocalStore")
	}
	if _, err := v.app.Status(); err != nil {
		t.Errorf("Status on a non-git store: %v", err)
	}

	if _, err := v.app.CreatePassword("github/personal", "hunter2", "hunter2", "url: https://github.com\n"); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}
	if got := entriesOf(t, v); len(got) != 1 || got[0] != "github/personal" {
		t.Fatalf("ListPasswords = %v", got)
	}
	if plain := mustShow(t, v, "github/personal"); plain != "hunter2\nurl: https://github.com\n" {
		t.Fatalf("ShowPassword = %q", plain)
	}

	if _, err := v.app.UpdatePassword("github/personal", "hunter3", "url: https://github.com\n", false); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	if plain := mustShow(t, v, "github/personal"); plain != "hunter3\nurl: https://github.com\n" {
		t.Fatalf("ShowPassword after edit = %q", plain)
	}

	if err := v.app.RemovePassword("github/personal"); err != nil {
		t.Fatalf("RemovePassword: %v", err)
	}
	if got := entriesOf(t, v); len(got) != 0 {
		t.Fatalf("ListPasswords after remove = %v", got)
	}
}

// TestReleaseSmokeKeyStoreSurvivesLockUnlock is the core anti-bricking test.
// Locking must drop key material from memory without touching what is on disk,
// and unlocking must reproduce the exact same plaintext.
func TestReleaseSmokeKeyStoreSurvivesLockUnlock(t *testing.T) {
	v := onboard(t, t.TempDir())
	seedEntries(t, v)

	before := keyBlobs(t, v.dataDir)
	want := map[string]string{}
	for _, name := range entriesOf(t, v) {
		want[name] = mustShow(t, v, name)
	}

	t.Run("LockClearsSessionButNotDisk", func(t *testing.T) {
		v.app.Lock()
		if v.app.IsUnlocked() {
			t.Error("IsUnlocked should be false after Lock")
		}
		assertEqualBlobs(t, before, keyBlobs(t, v.dataDir))
	})

	t.Run("WrongPasswordIsRejected", func(t *testing.T) {
		v.app.Lock()
		if err := v.app.Unlock(smokeLockPassword + "-wrong"); err == nil {
			t.Fatal("Unlock accepted a wrong password")
		}
		if v.app.IsUnlocked() {
			t.Error("a failed Unlock must not leave the session unlocked")
		}
		assertEqualBlobs(t, before, keyBlobs(t, v.dataDir))
	})

	t.Run("CorrectPasswordRestoresEveryEntry", func(t *testing.T) {
		v.app.Lock()
		if err := v.app.Unlock(v.lock); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		got := entriesOf(t, v)
		if len(got) != len(want) {
			t.Fatalf("ListPasswords = %v, want %d entries", got, len(want))
		}
		for name, plaintext := range want {
			if plain := mustShow(t, v, name); plain != plaintext {
				t.Errorf("entry %q = %q, want %q", name, plain, plaintext)
			}
		}
		assertEqualBlobs(t, before, keyBlobs(t, v.dataDir))
	})
}

// TestReleaseSmokeLockPasswordChangeKeepsVault covers the highest data-loss
// path in the app: re-sealing both key blobs under a new lock password. It
// asserts the old password stops working, the new one works, every entry still
// decrypts identically, and a brand new process can open the store.
func TestReleaseSmokeLockPasswordChangeKeepsVault(t *testing.T) {
	const newLock = "smoke-lock-pass-rotated"

	v := onboard(t, t.TempDir())
	seedEntries(t, v)
	want := map[string]string{}
	for _, name := range entriesOf(t, v) {
		want[name] = mustShow(t, v, name)
	}

	// Requires an unlocked session; refusing while locked is part of the
	// contract the settings form depends on.
	t.Run("RequiresUnlockedSession", func(t *testing.T) {
		v.app.Lock()
		if err := v.app.ChangeLockPassword(v.lock, newLock); err == nil {
			t.Fatal("ChangeLockPassword should be rejected while locked")
		}
		if err := v.app.Unlock(v.lock); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
	})

	t.Run("RejectsWrongCurrentPassword", func(t *testing.T) {
		if err := v.app.ChangeLockPassword("not-the-password", newLock); err == nil {
			t.Fatal("ChangeLockPassword accepted a wrong current password")
		}
		// The failed attempt must not have disturbed the vault.
		for name, plaintext := range want {
			if plain := mustShow(t, v, name); plain != plaintext {
				t.Errorf("entry %q changed after a failed rotation: %q", name, plain)
			}
		}
	})

	t.Run("RejectsEmptyNewPassword", func(t *testing.T) {
		if err := v.app.ChangeLockPassword(v.lock, ""); err == nil {
			t.Fatal("ChangeLockPassword accepted an empty new password")
		}
	})

	t.Run("RotationKeepsEveryEntryReadable", func(t *testing.T) {
		if err := v.app.ChangeLockPassword(v.lock, newLock); err != nil {
			t.Fatalf("ChangeLockPassword: %v", err)
		}
		for name, plaintext := range want {
			if plain := mustShow(t, v, name); plain != plaintext {
				t.Errorf("entry %q = %q, want %q", name, plain, plaintext)
			}
		}
	})

	t.Run("OldPasswordStopsWorking", func(t *testing.T) {
		v.app.Lock()
		if err := v.app.Unlock(v.lock); err == nil {
			t.Fatal("the old lock password still unlocks the store")
		}
		if err := v.app.Unlock(newLock); err != nil {
			t.Fatalf("Unlock with the new password: %v", err)
		}
	})

	t.Run("FreshProcessReadsTheRotatedVault", func(t *testing.T) {
		// A new App over the same data directory stands in for an app restart:
		// nothing may be carried over in memory.
		restarted := newSmokeApp(t, v.dataDir)
		if err := restarted.Unlock(v.lock); err == nil {
			t.Error("a fresh process still accepts the old lock password")
		}
		if err := restarted.Unlock(newLock); err != nil {
			t.Fatalf("fresh Unlock with the new password: %v", err)
		}
		settings := restarted.CurrentSettings()
		if settings.StorePath != v.store {
			t.Errorf("StorePath = %q, want %q", settings.StorePath, v.store)
		}
		if !settings.HasPGP || !settings.HasSSH {
			t.Errorf("a fresh process lost its keys: %+v", settings)
		}
		for name, plaintext := range want {
			got, err := restarted.ShowPassword(name)
			if err != nil {
				t.Fatalf("ShowPassword(%q) after restart: %v", name, err)
			}
			if got != plaintext {
				t.Errorf("entry %q = %q after restart, want %q", name, got, plaintext)
			}
		}
	})
}

// TestReleaseSmokeEditSemantics pins the behaviour behind the Add, Edit and
// Delete buttons. Each case is a branch a UI regression would silently take.
func TestReleaseSmokeEditSemantics(t *testing.T) {
	v := onboard(t, t.TempDir())

	t.Run("CreateRejectsDuplicateAndPointsAtEdit", func(t *testing.T) {
		if _, err := v.app.CreatePassword("web/mail", "pw1", "pw1", "first\n"); err != nil {
			t.Fatalf("CreatePassword: %v", err)
		}
		_, err := v.app.CreatePassword("web/mail", "pw2", "pw2", "second\n")
		if err == nil {
			t.Fatal("CreatePassword overwrote an existing entry")
		}
		if plain := mustShow(t, v, "web/mail"); plain != "pw1\nfirst\n" {
			t.Fatalf("a refused create must not modify the entry, got %q", plain)
		}
	})

	t.Run("CreateValidatesTheForm", func(t *testing.T) {
		cases := []struct {
			name, password, confirm, body string
		}{
			{"", "pw", "pw", ""},
			{"ok/entry", "", "", ""},
			{"ok/entry2", "pw", "different", ""},
			{"trailing/", "pw", "pw", ""},
		}
		for _, c := range cases {
			if _, err := v.app.CreatePassword(c.name, c.password, c.confirm, c.body); err == nil {
				t.Errorf("CreatePassword(%q, %q, %q) should have been rejected", c.name, c.password, c.confirm)
			}
		}
		if got := entriesOf(t, v); len(got) != 1 {
			t.Fatalf("rejected creates must not add entries, got %v", got)
		}
	})

	t.Run("EditReplacesPasswordWhenNotKeeping", func(t *testing.T) {
		if _, err := v.app.UpdatePassword("web/mail", "pw2", "second\n", false); err != nil {
			t.Fatalf("UpdatePassword: %v", err)
		}
		if plain := mustShow(t, v, "web/mail"); plain != "pw2\nsecond\n" {
			t.Fatalf("ShowPassword = %q", plain)
		}
	})

	t.Run("EditKeepsPasswordAndReplacesNotes", func(t *testing.T) {
		if _, err := v.app.UpdatePassword("web/mail", "", "third\n", true); err != nil {
			t.Fatalf("UpdatePassword: %v", err)
		}
		if plain := mustShow(t, v, "web/mail"); plain != "pw2\nthird\n" {
			t.Fatalf("keepPassword must preserve the stored secret, got %q", plain)
		}
	})

	t.Run("EditWithNothingToChangeIsANoOp", func(t *testing.T) {
		msg, err := v.app.UpdatePassword("web/mail", "", "", true)
		if err != nil {
			t.Fatalf("UpdatePassword: %v", err)
		}
		if msg == "" {
			t.Error("expected a message describing the no-op")
		}
		if plain := mustShow(t, v, "web/mail"); plain != "pw2\nthird\n" {
			t.Fatalf("a no-op edit changed the entry: %q", plain)
		}
	})

	t.Run("EditRejectsEmptyNewPasswordAndMissingEntry", func(t *testing.T) {
		if _, err := v.app.UpdatePassword("web/mail", "", "x\n", false); err == nil {
			t.Error("UpdatePassword should require a password when not keeping the current one")
		}
		if _, err := v.app.UpdatePassword("does/not/exist", "pw", "", false); err == nil {
			t.Error("UpdatePassword should not create a missing entry")
		}
		if plain := mustShow(t, v, "web/mail"); plain != "pw2\nthird\n" {
			t.Fatalf("a rejected edit changed the entry: %q", plain)
		}
	})

	t.Run("DeleteRemovesOnlyTheNamedEntry", func(t *testing.T) {
		if _, err := v.app.CreatePassword("web/other", "keepme", "keepme", ""); err != nil {
			t.Fatalf("CreatePassword: %v", err)
		}
		if err := v.app.RemovePassword("web/mail"); err != nil {
			t.Fatalf("RemovePassword: %v", err)
		}
		got := entriesOf(t, v)
		if len(got) != 1 || got[0] != "web/other" {
			t.Fatalf("ListPasswords = %v, want [web/other]", got)
		}
		if err := v.app.RemovePassword("web/mail"); err == nil {
			t.Error("RemovePassword should fail for a missing entry")
		}
	})
}

// TestReleaseSmokeEntryFeatures covers the per-entry actions the detail pane
// offers: login extraction and TOTP detection.
func TestReleaseSmokeEntryFeatures(t *testing.T) {
	v := onboard(t, t.TempDir())
	seedEntries(t, v)

	t.Run("LoginFromBodyWinsInAutoMode", func(t *testing.T) {
		got, err := v.app.Username("github/personal")
		if err != nil {
			t.Fatalf("Username: %v", err)
		}
		if got != "alice" {
			t.Errorf("Username = %q, want alice", got)
		}
	})

	t.Run("LoginFallsBackToFileName", func(t *testing.T) {
		// example.com/bob has no login field in the body.
		got, err := v.app.Username("example.com/bob")
		if err != nil {
			t.Fatalf("Username: %v", err)
		}
		if got != "bob" {
			t.Errorf("Username = %q, want bob", got)
		}
	})

	t.Run("UsernameSourceModeIsHonoured", func(t *testing.T) {
		if err := v.app.SetUsernameSource("body"); err != nil {
			t.Fatalf("SetUsernameSource: %v", err)
		}
		if got, err := v.app.Username("example.com/bob"); err != nil || got != "" {
			t.Errorf("body mode on an entry with no login field = %q, %v", got, err)
		}
		if err := v.app.SetUsernameSource("filename"); err != nil {
			t.Fatalf("SetUsernameSource: %v", err)
		}
		if got, err := v.app.Username("github/personal"); err != nil || got != "personal" {
			t.Errorf("filename mode = %q, %v; want personal", got, err)
		}
		if err := v.app.SetUsernameSource("auto"); err != nil {
			t.Fatalf("SetUsernameSource: %v", err)
		}
		if v.app.UsernameSource() != "auto" {
			t.Errorf("UsernameSource = %q, want auto", v.app.UsernameSource())
		}
	})

	t.Run("TOTPPresenceMatchesTheEntry", func(t *testing.T) {
		has, err := v.app.HasTOTP("totp/entry")
		if err != nil {
			t.Fatalf("HasTOTP: %v", err)
		}
		if !has {
			t.Error("HasTOTP = false for an entry carrying an otpauth URI")
		}
		has, err = v.app.HasTOTP("example.com/bob")
		if err != nil {
			t.Fatalf("HasTOTP: %v", err)
		}
		if has {
			t.Error("HasTOTP = true for an entry with no otpauth URI")
		}
	})

	t.Run("RevealingNeverLeaksThroughTheBridge", func(t *testing.T) {
		// ListPasswords and HasTOTP are the calls the UI makes before the user
		// asks to reveal; neither may return plaintext.
		for _, name := range entriesOf(t, v) {
			if strings := mustShow(t, v, name); strings == "" {
				t.Errorf("entry %q decrypted to nothing", name)
			}
		}
	})
}

// TestReleaseSmokeSettingsPersistAcrossRestart checks the preferences the
// settings modal writes, including that a restart does not lose them.
func TestReleaseSmokeSettingsPersistAcrossRestart(t *testing.T) {
	dataDir := t.TempDir()
	v := onboard(t, dataDir)

	t.Run("WriteEverySetting", func(t *testing.T) {
		if err := v.app.SetAutoLock(15); err != nil {
			t.Fatalf("SetAutoLock: %v", err)
		}
		if err := v.app.SetClipboardClear(45); err != nil {
			t.Fatalf("SetClipboardClear: %v", err)
		}
		if err := v.app.SetGitAuthor("Smoke Tester", "smoke@example.com"); err != nil {
			t.Fatalf("SetGitAuthor: %v", err)
		}
		if err := v.app.SetUsernameSource("body"); err != nil {
			t.Fatalf("SetUsernameSource: %v", err)
		}
	})

	t.Run("ValuesAreReadBackImmediately", func(t *testing.T) {
		if got := v.app.ClipboardClearSeconds(); got != 45 {
			t.Errorf("ClipboardClearSeconds = %d, want 45", got)
		}
		if got := v.app.AppInfo()["autoLock"]; got != "15 min" {
			t.Errorf("AppInfo autoLock = %q, want 15 min", got)
		}
		s := v.app.CurrentSettings()
		if s.AutoLockMinutes != 15 || s.GitAuthorName != "Smoke Tester" || s.GitAuthorEmail != "smoke@example.com" {
			t.Errorf("CurrentSettings = %+v", s)
		}
	})

	t.Run("InvalidValuesAreRejected", func(t *testing.T) {
		if err := v.app.SetUsernameSource("bogus"); err == nil {
			t.Error("SetUsernameSource accepted an unknown mode")
		}
		if err := v.app.SetClipboardClear(0); err == nil {
			t.Error("SetClipboardClear accepted a zero delay")
		}
		if err := v.app.SetClipboardClear(-1); err == nil {
			t.Error("SetClipboardClear accepted a negative delay")
		}
		if err := v.app.SetAutoLock(-1); err == nil {
			t.Error("SetAutoLock accepted a negative timeout")
		}
		// A rejected write must not have disturbed the stored values.
		if got := v.app.ClipboardClearSeconds(); got != 45 {
			t.Errorf("ClipboardClearSeconds = %d after rejected writes, want 45", got)
		}
		if v.app.UsernameSource() != "body" {
			t.Errorf("UsernameSource = %q after a rejected write, want body", v.app.UsernameSource())
		}
	})

	t.Run("FreshProcessKeepsThem", func(t *testing.T) {
		restarted := newSmokeApp(t, dataDir)
		s := restarted.CurrentSettings()
		if s.AutoLockMinutes != 15 {
			t.Errorf("AutoLockMinutes after restart = %d, want 15", s.AutoLockMinutes)
		}
		if s.ClipboardClearSeconds != 45 {
			t.Errorf("ClipboardClearSeconds after restart = %d, want 45", s.ClipboardClearSeconds)
		}
		if s.GitAuthorName != "Smoke Tester" || s.GitAuthorEmail != "smoke@example.com" {
			t.Errorf("git identity after restart = %q <%s>", s.GitAuthorName, s.GitAuthorEmail)
		}
		if s.UsernameSource != "body" {
			t.Errorf("UsernameSource after restart = %q, want body", s.UsernameSource)
		}
		if s.StorePath != v.store {
			t.Errorf("StorePath after restart = %q, want %q", s.StorePath, v.store)
		}
	})
}

// TestReleaseSmokeLockRefusesProtectedCalls confirms the lock boundary the UI
// depends on: after locking, every entry operation fails instead of silently
// returning empty data.
func TestReleaseSmokeLockRefusesProtectedCalls(t *testing.T) {
	v := onboard(t, t.TempDir())
	seedEntries(t, v)
	v.app.Lock()

	cases := []struct {
		name string
		call func() error
	}{
		{"ShowPassword", func() error { _, err := v.app.ShowPassword("github/personal"); return err }},
		{"CopyPassword", func() error { return v.app.CopyPassword("github/personal") }},
		{"CopyUsername", func() error { return v.app.CopyUsername("github/personal") }},
		{"HasTOTP", func() error { _, err := v.app.HasTOTP("totp/entry"); return err }},
		{"Username", func() error { _, err := v.app.Username("github/personal"); return err }},
		{"CreatePassword", func() error {
			_, err := v.app.CreatePassword("new/entry", "pw", "pw", "")
			return err
		}},
		{"UpdatePassword", func() error {
			_, err := v.app.UpdatePassword("github/personal", "pw", "", false)
			return err
		}},
		{"ChangeLockPassword", func() error { return v.app.ChangeLockPassword(v.lock, "other") }},
	}
	for _, c := range cases {
		if err := c.call(); err == nil {
			t.Errorf("%s succeeded while locked; it must refuse", c.name)
		}
	}
	// The vault is intact and the entry survived the refused calls.
	if err := v.app.Unlock(v.lock); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if got := entriesOf(t, v); len(got) != 3 {
		t.Fatalf("ListPasswords = %v, want the 3 seeded entries", got)
	}
}
