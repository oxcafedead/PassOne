package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// launchEditor writes current plaintext to a temporary file, opens the user's
// editor, and returns the resulting plaintext. The temporary file is always
// removed. On Windows the default editor is notepad.exe, which ships with the
// OS; the final Wails UI uses an embedded editor instead of an external one.
func launchEditor(initial []byte) ([]byte, error) {
	tmp, err := os.CreateTemp("", "gopass-edit-*.txt")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(initial); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	editor := editorCommand()
	cmd := exec.Command(editor, tmpName)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("editor %q failed: %v", editor, err)
	}

	out, err := os.ReadFile(tmpName)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func editorCommand() string {
	for _, v := range []string{"VISUAL", "EDITOR"} {
		if e := os.Getenv(v); e != "" {
			return e
		}
	}
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
}
