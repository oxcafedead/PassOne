package config

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// atomicReplace moves src onto dst, replacing any existing file.
// On Windows os.Rename fails when the destination exists, so this uses
// MoveFileEx with MOVEFILE_REPLACE_EXISTING for an atomic overwrite.
func atomicReplace(src, dst string) error {
	srcW, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	dstW, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(srcW, dstW, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	return nil
}

// RestrictACL sets a restrictive DACL on the given file granting access only
// to the current user (owner) and SYSTEM, and blocks inherited ACEs. Failures
// are returned to the caller so they can decide whether to abort.
func RestrictACL(path string) error {
	// DACL: SYSTEM every access; owner (the creating user) every access.
	sd, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

// MoveFile is a platform shim used when a move across the same volume is fine.
func MoveFile(src, dst string) error {
	return atomicReplace(src, dst)
}

// DirIsEmpty reports whether the directory contains any entries.
func DirIsEmpty(dir string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if len(names) > 0 {
		return false, nil
	}
	if err != nil && err != io.EOF {
		return false, err
	}
	return true, nil
}
