package cliputil

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const (
	// systemPolicyKey is where a group policy turns Clipboard History and
	// cross-device clipboard sync off for the machine.
	systemPolicyKey = `SOFTWARE\Policies\Microsoft\Windows\System`
	// clipboardUserKey is where the per-user Clipboard History and cloud
	// clipboard toggles live.
	clipboardUserKey = `Software\Microsoft\Clipboard`
)

// toggle is one registry value that can switch Windows Clipboard History or the
// cloud clipboard off.
type toggle struct {
	root registry.Key
	path string
	name string
}

// historyToggles lists every setting that matters here. Both stores snapshot
// what is copied, so both the local history and the cross-device clipboard are
// relevant to a password manager, and a group policy outranks the per-user
// setting.
var historyToggles = []toggle{
	{registry.LOCAL_MACHINE, systemPolicyKey, "AllowClipboardHistory"},
	{registry.LOCAL_MACHINE, systemPolicyKey, "AllowCrossDeviceClipboard"},
	{registry.CURRENT_USER, clipboardUserKey, "EnableClipboardHistory"},
	{registry.CURRENT_USER, clipboardUserKey, "EnableCloudClipboard"},
}

// HistoryEnabled reports whether Windows is keeping a Clipboard History for
// this user, or may sync the clipboard to their other devices.
//
// It errs towards true. A missing value means the Windows default, which is
// on, and a value that cannot be read proves nothing, so neither counts as
// "off". Only an explicit zero does.
func HistoryEnabled() (bool, error) {
	enabled, err := historyOff(readDword)
	if err != nil {
		return true, err
	}
	return !enabled, nil
}

// historyOff reports whether any of the history toggles is explicitly disabled.
// lookup returns the value of one setting, or nil when it is absent.
func historyOff(lookup func(root registry.Key, path, name string) (*uint64, error)) (bool, error) {
	for _, t := range historyToggles {
		v, err := lookup(t.root, t.path, t.name)
		if err != nil {
			return false, fmt.Errorf("could not read %s: %w", t.name, err)
		}
		if v != nil && *v == 0 {
			return true, nil
		}
	}
	return false, nil
}

// readDword returns the value of a registry value, or nil when the key or the
// value is absent.
func readDword(root registry.Key, path, name string) (*uint64, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = k.Close() }()

	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}
