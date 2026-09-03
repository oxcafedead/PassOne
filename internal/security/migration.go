package security

import (
	"errors"
	"fmt"
	"os"

	"github.com/oxcafedead/passone/internal/config"
)

// LegacyAppKeyExists reports whether a legacy DPAPI-protected app.key is still
// present, meaning a previous version's vault layout has not yet been migrated.
func LegacyAppKeyExists(paths config.Paths) bool {
	_, err := os.Stat(paths.AppKeyFile)
	return err == nil
}

// ReadLegacyAppKey reads and unprotects the legacy application key written by
// the old DPAPI-based vault. Callers must Wipe the returned key.
func ReadLegacyAppKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer Zero(data)
	key, err := DPAPIUnprotect(data)
	if err != nil {
		return nil, fmt.Errorf("unable to unprotect legacy application key: %w", err)
	}
	if len(key) != keyLen {
		Zero(key)
		return nil, errors.New("legacy application key has unexpected length")
	}
	return key, nil
}

// RemoveLegacyAppKey deletes the legacy app.key once migration has completed.
func RemoveLegacyAppKey(path string) error {
	return os.Remove(path)
}
