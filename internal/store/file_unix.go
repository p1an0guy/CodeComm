//go:build !windows

package store

import (
	"io/fs"
	"os"
)

func insecurePermissions(mode fs.FileMode) bool {
	return mode.Perm()&0o077 != 0
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
