//go:build !windows

package store

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
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

func validateDatabaseLinkCount(_ *os.File, info os.FileInfo) error {
	if info == nil {
		return fmt.Errorf("database file metadata is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fmt.Errorf("database native identity is unavailable")
	}
	if stat.Nlink != 1 {
		return fmt.Errorf(
			"database has %d hard links; exactly one is required",
			stat.Nlink,
		)
	}
	return nil
}
