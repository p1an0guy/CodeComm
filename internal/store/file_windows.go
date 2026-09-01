//go:build windows

package store

import (
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// Windows access is constrained by the owner-only per-user state directory.
// POSIX mode bits and directory fsync do not model NTFS DACLs or durability.
func insecurePermissions(fs.FileMode) bool {
	return false
}

func syncDirectory(string) error {
	return nil
}

func validateDatabaseLinkCount(file *os.File, _ os.FileInfo) error {
	if file == nil {
		return fmt.Errorf("database file handle is unavailable")
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(file.Fd()),
		&information,
	); err != nil {
		return fmt.Errorf("inspect database native identity: %w", err)
	}
	if information.NumberOfLinks != 1 {
		return fmt.Errorf(
			"database has %d hard links; exactly one is required",
			information.NumberOfLinks,
		)
	}
	return nil
}
