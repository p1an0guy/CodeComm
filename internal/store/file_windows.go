//go:build windows

package store

import "io/fs"

// Windows access is constrained by the owner-only per-user state directory.
// POSIX mode bits and directory fsync do not model NTFS DACLs or durability.
func insecurePermissions(fs.FileMode) bool {
	return false
}

func syncDirectory(string) error {
	return nil
}
