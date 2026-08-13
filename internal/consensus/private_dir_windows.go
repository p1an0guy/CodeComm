//go:build windows

package consensus

import "os"

// The per-user state root supplies the owner-only DACL on Windows. POSIX mode
// bits and directory fsync do not model NTFS access or durability.
func validatePrivateDirectory(os.FileInfo) error {
	return nil
}

func syncConsensusDirectory(string) error {
	return nil
}
