//go:build !windows

package joinbootstrap

import (
	"fmt"
	"os"
)

func validateJournalPath(string) error {
	return nil
}

func validateJournalDirectory(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"%w: parent mode %04o permits group or other access",
			ErrInvalidJournal,
			info.Mode().Perm(),
		)
	}
	return nil
}

func validateJournalFile(_ string, info os.FileInfo) error {
	if info == nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: insecure file", ErrInvalidJournal)
	}
	return nil
}

func syncJournalDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
