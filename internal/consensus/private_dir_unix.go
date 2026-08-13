//go:build !windows

package consensus

import (
	"fmt"
	"os"
)

func validatePrivateDirectory(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"%w: directory mode %04o permits group or other access",
			ErrInsecureConsensusPath,
			info.Mode().Perm(),
		)
	}
	return nil
}

func syncConsensusDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
