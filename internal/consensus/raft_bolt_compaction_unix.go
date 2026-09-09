//go:build !windows

package consensus

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openRaftBoltFileNoFollow(
	path string,
	flag int,
	mode os.FileMode,
) (*os.File, error) {
	descriptor, err := unix.Open(
		path,
		flag|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		uint32(mode.Perm()),
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil
}

func validateRaftBoltFileHandle(file *os.File, info os.FileInfo) error {
	if file == nil || info == nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: file is not regular", ErrInsecureConsensusPath)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Nlink != 1 {
		return fmt.Errorf(
			"%w: file has %d hard links",
			ErrInsecureConsensusPath,
			stat.Nlink,
		)
	}
	return nil
}

func replaceRaftBoltFile(source, target string) error {
	return os.Rename(source, target)
}
