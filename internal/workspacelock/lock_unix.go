//go:build !windows

package workspacelock

import (
	"errors"
	"os"
	"syscall"
	"time"
)

var errLockWouldBlock = errors.New("workspace lock: operation would block")

func validatePlatformPath(string) error {
	return nil
}

func validatePlatformFile(_ string, _ *os.File, info os.FileInfo) error {
	if info == nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm()&0o077 != 0 {
		return ErrInsecureFile
	}
	return nil
}

func lockFile(file *os.File) error {
	if file == nil {
		return ErrInsecureFile
	}
	err := syscall.Flock(
		int(file.Fd()),
		syscall.LOCK_EX|syscall.LOCK_NB,
	)
	if errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.EAGAIN) {
		return errLockWouldBlock
	}
	return err
}

func unlockFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}

func sleepForOwnerRecord() {
	time.Sleep(10 * time.Millisecond)
}
