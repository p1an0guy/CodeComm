//go:build !windows

package joinbootstrap

import (
	"errors"
	"os"
	"syscall"
)

func lockJoinFile(file *os.File) error {
	if file == nil {
		return ErrStateConflict
	}
	err := syscall.Flock(
		int(file.Fd()),
		syscall.LOCK_EX|syscall.LOCK_NB,
	)
	if errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.EAGAIN) {
		return ErrStateConflict
	}
	if err != nil {
		return errors.Join(ErrStateConflict, err)
	}
	return nil
}

func unlockJoinFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
