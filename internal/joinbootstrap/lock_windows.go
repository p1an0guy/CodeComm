//go:build windows

package joinbootstrap

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lockJoinFile(file *os.File) error {
	if file == nil {
		return ErrStateConflict
	}
	var overlapped windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|
			windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&overlapped,
	)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
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
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(
		windows.Handle(file.Fd()),
		0,
		1,
		0,
		&overlapped,
	)
}
