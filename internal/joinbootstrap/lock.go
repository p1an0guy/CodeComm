package joinbootstrap

import (
	"errors"
	"fmt"
	"os"
)

const joinLockSuffix = ".join.lock"

type joinLock struct {
	file *os.File
}

func acquireJoinLock(statePath string) (*joinLock, error) {
	path, err := journalPath(statePath)
	if err != nil {
		return nil, err
	}
	path = path[:len(path)-len(journalSuffix)] + joinLockSuffix
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open join lock: %v", ErrStateConflict, err)
	}
	locked := false
	defer func() {
		if !locked {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil ||
		!info.Mode().IsRegular() {
		return nil, ErrStateConflict
	}
	pathInfo, err := os.Lstat(path)
	if err != nil ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(info, pathInfo) {
		return nil, ErrStateConflict
	}
	if err := validateJournalFile(path, info); err != nil {
		return nil, errors.Join(ErrStateConflict, err)
	}
	if err := lockJoinFile(file); err != nil {
		return nil, err
	}
	locked = true
	return &joinLock{file: file}, nil
}

func (lock *joinLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unlockJoinFile(lock.file)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}
