package joinbootstrap

import (
	"errors"

	"github.com/ijonahch/codecomm/internal/workspacelock"
)

type joinLock struct {
	workspace *workspacelock.Lock
}

func acquireJoinLock(statePath string) (*joinLock, error) {
	lock, err := workspacelock.Acquire(statePath)
	if err != nil {
		return nil, errors.Join(ErrStateConflict, err)
	}
	return &joinLock{workspace: lock}, nil
}

func (lock *joinLock) Close() error {
	if lock == nil || lock.workspace == nil {
		return nil
	}
	err := lock.workspace.Close()
	lock.workspace = nil
	return err
}
