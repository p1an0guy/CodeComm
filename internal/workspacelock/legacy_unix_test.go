//go:build !windows

package workspacelock

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestLegacyUnixLockInteroperability(t *testing.T) {
	statePath := workspaceLockTestStatePath(t)
	current, err := Acquire(statePath)
	if err != nil {
		t.Fatalf("Acquire(current): %v", err)
	}
	path, err := Path(statePath)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(
		int(legacy.Fd()),
		syscall.LOCK_EX|syscall.LOCK_NB,
	); !errors.Is(err, syscall.EWOULDBLOCK) &&
		!errors.Is(err, syscall.EAGAIN) {
		_ = legacy.Close()
		t.Fatalf("legacy lock against current owner = %v", err)
	}
	if err := current.Close(); err != nil {
		_ = legacy.Close()
		t.Fatalf("Close(current): %v", err)
	}
	if err := syscall.Flock(
		int(legacy.Fd()),
		syscall.LOCK_EX|syscall.LOCK_NB,
	); err != nil {
		_ = legacy.Close()
		t.Fatalf("legacy lock: %v", err)
	}
	if _, err := Acquire(statePath); !errors.Is(err, ErrHeld) {
		_ = syscall.Flock(int(legacy.Fd()), syscall.LOCK_UN)
		_ = legacy.Close()
		t.Fatalf("Acquire(legacy held) error = %v", err)
	}
	if err := syscall.Flock(
		int(legacy.Fd()),
		syscall.LOCK_UN,
	); err != nil {
		_ = legacy.Close()
		t.Fatalf("legacy unlock: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy handle: %v", err)
	}
}

func acquireLegacyWorkspaceLock(
	statePath string,
) (func() error, error) {
	path, err := Path(statePath)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(
		int(file.Fd()),
		syscall.LOCK_EX|syscall.LOCK_NB,
	); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() error {
		return errors.Join(
			syscall.Flock(int(file.Fd()), syscall.LOCK_UN),
			file.Close(),
		)
	}, nil
}
