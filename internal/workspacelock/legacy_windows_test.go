//go:build windows

package workspacelock

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLegacyWindowsLockInteroperability(t *testing.T) {
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
	var overlap windows.Overlapped
	if err := windows.LockFileEx(
		windows.Handle(legacy.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|
			windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&overlap,
	); !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		_ = legacy.Close()
		t.Fatalf("legacy lock against current owner = %v", err)
	}
	if err := current.Close(); err != nil {
		_ = legacy.Close()
		t.Fatalf("Close(current): %v", err)
	}
	overlap = windows.Overlapped{}
	if err := windows.LockFileEx(
		windows.Handle(legacy.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|
			windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&overlap,
	); err != nil {
		_ = legacy.Close()
		t.Fatalf("legacy lock: %v", err)
	}
	if _, err := Acquire(statePath); !errors.Is(err, ErrHeld) {
		_ = windows.UnlockFileEx(
			windows.Handle(legacy.Fd()),
			0,
			1,
			0,
			&overlap,
		)
		_ = legacy.Close()
		t.Fatalf("Acquire(legacy held) error = %v", err)
	}
	if err := windows.UnlockFileEx(
		windows.Handle(legacy.Fd()),
		0,
		1,
		0,
		&overlap,
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
	overlap := &windows.Overlapped{}
	if err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|
			windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlap,
	); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() error {
		return errors.Join(
			windows.UnlockFileEx(
				windows.Handle(file.Fd()),
				0,
				1,
				0,
				overlap,
			),
			file.Close(),
		)
	}, nil
}
