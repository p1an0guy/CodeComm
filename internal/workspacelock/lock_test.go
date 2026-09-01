package workspacelock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	lockHelperModeEnv  = "CODECOMM_WORKSPACE_LOCK_HELPER"
	lockHelperStateEnv = "CODECOMM_WORKSPACE_LOCK_STATE"
	lockHelperReadyEnv = "CODECOMM_WORKSPACE_LOCK_READY"
)

func TestPathPreservesJoinLockName(t *testing.T) {
	t.Parallel()

	if ownerRecordOffset < lockRegionSize {
		t.Fatalf(
			"owner record offset %d overlaps lock region %d",
			ownerRecordOffset,
			lockRegionSize,
		)
	}
	statePath := filepath.Join(t.TempDir(), "state.db")
	path, err := Path(statePath)
	if err != nil {
		t.Fatalf("Path(): %v", err)
	}
	if path != statePath+".join.lock" {
		t.Fatalf("Path() = %q", path)
	}
	for _, invalid := range []string{
		"",
		"state.db",
		statePath + string(filepath.Separator) + ".." +
			string(filepath.Separator) + filepath.Base(statePath),
	} {
		if _, err := Path(invalid); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("Path(%q) error = %v", invalid, err)
		}
	}
}

func TestAcquireExcludesHandlesAndReportsHolder(t *testing.T) {
	statePath := workspaceLockTestStatePath(t)
	first, err := Acquire(statePath)
	if err != nil {
		t.Fatalf("Acquire(first): %v", err)
	}
	if first.HolderPID() != os.Getpid() {
		t.Fatalf("HolderPID() = %d", first.HolderPID())
	}
	path, err := Path(statePath)
	if err != nil || first.Path() != path {
		t.Fatalf("lock path = %q, Path() = %q, err = %v", first.Path(), path, err)
	}

	_, err = Acquire(statePath)
	var held *HeldError
	if !errors.Is(err, ErrHeld) ||
		!errors.As(err, &held) ||
		held.PID != os.Getpid() ||
		held.Path != path {
		t.Fatalf("contended Acquire() error = %#v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first again): %v", err)
	}

	second, err := Acquire(statePath)
	if err != nil {
		t.Fatalf("Acquire(after close): %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close(second): %v", err)
	}
}

func TestAcquireOverwritesUnlockedStaleOwnerRecord(t *testing.T) {
	statePath := workspaceLockTestStatePath(t)
	path, err := Path(statePath)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerPID(file, os.Getpid()); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	lock, err := Acquire(statePath)
	if err != nil {
		t.Fatalf("Acquire(stale reused pid): %v", err)
	}
	if lock.HolderPID() != os.Getpid() {
		t.Fatalf("HolderPID() = %d", lock.HolderPID())
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
}

func TestAcquireOverwritesCorruptUnlockedOwnerRecord(t *testing.T) {
	t.Parallel()

	statePath := workspaceLockTestStatePath(t)
	path, err := Path(statePath)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("not-a-pid"), ownerRecordOffset); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err := Acquire(statePath)
	if err != nil {
		t.Fatalf("Acquire(corrupt stale owner): %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
}

func TestReadOwnerPIDAcceptsFullUint32Range(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("platform int cannot represent a full Windows PID")
	}
	statePath := workspaceLockTestStatePath(t)
	path, err := Path(statePath)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	const highPID = uint64(1<<32 - 1)
	record := []byte("pid=" + strconv.FormatUint(highPID, 10))
	if _, err := file.WriteAt(record, ownerRecordOffset); err != nil {
		t.Fatal(err)
	}
	got, err := readOwnerPID(file)
	if err != nil || uint64(got) != highPID {
		t.Fatalf("readOwnerPID() = (%d, %v)", got, err)
	}
}

func TestAcquireReclaimsLockAfterOwnerProcessDies(t *testing.T) {
	statePath := workspaceLockTestStatePath(t)
	readyPath := filepath.Join(t.TempDir(), "ready")
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestWorkspaceLockProcessHelper$",
		"-test.count=1",
	)
	command.Env = append(
		os.Environ(),
		lockHelperModeEnv+"=hold",
		lockHelperStateEnv+"="+statePath,
		lockHelperReadyEnv+"="+readyPath,
	)
	if err := command.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if command.Process != nil && !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	waitForWorkspaceLockHelper(t, command, readyPath)

	_, err := Acquire(statePath)
	var held *HeldError
	if !errors.Is(err, ErrHeld) ||
		!errors.As(err, &held) ||
		held.PID != command.Process.Pid {
		t.Fatalf(
			"Acquire(process contention) error = %#v, helper pid = %d",
			err,
			command.Process.Pid,
		)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed helper exited successfully")
	}
	waited = true

	reclaimed, err := Acquire(statePath)
	if err != nil {
		t.Fatalf("Acquire(after process death): %v", err)
	}
	if reclaimed.HolderPID() != os.Getpid() {
		t.Fatalf("reclaimed HolderPID() = %d", reclaimed.HolderPID())
	}
	if err := reclaimed.Close(); err != nil {
		t.Fatalf("Close(reclaimed): %v", err)
	}
}

func TestAcquireInteroperatesWithLegacyOwnerProcess(t *testing.T) {
	statePath := workspaceLockTestStatePath(t)
	readyPath := filepath.Join(t.TempDir(), "ready")
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestWorkspaceLockProcessHelper$",
		"-test.count=1",
	)
	command.Env = append(
		os.Environ(),
		lockHelperModeEnv+"=legacy",
		lockHelperStateEnv+"="+statePath,
		lockHelperReadyEnv+"="+readyPath,
	)
	if err := command.Start(); err != nil {
		t.Fatalf("start legacy helper: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if command.Process != nil && !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	waitForWorkspaceLockHelper(t, command, readyPath)

	_, err := Acquire(statePath)
	var held *HeldError
	if !errors.Is(err, ErrHeld) ||
		!errors.As(err, &held) ||
		held.PID != 0 {
		t.Fatalf("Acquire(legacy process held) error = %#v", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("kill legacy helper: %v", err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed legacy helper exited successfully")
	}
	waited = true

	reclaimed, err := Acquire(statePath)
	if err != nil {
		t.Fatalf("Acquire(after legacy process death): %v", err)
	}
	if err := reclaimed.Close(); err != nil {
		t.Fatalf("Close(reclaimed): %v", err)
	}
}

func TestWorkspaceLockProcessHelper(t *testing.T) {
	mode := os.Getenv(lockHelperModeEnv)
	if mode != "hold" && mode != "legacy" {
		t.Skip("workspace-lock subprocess helper")
	}
	statePath := os.Getenv(lockHelperStateEnv)
	readyPath := os.Getenv(lockHelperReadyEnv)
	var release func() error
	switch mode {
	case "hold":
		lock, err := Acquire(statePath)
		if err != nil {
			t.Fatalf("Acquire(helper): %v", err)
		}
		release = lock.Close
	case "legacy":
		var err error
		release, err = acquireLegacyWorkspaceLock(statePath)
		if err != nil {
			t.Fatalf("acquire legacy helper lock: %v", err)
		}
	}
	defer release()
	if err := os.WriteFile(
		readyPath,
		[]byte(strconv.Itoa(os.Getpid())),
		0o600,
	); err != nil {
		t.Fatalf("write helper ready file: %v", err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func workspaceLockTestStatePath(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "state.db")
}

func waitForWorkspaceLockHelper(
	t *testing.T,
	command *exec.Cmd,
	readyPath string,
) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		encoded, err := os.ReadFile(readyPath)
		if err == nil {
			pid, parseErr := strconv.Atoi(string(encoded))
			if parseErr != nil || pid != command.Process.Pid {
				t.Fatalf("helper ready pid = %q, error = %v", encoded, parseErr)
			}
			return
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read helper ready file: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = command.Process.Kill()
	err := command.Wait()
	t.Fatalf("workspace-lock helper did not become ready: %v", err)
}
