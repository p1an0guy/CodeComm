// Package workspacelock provides the process-wide ownership lock for one
// CodeComm workspace.
package workspacelock

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	// Suffix preserves the lock name used by the original join-only lock.
	Suffix = ".join.lock"

	// Keep metadata outside the mandatory Windows byte-range lock so a
	// contender can report the holder without acquiring ownership.
	lockRegionSize    = 1
	ownerRecordOffset = int64(lockRegionSize)
	ownerRecordSize   = 32
)

var (
	ErrInvalidPath     = errors.New("workspace lock: invalid state path")
	ErrInsecureFile    = errors.New("workspace lock: insecure lock file")
	ErrHeld            = errors.New("workspace lock: already held")
	ErrInvalidMetadata = errors.New("workspace lock: invalid owner metadata")
)

// HeldError reports the process recorded by the current lock owner. PID is
// zero only when contending with a legacy owner that did not record one.
type HeldError struct {
	Path string
	PID  int
}

func (err *HeldError) Error() string {
	if err == nil {
		return ErrHeld.Error()
	}
	if err.PID > 0 {
		return fmt.Sprintf("%s: %s (pid %d)", ErrHeld, err.Path, err.PID)
	}
	return fmt.Sprintf("%s: %s (holder pid unavailable)", ErrHeld, err.Path)
}

func (*HeldError) Unwrap() error {
	return ErrHeld
}

// Lock is an exclusive OS lock. Copies share ownership, and Close releases
// that ownership exactly once.
type Lock struct {
	state *lockState
}

type lockState struct {
	mu   sync.Mutex
	file *os.File
	path string
	pid  int

	closeOnce sync.Once
	closeErr  error
}

// Path returns the lock path for statePath.
func Path(statePath string) (string, error) {
	if statePath == "" ||
		!filepath.IsAbs(statePath) ||
		filepath.Clean(statePath) != statePath {
		return "", ErrInvalidPath
	}
	return statePath + Suffix, nil
}

// Acquire takes the exclusive lock associated with statePath without waiting.
// The OS lock is authoritative; stale diagnostic metadata is overwritten only
// after that lock has been acquired.
func Acquire(statePath string) (*Lock, error) {
	path, err := Path(statePath)
	if err != nil {
		return nil, err
	}
	return AcquireFile(path)
}

// AcquireFile takes an exclusive lock at an explicit owner-only lock-file
// path. It is used by storage owners that need a stable lock independent of a
// replaceable data-file inode.
func AcquireFile(path string) (*Lock, error) {
	if path == "" ||
		!filepath.IsAbs(path) ||
		filepath.Clean(path) != path {
		return nil, ErrInvalidPath
	}
	if err := validatePlatformPath(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("workspace lock: open %s: %w", path, err)
	}
	owned := false
	defer func() {
		if !owned {
			_ = file.Close()
		}
	}()
	if err := validateOpenedFile(path, file); err != nil {
		return nil, err
	}
	if err := lockFile(file); err != nil {
		if errors.Is(err, errLockWouldBlock) {
			return nil, &HeldError{
				Path: path,
				PID:  contendedHolderPID(file),
			}
		}
		return nil, fmt.Errorf("workspace lock: lock %s: %w", path, err)
	}
	locked := true
	defer func() {
		if locked {
			_ = unlockFile(file)
		}
	}()
	if err := validateOpenedFile(path, file); err != nil {
		return nil, err
	}

	pid := os.Getpid()
	if pid < 1 {
		return nil, fmt.Errorf("%w: invalid current process id", ErrInvalidMetadata)
	}
	if err := writeOwnerPID(file, pid); err != nil {
		return nil, err
	}

	locked = false
	owned = true
	return &Lock{
		state: &lockState{
			file: file,
			path: path,
			pid:  pid,
		},
	}, nil
}

// Path reports the concrete lock-file path.
func (lock *Lock) Path() string {
	if lock == nil || lock.state == nil {
		return ""
	}
	lock.state.mu.Lock()
	defer lock.state.mu.Unlock()
	return lock.state.path
}

// HolderPID reports this process's recorded ownership identity.
func (lock *Lock) HolderPID() int {
	if lock == nil || lock.state == nil {
		return 0
	}
	lock.state.mu.Lock()
	defer lock.state.mu.Unlock()
	return lock.state.pid
}

// Close clears the clean-owner record, releases the OS lock, and closes the
// file. The OS still releases ownership if the process exits without Close.
func (lock *Lock) Close() error {
	if lock == nil || lock.state == nil {
		return nil
	}
	state := lock.state
	state.closeOnce.Do(func() {
		state.mu.Lock()
		defer state.mu.Unlock()
		if state.file == nil {
			return
		}
		clearErr := clearOwnerPID(state.file)
		unlockErr := unlockFile(state.file)
		closeErr := state.file.Close()
		state.file = nil
		state.pid = 0
		state.closeErr = errors.Join(clearErr, unlockErr, closeErr)
	})
	return state.closeErr
}

func validateOpenedFile(path string, file *os.File) error {
	if file == nil {
		return ErrInsecureFile
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.Join(ErrInsecureFile, err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		!pathInfo.Mode().IsRegular() ||
		!os.SameFile(info, pathInfo) {
		return errors.Join(ErrInsecureFile, err)
	}
	if err := validatePlatformFile(path, file, info); err != nil {
		return errors.Join(ErrInsecureFile, err)
	}
	return nil
}

func contendedHolderPID(file *os.File) int {
	for attempt := 0; attempt < 5; attempt++ {
		pid, err := readOwnerPID(file)
		if err == nil && pid > 0 {
			return pid
		}
		if attempt < 4 {
			sleepForOwnerRecord()
		}
	}
	return 0
}

func readOwnerPID(file *os.File) (int, error) {
	if file == nil {
		return 0, ErrInvalidMetadata
	}
	record := make([]byte, ownerRecordSize)
	count, err := file.ReadAt(record, ownerRecordOffset)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("%w: read owner: %v", ErrInvalidMetadata, err)
	}
	record = record[:count]
	record = bytes.Trim(record, "\x00 \t\r\n")
	if len(record) == 0 {
		return 0, nil
	}
	value := strings.TrimPrefix(string(record), "pid=")
	if value == string(record) {
		return 0, ErrInvalidMetadata
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	maxInt := uint64(^uint(0) >> 1)
	if err != nil || parsed < 1 || parsed > maxInt {
		return 0, errors.Join(ErrInvalidMetadata, err)
	}
	return int(parsed), nil
}

func writeOwnerPID(file *os.File, pid int) error {
	if file == nil || pid < 1 {
		return ErrInvalidMetadata
	}
	record := make([]byte, ownerRecordSize)
	encoded := []byte("pid=" + strconv.Itoa(pid))
	if len(encoded) > len(record) {
		return ErrInvalidMetadata
	}
	copy(record, encoded)
	if count, err := file.WriteAt(record, ownerRecordOffset); err != nil {
		return fmt.Errorf("workspace lock: write owner: %w", err)
	} else if count != len(record) {
		return fmt.Errorf("workspace lock: write owner: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("workspace lock: sync owner: %w", err)
	}
	return nil
}

func clearOwnerPID(file *os.File) error {
	if file == nil {
		return nil
	}
	if count, err := file.WriteAt(
		make([]byte, ownerRecordSize),
		ownerRecordOffset,
	); err != nil {
		return fmt.Errorf("workspace lock: clear owner: %w", err)
	} else if count != ownerRecordSize {
		return fmt.Errorf("workspace lock: clear owner: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("workspace lock: sync cleared owner: %w", err)
	}
	return nil
}
