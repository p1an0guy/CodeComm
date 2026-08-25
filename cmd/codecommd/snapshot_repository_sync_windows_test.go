//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSyncDaemonSnapshotDirectoryWindows(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(directory, "artifact"),
		[]byte("snapshot"),
		0o600,
	); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	if err := syncDaemonSnapshotDirectory(directory); err != nil {
		t.Fatalf("sync snapshot directory: %v", err)
	}
}

func TestSyncDaemonSnapshotDirectoryWindowsLongPath(t *testing.T) {
	directory := t.TempDir()
	for len(directory) < 300 {
		directory = filepath.Join(directory, strings.Repeat("d", 32))
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create long snapshot directory: %v", err)
		}
	}

	if err := syncDaemonSnapshotDirectory(directory); err != nil {
		t.Fatalf("sync long snapshot directory: %v", err)
	}
}

func TestSyncDaemonSnapshotDirectoryWindowsMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	err := syncDaemonSnapshotDirectory(path)
	if err == nil {
		t.Fatal("sync missing snapshot directory succeeded")
	}
	var pathError *os.PathError
	if !errors.As(err, &pathError) {
		t.Fatalf("sync error type = %T, want *os.PathError", err)
	}
	if pathError.Op != "open" || pathError.Path != path {
		t.Fatalf(
			"sync path error = %#v, want open error for %q",
			pathError,
			path,
		)
	}
}

func TestSyncDaemonSnapshotDirectoryWindowsRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("snapshot"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	err := syncDaemonSnapshotDirectory(path)
	if !errors.Is(err, windows.ERROR_DIRECTORY) {
		t.Fatalf(
			"sync regular file error = %v, want ERROR_DIRECTORY",
			err,
		)
	}
	assertDaemonSnapshotWindowsPathError(t, err, "open", path)
}

func TestSyncDaemonSnapshotDirectoryWindowsUsesDurableHandleContract(
	t *testing.T,
) {
	const (
		path   = `\\?\C:\codecomm\snapshots`
		handle = windows.Handle(0x1234)
	)
	var calls []string
	api := daemonSnapshotDirectoryWindowsAPI{
		createFile: func(
			name *uint16,
			access uint32,
			share uint32,
			security *windows.SecurityAttributes,
			disposition uint32,
			flags uint32,
			template windows.Handle,
		) (windows.Handle, error) {
			calls = append(calls, "open")
			if got := windows.UTF16PtrToString(name); got != path {
				t.Errorf("CreateFile path = %q, want %q", got, path)
			}
			wantAccess := uint32(
				windows.GENERIC_READ | windows.GENERIC_WRITE,
			)
			if access != wantAccess {
				t.Errorf(
					"CreateFile access = %#x, want %#x",
					access,
					wantAccess,
				)
			}
			wantShare := uint32(
				windows.FILE_SHARE_READ |
					windows.FILE_SHARE_WRITE |
					windows.FILE_SHARE_DELETE,
			)
			if share != wantShare {
				t.Errorf(
					"CreateFile share = %#x, want %#x",
					share,
					wantShare,
				)
			}
			if security != nil ||
				disposition != windows.OPEN_EXISTING ||
				flags != windows.FILE_FLAG_BACKUP_SEMANTICS|
					windows.FILE_FLAG_OPEN_REPARSE_POINT ||
				template != 0 {
				t.Errorf(
					"CreateFile trailing arguments = (%p, %#x, %#x, %#x)",
					security,
					disposition,
					flags,
					template,
				)
			}
			return handle, nil
		},
		fileInformation: func(
			got windows.Handle,
			information *windows.ByHandleFileInformation,
		) error {
			calls = append(calls, "stat")
			if got != handle {
				t.Errorf("GetFileInformationByHandle handle = %#x", got)
			}
			information.FileAttributes = windows.FILE_ATTRIBUTE_DIRECTORY
			return nil
		},
		flushFileBuffers: func(got windows.Handle) error {
			calls = append(calls, "flush")
			if got != handle {
				t.Errorf("FlushFileBuffers handle = %#x", got)
			}
			return nil
		},
		closeHandle: func(got windows.Handle) error {
			calls = append(calls, "close")
			if got != handle {
				t.Errorf("CloseHandle handle = %#x", got)
			}
			return nil
		},
	}

	if err := syncDaemonSnapshotDirectoryWithWindowsAPI(
		path,
		api,
	); err != nil {
		t.Fatalf("sync with recording API: %v", err)
	}
	if want := []string{"open", "stat", "flush", "close"}; !slices.Equal(
		calls,
		want,
	) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestSyncDaemonSnapshotDirectoryWindowsFailsClosed(t *testing.T) {
	openFailure := errors.New("open failure")
	statFailure := errors.New("stat failure")
	flushFailure := errors.New("flush failure")
	closeFailure := errors.New("close failure")
	tests := []struct {
		name       string
		options    daemonSnapshotDirectoryWindowsAPITestOptions
		wantOp     string
		wantErrors []error
		wantCalls  []string
	}{
		{
			name: "open",
			options: daemonSnapshotDirectoryWindowsAPITestOptions{
				openErr:        openFailure,
				fileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY,
			},
			wantOp:     "open",
			wantErrors: []error{openFailure},
			wantCalls:  []string{"open"},
		},
		{
			name: "inspect",
			options: daemonSnapshotDirectoryWindowsAPITestOptions{
				statErr:        statFailure,
				fileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY,
			},
			wantOp:     "stat",
			wantErrors: []error{statFailure},
			wantCalls:  []string{"open", "stat", "close"},
		},
		{
			name:    "not directory",
			options: daemonSnapshotDirectoryWindowsAPITestOptions{},
			wantOp:  "open",
			wantErrors: []error{
				windows.ERROR_DIRECTORY,
			},
			wantCalls: []string{"open", "stat", "close"},
		},
		{
			name: "reparse directory",
			options: daemonSnapshotDirectoryWindowsAPITestOptions{
				fileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY |
					windows.FILE_ATTRIBUTE_REPARSE_POINT,
			},
			wantOp: "open",
			wantErrors: []error{
				windows.ERROR_DIRECTORY,
			},
			wantCalls: []string{"open", "stat", "close"},
		},
		{
			name: "flush",
			options: daemonSnapshotDirectoryWindowsAPITestOptions{
				flushErr:       flushFailure,
				fileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY,
			},
			wantOp:     "sync",
			wantErrors: []error{flushFailure},
			wantCalls:  []string{"open", "stat", "flush", "close"},
		},
		{
			name: "close",
			options: daemonSnapshotDirectoryWindowsAPITestOptions{
				closeErr:       closeFailure,
				fileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY,
			},
			wantOp:     "close",
			wantErrors: []error{closeFailure},
			wantCalls:  []string{"open", "stat", "flush", "close"},
		},
		{
			name: "flush and close",
			options: daemonSnapshotDirectoryWindowsAPITestOptions{
				flushErr:       flushFailure,
				closeErr:       closeFailure,
				fileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY,
			},
			wantOp:     "sync",
			wantErrors: []error{flushFailure, closeFailure},
			wantCalls:  []string{"open", "stat", "flush", "close"},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			const path = `\\?\C:\codecomm\snapshots`
			err := syncDaemonSnapshotDirectoryWithWindowsAPI(
				path,
				daemonSnapshotDirectoryWindowsTestAPI(
					&calls,
					test.options,
				),
			)
			if err == nil {
				t.Fatal("sync succeeded")
			}
			for _, want := range test.wantErrors {
				if !errors.Is(err, want) {
					t.Errorf("sync error = %v, want wrapping %v", err, want)
				}
			}
			assertDaemonSnapshotWindowsPathError(
				t,
				err,
				test.wantOp,
				path,
			)
			if !slices.Equal(calls, test.wantCalls) {
				t.Errorf("calls = %v, want %v", calls, test.wantCalls)
			}
		})
	}
}

type daemonSnapshotDirectoryWindowsAPITestOptions struct {
	openErr        error
	statErr        error
	flushErr       error
	closeErr       error
	fileAttributes uint32
}

func daemonSnapshotDirectoryWindowsTestAPI(
	calls *[]string,
	options daemonSnapshotDirectoryWindowsAPITestOptions,
) daemonSnapshotDirectoryWindowsAPI {
	const handle = windows.Handle(0x1234)
	return daemonSnapshotDirectoryWindowsAPI{
		createFile: func(
			*uint16,
			uint32,
			uint32,
			*windows.SecurityAttributes,
			uint32,
			uint32,
			windows.Handle,
		) (windows.Handle, error) {
			*calls = append(*calls, "open")
			if options.openErr != nil {
				return 0, options.openErr
			}
			return handle, nil
		},
		fileInformation: func(
			got windows.Handle,
			information *windows.ByHandleFileInformation,
		) error {
			*calls = append(*calls, "stat")
			if got != handle {
				return windows.ERROR_INVALID_HANDLE
			}
			information.FileAttributes = options.fileAttributes
			return options.statErr
		},
		flushFileBuffers: func(got windows.Handle) error {
			*calls = append(*calls, "flush")
			if got != handle {
				return windows.ERROR_INVALID_HANDLE
			}
			return options.flushErr
		},
		closeHandle: func(got windows.Handle) error {
			*calls = append(*calls, "close")
			if got != handle {
				return windows.ERROR_INVALID_HANDLE
			}
			return options.closeErr
		},
	}
}

func assertDaemonSnapshotWindowsPathError(
	t *testing.T,
	err error,
	op string,
	path string,
) {
	t.Helper()
	var pathError *os.PathError
	if !errors.As(err, &pathError) {
		t.Fatalf("sync error type = %T, want *os.PathError", err)
	}
	if pathError.Op != op || pathError.Path != path {
		t.Fatalf(
			"sync path error = %#v, want %s error for %q",
			pathError,
			op,
			path,
		)
	}
}
