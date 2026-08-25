//go:build windows

package main

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

type daemonSnapshotDirectoryWindowsAPI struct {
	createFile func(
		*uint16,
		uint32,
		uint32,
		*windows.SecurityAttributes,
		uint32,
		uint32,
		windows.Handle,
	) (windows.Handle, error)
	fileInformation func(
		windows.Handle,
		*windows.ByHandleFileInformation,
	) error
	flushFileBuffers func(windows.Handle) error
	closeHandle      func(windows.Handle) error
}

func syncDaemonSnapshotDirectory(path string) error {
	return syncDaemonSnapshotDirectoryWithWindowsAPI(
		path,
		daemonSnapshotDirectoryNativeWindowsAPI(),
	)
}

func syncDaemonSnapshotDirectoryWithWindowsAPI(
	path string,
	api daemonSnapshotDirectoryWindowsAPI,
) (resultErr error) {
	windowsPath, err := daemonSnapshotDirectoryWindowsPath(path)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	pathPointer, err := windows.UTF16PtrFromString(windowsPath)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	handle, err := api.createFile(
		pathPointer,
		// FlushFileBuffers requires write access. Read access makes the
		// handle-level directory check reliable on local and SMB filesystems.
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|
			windows.FILE_SHARE_WRITE|
			windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|
			windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer func() {
		if closeErr := api.closeHandle(handle); closeErr != nil {
			resultErr = errors.Join(
				resultErr,
				&os.PathError{
					Op:   "close",
					Path: path,
					Err:  closeErr,
				},
			)
		}
	}()

	var information windows.ByHandleFileInformation
	if err := api.fileInformation(handle, &information); err != nil {
		return &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return &os.PathError{
			Op:   "open",
			Path: path,
			Err:  windows.ERROR_DIRECTORY,
		}
	}
	if err := api.flushFileBuffers(handle); err != nil {
		return &os.PathError{Op: "sync", Path: path, Err: err}
	}
	return nil
}

func daemonSnapshotDirectoryNativeWindowsAPI() daemonSnapshotDirectoryWindowsAPI {
	return daemonSnapshotDirectoryWindowsAPI{
		createFile:       windows.CreateFile,
		fileInformation:  windows.GetFileInformationByHandle,
		flushFileBuffers: windows.FlushFileBuffers,
		closeHandle:      windows.CloseHandle,
	}
}

func daemonSnapshotDirectoryWindowsPath(path string) (string, error) {
	if path == "" {
		return "", windows.ERROR_PATH_NOT_FOUND
	}
	if strings.HasPrefix(path, `\\?\`) ||
		strings.HasPrefix(path, `\??\`) ||
		strings.HasPrefix(path, `\\.\`) {
		return path, nil
	}
	absolutePath, err := windows.FullPath(path)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(absolutePath, `\\?\`) ||
		strings.HasPrefix(absolutePath, `\??\`) ||
		strings.HasPrefix(absolutePath, `\\.\`) {
		return absolutePath, nil
	}
	if strings.HasPrefix(absolutePath, `\\`) {
		return `\\?\UNC\` + absolutePath[2:], nil
	}
	return `\\?\` + absolutePath, nil
}
