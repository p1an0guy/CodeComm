//go:build windows

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func openDaemonSnapshotPath(path string, directory bool) (*os.File, error) {
	if !cleanAbsolutePath(path) {
		return nil, errDaemonSnapshotIntegrity
	}
	extended, err := daemonSnapshotDirectoryWindowsPath(path)
	if err != nil {
		return nil, err
	}
	pathPointer, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|
			windows.FILE_SHARE_WRITE|
			windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return nil, err
	}
	closeHandle := true
	defer func() {
		if closeHandle {
			_ = windows.CloseHandle(handle)
		}
	}()

	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		handle,
		&information,
	); err != nil {
		return nil, err
	}
	isDirectory := information.FileAttributes&
		windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		directory != isDirectory {
		return nil, errDaemonSnapshotIntegrity
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return nil, errDaemonSnapshotIntegrity
	}
	closeHandle = false
	return file, nil
}

func daemonSnapshotOpenFlags() int {
	return 0
}

func validDaemonSnapshotFileInfo(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok ||
		attributes.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	fileType := info.Mode().Type()
	return directory && fileType == os.ModeDir ||
		!directory && fileType == 0
}
