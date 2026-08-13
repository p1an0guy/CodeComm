//go:build windows

package agent

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const maxWindowsCanonicalPathUnits = 32768

func inspectNativeDirectory(path string) (_ nativeDirectoryIdentity, err error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nativeDirectoryIdentity{}, err
	}
	pathPointer, err := windows.UTF16PtrFromString(filepath.Clean(absolute))
	if err != nil {
		return nativeDirectoryIdentity{}, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nativeDirectoryIdentity{}, err
	}
	defer func() {
		if closeErr := windows.CloseHandle(handle); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return nativeDirectoryIdentity{}, err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return nativeDirectoryIdentity{}, fmt.Errorf("%q is not a directory", absolute)
	}
	canonical, err := finalWindowsPath(handle)
	if err != nil {
		return nativeDirectoryIdentity{}, err
	}
	fileID := uint64(information.FileIndexHigh)<<32 |
		uint64(information.FileIndexLow)
	return nativeDirectoryIdentity{
		canonicalPath: canonical,
		value: fmt.Sprintf(
			"codecomm-directory-v1:windows:%08x:%016x",
			information.VolumeSerialNumber,
			fileID,
		),
	}, nil
}

func finalWindowsPath(handle windows.Handle) (string, error) {
	size, err := windows.GetFinalPathNameByHandle(handle, nil, 0, 0)
	if err != nil {
		return "", err
	}
	if size == 0 || size > maxWindowsCanonicalPathUnits {
		return "", fmt.Errorf("invalid canonical Windows path length %d", size)
	}
	buffer := make([]uint16, size+1)
	length, err := windows.GetFinalPathNameByHandle(
		handle,
		&buffer[0],
		uint32(len(buffer)),
		0,
	)
	if err != nil {
		return "", err
	}
	if length == 0 || length >= uint32(len(buffer)) {
		return "", fmt.Errorf("canonical Windows path changed while reading")
	}
	path := windows.UTF16ToString(buffer[:length])
	switch {
	case strings.HasPrefix(path, `\\?\UNC\`):
		path = `\\` + path[len(`\\?\UNC\`):]
	case strings.HasPrefix(path, `\\?\`):
		path = path[len(`\\?\`):]
	}
	return filepath.Clean(path), nil
}
