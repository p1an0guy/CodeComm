//go:build windows

package consensus

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var replaceRaftBoltFileW = windows.NewLazySystemDLL(
	"kernel32.dll",
).NewProc("ReplaceFileW")

func openRaftBoltFileNoFollow(
	path string,
	flag int,
	_ os.FileMode,
) (*os.File, error) {
	encodedPath, err := raftBoltWindowsPath(path)
	if err != nil {
		return nil, err
	}
	pathPointer, err := windows.UTF16PtrFromString(encodedPath)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.GENERIC_READ)
	if flag&(os.O_WRONLY|os.O_RDWR) != 0 {
		access |= windows.GENERIC_WRITE
	}
	creationDisposition := uint32(windows.OPEN_EXISTING)
	switch {
	case flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		creationDisposition = windows.CREATE_NEW
	case flag&os.O_CREATE != 0 && flag&os.O_TRUNC != 0:
		creationDisposition = windows.CREATE_ALWAYS
	case flag&os.O_CREATE != 0:
		creationDisposition = windows.OPEN_ALWAYS
	case flag&os.O_TRUNC != 0:
		creationDisposition = windows.TRUNCATE_EXISTING
	}
	handle, err := windows.CreateFile(
		pathPointer,
		access,
		windows.FILE_SHARE_READ|
			windows.FILE_SHARE_WRITE|
			windows.FILE_SHARE_DELETE,
		nil,
		creationDisposition,
		windows.FILE_ATTRIBUTE_NORMAL|
			windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func validateRaftBoltFileHandle(file *os.File, info os.FileInfo) error {
	if file == nil || info == nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: file is not regular", ErrInsecureConsensusPath)
	}
	var native windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(file.Fd()),
		&native,
	); err != nil {
		return err
	}
	if native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		native.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fmt.Errorf(
			"%w: file is a reparse point or directory",
			ErrInsecureConsensusPath,
		)
	}
	if native.NumberOfLinks != 1 {
		return fmt.Errorf(
			"%w: file has %d hard links",
			ErrInsecureConsensusPath,
			native.NumberOfLinks,
		)
	}
	return validateWindowsConsensusHandleSecurity(
		windows.Handle(file.Fd()),
	)
}

func replaceRaftBoltFile(source, target string) error {
	encodedSource, err := raftBoltWindowsPath(source)
	if err != nil {
		return err
	}
	encodedTarget, err := raftBoltWindowsPath(target)
	if err != nil {
		return err
	}
	sourcePointer, err := windows.UTF16PtrFromString(encodedSource)
	if err != nil {
		return err
	}
	targetPointer, err := windows.UTF16PtrFromString(encodedTarget)
	if err != nil {
		return err
	}
	success, _, callErr := replaceRaftBoltFileW.Call(
		uintptr(unsafe.Pointer(targetPointer)),
		uintptr(unsafe.Pointer(sourcePointer)),
		0,
		0,
		0,
		0,
	)
	runtime.KeepAlive(sourcePointer)
	runtime.KeepAlive(targetPointer)
	if success == 0 {
		return callErr
	}
	return nil
}

func raftBoltWindowsPath(path string) (string, error) {
	absolute, err := windows.FullPath(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	switch {
	case strings.HasPrefix(absolute, `\\?\`),
		strings.HasPrefix(absolute, `\??\`),
		strings.HasPrefix(absolute, `\\.\`):
		return absolute, nil
	case strings.HasPrefix(absolute, `\\`):
		return `\\?\UNC\` + absolute[2:], nil
	default:
		return `\\?\` + absolute, nil
	}
}
