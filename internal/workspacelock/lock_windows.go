//go:build windows

package workspacelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxWindowsLockPathUnits = 32768

const windowsLockWriteMask windows.ACCESS_MASK = windows.GENERIC_ALL |
	windows.GENERIC_WRITE |
	windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER

var errLockWouldBlock = errors.New("workspace lock: operation would block")

func validatePlatformPath(path string) error {
	absolute, err := windows.FullPath(filepath.Clean(path))
	if err != nil {
		return errors.Join(ErrInvalidPath, err)
	}
	lower := strings.ToLower(absolute)
	if strings.HasPrefix(lower, `\\?\unc\`) ||
		strings.HasPrefix(lower, `\??\unc\`) ||
		strings.HasPrefix(lower, `\\.\`) ||
		strings.HasPrefix(lower, `\\`) &&
			!strings.HasPrefix(lower, `\\?\`) {
		return fmt.Errorf("%w: remote and device paths are forbidden", ErrInvalidPath)
	}
	encoded, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return errors.Join(ErrInvalidPath, err)
	}
	buffer := make([]uint16, maxWindowsLockPathUnits)
	if err := windows.GetVolumePathName(
		encoded,
		&buffer[0],
		uint32(len(buffer)),
	); err != nil {
		return errors.Join(ErrInvalidPath, err)
	}
	rootPointer, err := windows.UTF16PtrFromString(
		windows.UTF16ToString(buffer),
	)
	if err != nil {
		return errors.Join(ErrInvalidPath, err)
	}
	switch windows.GetDriveType(rootPointer) {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_RAMDISK:
		return nil
	default:
		return fmt.Errorf("%w: lock must use a local writable volume", ErrInvalidPath)
	}
}

func validatePlatformFile(
	_ string,
	file *os.File,
	info os.FileInfo,
) error {
	if file == nil || info == nil || !info.Mode().IsRegular() {
		return ErrInsecureFile
	}
	handle := windows.Handle(file.Fd())
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		handle,
		&information,
	); err != nil {
		return err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInsecureFile
	}
	if err := validateWindowsLockHandleVolume(handle); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return errors.Join(ErrInsecureFile, err)
	}
	return validateWindowsLockDescriptor(descriptor, user.User.Sid)
}

func validateWindowsLockDescriptor(
	descriptor *windows.SECURITY_DESCRIPTOR,
	currentUser *windows.SID,
) error {
	if descriptor == nil || currentUser == nil || !currentUser.IsValid() {
		return ErrInsecureFile
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil ||
		owner == nil ||
		ownerDefaulted ||
		!owner.Equals(currentUser) {
		return errors.Join(ErrInsecureFile, err)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 {
		return errors.Join(ErrInsecureFile, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.Join(ErrInsecureFile, err)
	}
	ownerCanWrite := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil ||
			ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Sizeof(*ace)) {
			return errors.Join(ErrInsecureFile, err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return ErrInsecureFile
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return ErrInsecureFile
		}
		if !trustedWindowsLockSID(sid, currentUser) {
			return ErrInsecureFile
		}
		if sid.Equals(currentUser) &&
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 &&
			ace.Mask&windowsLockWriteMask != 0 {
			ownerCanWrite = true
		}
	}
	if !ownerCanWrite {
		return ErrInsecureFile
	}
	return nil
}

func trustedWindowsLockSID(sid, currentUser *windows.SID) bool {
	return sid.Equals(currentUser) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
}

func validateWindowsLockHandleVolume(handle windows.Handle) error {
	size, err := windows.GetFinalPathNameByHandle(handle, nil, 0, 0)
	if err != nil || size == 0 || size > maxWindowsLockPathUnits {
		return errors.Join(ErrInvalidPath, err)
	}
	buffer := make([]uint16, size+1)
	length, err := windows.GetFinalPathNameByHandle(
		handle,
		&buffer[0],
		uint32(len(buffer)),
		0,
	)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return errors.Join(ErrInvalidPath, err)
	}
	finalPath := strings.ToLower(windows.UTF16ToString(buffer[:length]))
	if strings.HasPrefix(finalPath, `\\?\unc\`) ||
		strings.HasPrefix(finalPath, `\??\unc\`) {
		return ErrInvalidPath
	}
	return nil
}

func lockFile(file *os.File) error {
	if file == nil {
		return ErrInsecureFile
	}
	var overlapped windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|
			windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		lockRegionSize,
		0,
		&overlapped,
	)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errLockWouldBlock
	}
	return err
}

func unlockFile(file *os.File) error {
	if file == nil {
		return nil
	}
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(
		windows.Handle(file.Fd()),
		0,
		lockRegionSize,
		0,
		&overlapped,
	)
}

func sleepForOwnerRecord() {
	time.Sleep(10 * time.Millisecond)
}
