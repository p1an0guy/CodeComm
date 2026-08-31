//go:build windows

package joinbootstrap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxWindowsJournalPathUnits = 32768

const windowsJournalWriteMask windows.ACCESS_MASK = windows.GENERIC_ALL |
	windows.GENERIC_WRITE |
	windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER

func validateJournalPath(path string) error {
	return validateWindowsJournalVolume(path)
}

func validateJournalDirectory(path string, info os.FileInfo) error {
	if info == nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: insecure directory", ErrInvalidJournal)
	}
	return validateWindowsJournalObject(path, true)
}

func validateJournalFile(path string, info os.FileInfo) error {
	if info == nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: insecure file", ErrInvalidJournal)
	}
	return validateWindowsJournalObject(path, false)
}

func validateWindowsJournalObject(path string, directory bool) (resultErr error) {
	if err := validateWindowsJournalVolume(path); err != nil {
		return err
	}
	extended, err := windowsJournalPath(path)
	if err != nil {
		return fmt.Errorf("%w: normalize path: %v", ErrInvalidJournal, err)
	}
	pathPointer, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return fmt.Errorf("%w: encode path: %v", ErrInvalidJournal, err)
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|
			windows.FILE_SHARE_WRITE|
			windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return fmt.Errorf("%w: open private object: %v", ErrInvalidJournal, err)
	}
	defer func() {
		if closeErr := windows.CloseHandle(handle); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		handle,
		&information,
	); err != nil {
		return fmt.Errorf("%w: inspect private object: %v", ErrInvalidJournal, err)
	}
	isDirectory := information.FileAttributes&
		windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		isDirectory != directory {
		return fmt.Errorf("%w: private object is a reparse point or wrong type", ErrInvalidJournal)
	}
	if err := validateWindowsJournalHandleVolume(handle); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("%w: read security descriptor: %v", ErrInvalidJournal, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("%w: read current Windows user: %v", ErrInvalidJournal, err)
	}
	return validateWindowsJournalDescriptor(descriptor, user.User.Sid)
}

func validateWindowsJournalDescriptor(
	descriptor *windows.SECURITY_DESCRIPTOR,
	currentUser *windows.SID,
) error {
	if descriptor == nil || currentUser == nil || !currentUser.IsValid() {
		return fmt.Errorf("%w: missing security identity", ErrInvalidJournal)
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil ||
		owner == nil ||
		ownerDefaulted ||
		!owner.Equals(currentUser) {
		return fmt.Errorf("%w: object owner is not the current user", ErrInvalidJournal)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 {
		return fmt.Errorf("%w: object has no DACL", ErrInvalidJournal)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: object has a null or invalid DACL", ErrInvalidJournal)
	}
	ownerCanWrite := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil ||
			ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Sizeof(*ace)) {
			return fmt.Errorf("%w: malformed DACL entry", ErrInvalidJournal)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return fmt.Errorf("%w: malformed DACL identity", ErrInvalidJournal)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("%w: unsupported DACL entry", ErrInvalidJournal)
		}
		if !trustedWindowsJournalSID(sid, currentUser) {
			return fmt.Errorf(
				"%w: DACL grants access to an untrusted principal",
				ErrInvalidJournal,
			)
		}
		if sid.Equals(currentUser) &&
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 &&
			ace.Mask&windowsJournalWriteMask != 0 {
			ownerCanWrite = true
		}
	}
	if !ownerCanWrite {
		return fmt.Errorf("%w: DACL does not grant the owner write access", ErrInvalidJournal)
	}
	return nil
}

func trustedWindowsJournalSID(sid, currentUser *windows.SID) bool {
	return sid.Equals(currentUser) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
}

func validateWindowsJournalVolume(path string) error {
	absolute, err := windows.FullPath(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("%w: resolve volume: %v", ErrInvalidJournal, err)
	}
	lower := strings.ToLower(absolute)
	if strings.HasPrefix(lower, `\\?\unc\`) ||
		strings.HasPrefix(lower, `\??\unc\`) ||
		strings.HasPrefix(lower, `\\.\`) ||
		strings.HasPrefix(lower, `\\`) &&
			!strings.HasPrefix(lower, `\\?\`) {
		return fmt.Errorf("%w: remote and device paths are forbidden", ErrInvalidJournal)
	}
	encoded, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return fmt.Errorf("%w: encode volume path: %v", ErrInvalidJournal, err)
	}
	buffer := make([]uint16, maxWindowsJournalPathUnits)
	if err := windows.GetVolumePathName(
		encoded,
		&buffer[0],
		uint32(len(buffer)),
	); err != nil {
		return fmt.Errorf("%w: resolve volume root: %v", ErrInvalidJournal, err)
	}
	root := windows.UTF16ToString(buffer)
	rootPointer, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return fmt.Errorf("%w: encode volume root: %v", ErrInvalidJournal, err)
	}
	switch windows.GetDriveType(rootPointer) {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_RAMDISK:
		return nil
	default:
		return fmt.Errorf("%w: state must use a local writable volume", ErrInvalidJournal)
	}
}

func validateWindowsJournalHandleVolume(handle windows.Handle) error {
	size, err := windows.GetFinalPathNameByHandle(handle, nil, 0, 0)
	if err != nil || size == 0 || size > maxWindowsJournalPathUnits {
		return fmt.Errorf("%w: resolve final path: %v", ErrInvalidJournal, err)
	}
	buffer := make([]uint16, size+1)
	length, err := windows.GetFinalPathNameByHandle(
		handle,
		&buffer[0],
		uint32(len(buffer)),
		0,
	)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return fmt.Errorf("%w: read final path: %v", ErrInvalidJournal, err)
	}
	finalPath := strings.ToLower(windows.UTF16ToString(buffer[:length]))
	if strings.HasPrefix(finalPath, `\\?\unc\`) ||
		strings.HasPrefix(finalPath, `\??\unc\`) {
		return fmt.Errorf("%w: remote state is forbidden", ErrInvalidJournal)
	}
	return nil
}

func syncJournalDirectory(path string) (resultErr error) {
	if err := validateWindowsJournalVolume(path); err != nil {
		return err
	}
	extended, err := windowsJournalPath(path)
	if err != nil {
		return err
	}
	pathPointer, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pathPointer,
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
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, windows.CloseHandle(handle))
	}()
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		handle,
		&information,
	); err != nil {
		return err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: sync target is not a private directory", ErrInvalidJournal)
	}
	if err := windows.FlushFileBuffers(handle); err != nil &&
		!errors.Is(err, windows.ERROR_INVALID_FUNCTION) &&
		!errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		return err
	}
	return nil
}

func windowsJournalPath(path string) (string, error) {
	absolute, err := windows.FullPath(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(absolute, `\\?\`) ||
		strings.HasPrefix(absolute, `\??\`) ||
		strings.HasPrefix(absolute, `\\.\`) {
		return absolute, nil
	}
	if strings.HasPrefix(absolute, `\\`) {
		return `\\?\UNC\` + absolute[2:], nil
	}
	return `\\?\` + absolute, nil
}
