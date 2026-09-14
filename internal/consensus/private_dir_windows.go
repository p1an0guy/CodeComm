//go:build windows

package consensus

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxWindowsConsensusPathUnits = 32768

const windowsConsensusWriteMask windows.ACCESS_MASK = windows.GENERIC_ALL |
	windows.GENERIC_WRITE |
	windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER

func validateConsensusDirectoryPath(path string) error {
	absolute, err := windows.FullPath(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf(
			"%w: resolve storage volume: %v",
			ErrInsecureConsensusPath,
			err,
		)
	}
	lower := strings.ToLower(absolute)
	if strings.HasPrefix(lower, `\\?\unc\`) ||
		strings.HasPrefix(lower, `\??\unc\`) ||
		strings.HasPrefix(lower, `\\.\`) ||
		strings.HasPrefix(lower, `\\`) &&
			!strings.HasPrefix(lower, `\\?\`) {
		return fmt.Errorf(
			"%w: remote and device paths are forbidden",
			ErrInsecureConsensusPath,
		)
	}
	encoded, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInsecureConsensusPath, err)
	}
	buffer := make([]uint16, maxWindowsConsensusPathUnits)
	if err := windows.GetVolumePathName(
		encoded,
		&buffer[0],
		uint32(len(buffer)),
	); err != nil {
		return fmt.Errorf(
			"%w: resolve storage volume root: %v",
			ErrInsecureConsensusPath,
			err,
		)
	}
	root, err := windows.UTF16PtrFromString(
		windows.UTF16ToString(buffer),
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInsecureConsensusPath, err)
	}
	switch windows.GetDriveType(root) {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_RAMDISK:
		return nil
	default:
		return fmt.Errorf(
			"%w: storage must use a local writable volume",
			ErrInsecureConsensusPath,
		)
	}
}

func validatePrivateDirectory(path string, info os.FileInfo) error {
	if info == nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%w: storage path is not a real directory",
			ErrInsecureConsensusPath,
		)
	}
	if err := validateConsensusDirectoryPath(path); err != nil {
		return err
	}
	handle, err := openWindowsConsensusDirectory(
		path,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return validateWindowsConsensusHandleSecurity(handle)
}

func validateWindowsConsensusHandleSecurity(
	handle windows.Handle,
) error {
	if handle == 0 || handle == windows.InvalidHandle {
		return fmt.Errorf(
			"%w: storage handle is unavailable",
			ErrInsecureConsensusPath,
		)
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: read storage object DACL: %v",
			ErrInsecureConsensusPath,
			err,
		)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf(
			"%w: read current Windows storage user: %v",
			ErrInsecureConsensusPath,
			err,
		)
	}
	return validateWindowsConsensusDescriptor(
		descriptor,
		user.User.Sid,
	)
}

func validateWindowsConsensusDescriptor(
	descriptor *windows.SECURITY_DESCRIPTOR,
	currentUser *windows.SID,
) error {
	if descriptor == nil || currentUser == nil || !currentUser.IsValid() {
		return fmt.Errorf(
			"%w: missing storage security identity",
			ErrInsecureConsensusPath,
		)
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil ||
		owner == nil ||
		ownerDefaulted ||
		!owner.Equals(currentUser) {
		return fmt.Errorf(
			"%w: storage owner is not the current user",
			ErrInsecureConsensusPath,
		)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 {
		return fmt.Errorf(
			"%w: storage object has no DACL",
			ErrInsecureConsensusPath,
		)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf(
			"%w: storage object has a null or invalid DACL",
			ErrInsecureConsensusPath,
		)
	}
	ownerCanWrite := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil ||
			ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Sizeof(*ace)) {
			return fmt.Errorf(
				"%w: malformed storage DACL entry",
				ErrInsecureConsensusPath,
			)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return fmt.Errorf(
				"%w: malformed storage DACL identity",
				ErrInsecureConsensusPath,
			)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf(
				"%w: unsupported storage DACL entry",
				ErrInsecureConsensusPath,
			)
		}
		if !trustedWindowsConsensusSID(sid, currentUser) {
			return fmt.Errorf(
				"%w: storage DACL grants access to an untrusted principal",
				ErrInsecureConsensusPath,
			)
		}
		if sid.Equals(currentUser) &&
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 &&
			ace.Mask&windowsConsensusWriteMask != 0 {
			ownerCanWrite = true
		}
	}
	if !ownerCanWrite {
		return fmt.Errorf(
			"%w: storage object DACL does not grant owner write access",
			ErrInsecureConsensusPath,
		)
	}
	return nil
}

func trustedWindowsConsensusSID(
	sid *windows.SID,
	currentUser *windows.SID,
) bool {
	return sid.Equals(currentUser) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
}

func openWindowsConsensusDirectory(
	path string,
	access uint32,
) (windows.Handle, error) {
	encodedPath, err := raftBoltWindowsPath(path)
	if err != nil {
		return 0, err
	}
	pathPointer, err := windows.UTF16PtrFromString(encodedPath)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		access,
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
		return 0, err
	}
	valid := false
	defer func() {
		if !valid {
			_ = windows.CloseHandle(handle)
		}
	}()
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		handle,
		&information,
	); err != nil {
		return 0, err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return 0, fmt.Errorf(
			"%w: storage handle is not a real directory",
			ErrInsecureConsensusPath,
		)
	}
	if err := validateWindowsConsensusFinalPath(handle, path); err != nil {
		return 0, err
	}
	valid = true
	return handle, nil
}

func validateWindowsConsensusFinalPath(
	handle windows.Handle,
	path string,
) error {
	size, err := windows.GetFinalPathNameByHandle(handle, nil, 0, 0)
	if err != nil || size == 0 || size > maxWindowsConsensusPathUnits {
		return fmt.Errorf(
			"%w: resolve final storage path: %v",
			ErrInsecureConsensusPath,
			err,
		)
	}
	buffer := make([]uint16, size+1)
	length, err := windows.GetFinalPathNameByHandle(
		handle,
		&buffer[0],
		uint32(len(buffer)),
		0,
	)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return fmt.Errorf(
			"%w: read final storage path: %v",
			ErrInsecureConsensusPath,
			err,
		)
	}
	finalPath := normalizeWindowsConsensusPath(
		windows.UTF16ToString(buffer[:length]),
	)
	expected, err := longWindowsConsensusPath(path)
	if err != nil {
		return fmt.Errorf("%w: expand storage path: %v", ErrInsecureConsensusPath, err)
	}
	if strings.HasPrefix(finalPath, `\\?\unc\`) ||
		strings.HasPrefix(finalPath, `\??\unc\`) ||
		finalPath != normalizeWindowsConsensusPath(expected) {
		return fmt.Errorf(
			"%w: storage path traverses a remote or reparse-backed directory",
			ErrInsecureConsensusPath,
		)
	}
	return nil
}

func longWindowsConsensusPath(path string) (string, error) {
	expected, err := raftBoltWindowsPath(path)
	if err != nil {
		return "", err
	}
	encoded, err := windows.UTF16PtrFromString(expected)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, maxWindowsConsensusPathUnits)
	length, err := windows.GetLongPathName(
		encoded,
		&buffer[0],
		uint32(len(buffer)),
	)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return "", errors.Join(errors.New("resolve long storage path"), err)
	}
	return windows.UTF16ToString(buffer[:length]), nil
}

func normalizeWindowsConsensusPath(path string) string {
	return strings.TrimRight(strings.ToLower(path), `\/`)
}

func syncConsensusDirectory(path string) (resultErr error) {
	handle, err := openWindowsConsensusDirectory(
		path,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
	)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, windows.CloseHandle(handle))
	}()
	if err := windows.FlushFileBuffers(handle); err != nil &&
		!errors.Is(err, windows.ERROR_INVALID_FUNCTION) &&
		!errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		return err
	}
	return nil
}
