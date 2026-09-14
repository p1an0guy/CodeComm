//go:build windows

package consensus

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsConsensusDescriptorRejectsUntrustedAccess(t *testing.T) {
	t.Parallel()

	const user = "S-1-5-21-1000-1000-1000-1000"
	current, err := windows.StringToSid(user)
	if err != nil {
		t.Fatal(err)
	}
	for name, descriptorText := range map[string]string{
		"owner only": "O:" + user + "D:(A;;GA;;;" + user + ")",
		"system and administrators": "O:" + user +
			"D:(A;;GA;;;" + user + ")" +
			"(A;;GA;;;SY)(A;;GA;;;BA)",
	} {
		t.Run(name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(
				descriptorText,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateWindowsConsensusDescriptor(
				descriptor,
				current,
			); err != nil {
				t.Fatalf("valid descriptor rejected: %v", err)
			}
		})
	}

	for name, descriptorText := range map[string]string{
		"wrong owner": "O:SYD:(A;;GA;;;" + user + ")",
		"world read": "O:" + user +
			"D:(A;;GA;;;" + user + ")(A;;GR;;;WD)",
		"world write": "O:" + user +
			"D:(A;;GA;;;" + user + ")(A;;GW;;;WD)",
		"null DACL":       "O:" + user + "D:NO_ACCESS_CONTROL",
		"owner read only": "O:" + user + "D:(A;;GR;;;" + user + ")",
	} {
		t.Run(name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(
				descriptorText,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateWindowsConsensusDescriptor(
				descriptor,
				current,
			); !errors.Is(err, ErrInsecureConsensusPath) {
				t.Fatalf(
					"insecure descriptor error = %v, want %v",
					err,
					ErrInsecureConsensusPath,
				)
			}
		})
	}
}

func TestWindowsConsensusDirectoryRejectsUNCPath(t *testing.T) {
	t.Parallel()

	if err := validateConsensusDirectoryPath(
		`\\server\share\consensus`,
	); !errors.Is(err, ErrInsecureConsensusPath) {
		t.Fatalf("UNC path error = %v", err)
	}
}

func TestWindowsConsensusDirectoryAcceptsShortPathAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consensus-directory-with-long-name")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	shortPath, err := windowsConsensusShortPath(path)
	if err != nil {
		t.Skipf("8.3 aliases unavailable: %v", err)
	}
	if strings.EqualFold(shortPath, path) {
		t.Skip("volume did not assign an 8.3 alias")
	}

	handle, err := openWindowsConsensusDirectory(
		shortPath,
		windows.FILE_READ_ATTRIBUTES,
	)
	if err != nil {
		t.Fatalf("short path alias rejected: %v", err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsConsensusDirectoryRejectsParentReparsePoint(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	child := filepath.Join(target, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	handle, err := openWindowsConsensusDirectory(
		filepath.Join(alias, "child"),
		windows.FILE_READ_ATTRIBUTES,
	)
	if err == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("parent reparse point was accepted")
	}
	if !errors.Is(err, ErrInsecureConsensusPath) {
		t.Fatalf("parent reparse point error = %v", err)
	}
}

func windowsConsensusShortPath(path string) (string, error) {
	encoded, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, maxWindowsConsensusPathUnits)
	length, err := windows.GetShortPathName(
		encoded,
		&buffer[0],
		uint32(len(buffer)),
	)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return "", errors.Join(errors.New("resolve short path"), err)
	}
	return windows.UTF16ToString(buffer[:length]), nil
}

func TestWindowsRaftBoltFileRejectsPermissiveDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raft.db")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("read current user: %v", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + user.User.Sid.String() +
			"D:P(A;;GA;;;" + user.User.Sid.String() + ")" +
			"(A;;GR;;;WD)",
	)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read permissive fixture DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatalf("install permissive fixture DACL: %v", err)
	}

	file, err := openRaftBoltFileNoFollow(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRaftBoltFileHandle(
		file,
		info,
	); !errors.Is(err, ErrInsecureConsensusPath) {
		t.Fatalf(
			"permissive Raft file DACL error = %v, want %v",
			err,
			ErrInsecureConsensusPath,
		)
	}
}
