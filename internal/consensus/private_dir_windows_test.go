//go:build windows

package consensus

import (
	"errors"
	"os"
	"path/filepath"
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
