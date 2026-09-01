//go:build windows

package workspacelock

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsLockDescriptorRejectsUntrustedAccess(t *testing.T) {
	t.Parallel()

	const user = "S-1-5-21-1000-1000-1000-1000"
	current, err := windows.StringToSid(user)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := windows.SecurityDescriptorFromString(
		"O:" + user + "D:(A;;GA;;;" + user + ")(A;;GA;;;SY)(A;;GA;;;BA)",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsLockDescriptor(valid, current); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}

	for name, descriptorText := range map[string]string{
		"wrong owner": "O:SYD:(A;;GA;;;" + user + ")",
		"world read": "O:" + user +
			"D:(A;;GA;;;" + user + ")(A;;GR;;;WD)",
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
			if err := validateWindowsLockDescriptor(
				descriptor,
				current,
			); !errors.Is(err, ErrInsecureFile) {
				t.Fatalf("insecure descriptor error = %v", err)
			}
		})
	}
}

func TestWindowsLockRejectsUNCPath(t *testing.T) {
	t.Parallel()

	if err := validatePlatformPath(
		`\\server\share\state.db.join.lock`,
	); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("UNC path error = %v", err)
	}
}
