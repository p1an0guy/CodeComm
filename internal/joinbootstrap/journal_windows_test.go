//go:build windows

package joinbootstrap

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsJournalDescriptorRejectsUntrustedAccess(t *testing.T) {
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
			if err := validateWindowsJournalDescriptor(
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
			if err := validateWindowsJournalDescriptor(
				descriptor,
				current,
			); !errors.Is(err, ErrInvalidJournal) {
				t.Fatalf("insecure descriptor error = %v", err)
			}
		})
	}
}

func TestWindowsJournalVolumeRejectsUNCPath(t *testing.T) {
	t.Parallel()

	if err := validateWindowsJournalVolume(
		`\\server\share\state.db`,
	); !errors.Is(err, ErrInvalidJournal) {
		t.Fatalf("UNC path error = %v", err)
	}
}
