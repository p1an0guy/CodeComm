package device

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	testPublicKeyHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	testDeviceID     = domain.DeviceID("cc121fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9")
)

func TestDeviceValidateAcceptsDocumentedEntity(t *testing.T) {
	t.Parallel()

	device := validDevice()
	if err := device.Validate(); err != nil {
		t.Fatalf("Device.Validate() error = %v", err)
	}
}

func TestDeriveIDUsesFullLowercaseSHA256(t *testing.T) {
	t.Parallel()

	key := testPublicKey(t)
	got, err := DeriveID(key)
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}
	if got != testDeviceID {
		t.Fatalf("DeriveID() = %q, want %q", got, testDeviceID)
	}
	if !got.Valid() {
		t.Fatalf("DeriveID() returned malformed device ID %q", got)
	}
}

func TestDeriveIDRejectsWrongPublicKeyLength(t *testing.T) {
	t.Parallel()

	for _, length := range []int{0, ed25519.PublicKeySize - 1, ed25519.PublicKeySize + 1} {
		length := length
		t.Run(strings.Repeat("x", length), func(t *testing.T) {
			t.Parallel()

			got, err := DeriveID(make(ed25519.PublicKey, length))
			if !errors.Is(err, ErrInvalidIdentityPublicKey) {
				t.Fatalf("DeriveID(%d-byte key) error = %v, want %v", length, err, ErrInvalidIdentityPublicKey)
			}
			if got != "" {
				t.Fatalf("DeriveID(%d-byte key) = %q after error, want zero value", length, got)
			}
		})
	}
}

func TestDeviceValidateRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Device)
		want   error
	}{
		{
			name: "malformed device ID",
			mutate: func(device *Device) {
				device.ID = "cc1"
			},
			want: ErrInvalidID,
		},
		{
			name: "device ID does not commit to key",
			mutate: func(device *Device) {
				device.ID = domain.DeviceID("cc1" + strings.Repeat("0", 64))
			},
			want: ErrDeviceIDMismatch,
		},
		{
			name: "short identity public key",
			mutate: func(device *Device) {
				device.IdentityPublicKey = append(ed25519.PublicKey(nil), device.IdentityPublicKey[:31]...)
			},
			want: ErrInvalidIdentityPublicKey,
		},
		{
			name: "long identity public key",
			mutate: func(device *Device) {
				device.IdentityPublicKey = append(append(ed25519.PublicKey(nil), device.IdentityPublicKey...), 0)
			},
			want: ErrInvalidIdentityPublicKey,
		},
		{
			name: "invalid role",
			mutate: func(device *Device) {
				device.Role = Role("admin")
			},
			want: ErrInvalidRole,
		},
		{
			name: "invalid daemon version",
			mutate: func(device *Device) {
				device.DaemonVersion = "v1.2.3"
			},
			want: ErrInvalidDaemonVersion,
		},
		{
			name: "zero max apply level",
			mutate: func(device *Device) {
				device.MaxApplyLevel = 0
			},
			want: ErrInvalidMaxApplyLevel,
		},
		{
			name: "max apply level over protocol limit",
			mutate: func(device *Device) {
				device.MaxApplyLevel = domain.MaxApplyLevel + 1
			},
			want: ErrInvalidMaxApplyLevel,
		},
		{
			name: "invalid status",
			mutate: func(device *Device) {
				device.Status = Status("pending")
			},
			want: ErrInvalidStatus,
		},
		{
			name: "zero entity version",
			mutate: func(device *Device) {
				device.EntityVersion = 0
			},
			want: ErrInvalidEntityVersion,
		},
		{
			name: "entity version over signed JSON limit",
			mutate: func(device *Device) {
				device.EntityVersion = domain.MaxSafeInteger + 1
			},
			want: ErrInvalidEntityVersion,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			device := validDevice()
			test.mutate(&device)
			if err := device.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Device.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDeviceValidateAcceptsIntegerBounds(t *testing.T) {
	t.Parallel()

	device := validDevice()
	device.MaxApplyLevel = domain.MaxApplyLevel
	device.EntityVersion = domain.MaxSafeInteger
	if err := device.Validate(); err != nil {
		t.Fatalf("Device.Validate() at signed integer limits error = %v", err)
	}
}

func TestDeviceValidateAcceptsAllRolesAndStatuses(t *testing.T) {
	t.Parallel()

	for _, role := range Roles() {
		role := role
		for _, status := range Statuses() {
			status := status
			t.Run(string(role)+"/"+string(status), func(t *testing.T) {
				t.Parallel()

				device := validDevice()
				device.Role = role
				device.Status = status
				if err := device.Validate(); err != nil {
					t.Fatalf("Device.Validate() error = %v", err)
				}
			})
		}
	}
}

func TestDaemonVersionAcceptsStrictSemVerAtByteLimit(t *testing.T) {
	t.Parallel()

	versions := []string{
		"0.0.0",
		"1.2.3",
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-0A",
		"1.0.0-01a",
		"1.0.0+001",
		"1.0.0-alpha.1+build.001",
		"99999999999999999999.2.3",
		"1.2.3+" + strings.Repeat("a", MaxDaemonVersionBytes-len("1.2.3+")),
	}
	for _, version := range versions {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			device := validDevice()
			device.DaemonVersion = version
			if err := device.Validate(); err != nil {
				t.Fatalf("Device.Validate() with version %q error = %v", version, err)
			}
		})
	}
}

func TestDaemonVersionRejectsInvalidSemVerAndOnePastBound(t *testing.T) {
	t.Parallel()

	versions := []string{
		"",
		"1",
		"1.2",
		"v1.2.3",
		"01.2.3",
		"1.02.3",
		"1.2.03",
		"1.2.3-",
		"1.2.3+",
		"1.2.3-alpha..1",
		"1.2.3-alpha_1",
		"1.2.3-01",
		"1.2.3-β",
		"1.2.3\n",
		"1.2.3+" + strings.Repeat("a", MaxDaemonVersionBytes-len("1.2.3+")+1),
	}
	for _, version := range versions {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			device := validDevice()
			device.DaemonVersion = version
			if err := device.Validate(); !errors.Is(err, ErrInvalidDaemonVersion) {
				t.Fatalf("Device.Validate() with version %q error = %v, want %v", version, err, ErrInvalidDaemonVersion)
			}
		})
	}
}

func TestEnumCollectionsReturnDefensiveCopies(t *testing.T) {
	t.Parallel()

	roles := Roles()
	roles[0] = Role("corrupt")
	if got := Roles()[0]; got != RoleOwner {
		t.Fatalf("Roles()[0] = %q after caller mutation, want %q", got, RoleOwner)
	}

	statuses := Statuses()
	statuses[0] = Status("corrupt")
	if got := Statuses()[0]; got != StatusActive {
		t.Fatalf("Statuses()[0] = %q after caller mutation, want %q", got, StatusActive)
	}
}

func validDevice() Device {
	return Device{
		ID:                testDeviceID,
		Role:              RoleEditor,
		IdentityPublicKey: testPublicKey(nil),
		DaemonVersion:     "1.2.3",
		MaxApplyLevel:     1,
		Status:            StatusActive,
		EntityVersion:     1,
	}
}

func testPublicKey(t *testing.T) ed25519.PublicKey {
	raw, err := hex.DecodeString(testPublicKeyHex)
	if err != nil {
		if t == nil {
			panic(err)
		}
		t.Fatalf("decode test public key: %v", err)
	}
	return ed25519.PublicKey(raw)
}
