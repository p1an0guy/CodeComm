package credentialstore

import (
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	testSessionID = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abc")
	testDeviceID  = domain.DeviceID("cc1" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	testInviteID  = domain.UUIDv7("01890f47-3e73-7d5a-8c9b-123456789abc")
)

func TestIdentityReferenceIsStableAndValid(t *testing.T) {
	t.Parallel()

	reference := IdentityReference()
	if err := reference.Validate(); err != nil {
		t.Fatalf("IdentityReference().Validate() error = %v", err)
	}
	if reference.Kind() != KindIdentity {
		t.Fatalf("IdentityReference().Kind() = %q, want %q", reference.Kind(), KindIdentity)
	}
	if reference.String() != "identity/v1" {
		t.Fatalf("IdentityReference().String() = %q", reference.String())
	}
}

func TestEpochReferenceBindsSessionDeviceAndEpoch(t *testing.T) {
	t.Parallel()

	reference, err := EpochReference(testSessionID, testDeviceID, 42)
	if err != nil {
		t.Fatalf("EpochReference() error = %v", err)
	}
	if err := reference.Validate(); err != nil {
		t.Fatalf("Reference.Validate() error = %v", err)
	}
	if reference.Kind() != KindEpoch {
		t.Fatalf("Reference.Kind() = %q, want %q", reference.Kind(), KindEpoch)
	}
	want := "epoch/v1/" + string(testSessionID) + "/" + string(testDeviceID) + "/42"
	if reference.String() != want {
		t.Fatalf("Reference.String() = %q, want %q", reference.String(), want)
	}
}

func TestEpochReferenceRejectsInvalidComponents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sessionID domain.UUIDv7
		deviceID  domain.DeviceID
		epoch     uint64
	}{
		{name: "session", sessionID: "", deviceID: testDeviceID, epoch: 1},
		{name: "device", sessionID: testSessionID, deviceID: "", epoch: 1},
		{name: "zero epoch", sessionID: testSessionID, deviceID: testDeviceID, epoch: 0},
		{
			name:      "epoch over signed JSON limit",
			sessionID: testSessionID,
			deviceID:  testDeviceID,
			epoch:     domain.MaxSafeInteger + 1,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reference, err := EpochReference(test.sessionID, test.deviceID, test.epoch)
			if !errors.Is(err, ErrInvalidReference) {
				t.Fatalf("EpochReference() error = %v, want %v", err, ErrInvalidReference)
			}
			if reference != (Reference{}) {
				t.Fatalf("EpochReference() = %+v after error, want zero value", reference)
			}
		})
	}
}

func TestInviteReferenceBindsSessionAndInvite(t *testing.T) {
	t.Parallel()

	reference, err := InviteReference(testSessionID, testInviteID)
	if err != nil {
		t.Fatalf("InviteReference() error = %v", err)
	}
	if err := reference.Validate(); err != nil {
		t.Fatalf("Reference.Validate() error = %v", err)
	}
	if reference.Kind() != KindInvite {
		t.Fatalf("Reference.Kind() = %q, want %q", reference.Kind(), KindInvite)
	}
	want := "invite/v1/" + string(testSessionID) + "/" + string(testInviteID)
	if reference.String() != want {
		t.Fatalf("Reference.String() = %q, want %q", reference.String(), want)
	}
}

func TestInviteReferenceRejectsInvalidComponents(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		sessionID domain.UUIDv7
		inviteID  domain.UUIDv7
	}{
		{name: "session", inviteID: testInviteID},
		{name: "invite", sessionID: testSessionID},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reference, err := InviteReference(test.sessionID, test.inviteID)
			if !errors.Is(err, ErrInvalidReference) {
				t.Fatalf("InviteReference() error = %v, want %v", err, ErrInvalidReference)
			}
			if reference != (Reference{}) {
				t.Fatalf("InviteReference() = %+v after error, want zero value", reference)
			}
		})
	}
}

func TestInviteReferenceValidationRejectsAliasesAndMalformedKeys(t *testing.T) {
	t.Parallel()

	canonical, err := InviteReference(testSessionID, testInviteID)
	if err != nil {
		t.Fatalf("InviteReference() error = %v", err)
	}
	tests := []Reference{
		{kind: KindIdentity, key: canonical.key},
		{kind: KindEpoch, key: canonical.key},
		{kind: KindInvite, key: IdentityReference().key},
		{kind: KindInvite, key: "invite/v2/" + string(testSessionID) + "/" + string(testInviteID)},
		{kind: KindInvite, key: canonical.key + "/"},
		{kind: KindInvite, key: "invite/v1/" + strings.ToUpper(string(testSessionID)) + "/" + string(testInviteID)},
	}
	for _, reference := range tests {
		if err := reference.Validate(); !errors.Is(err, ErrInvalidReference) {
			t.Errorf("Reference(%+v).Validate() error = %v, want %v", reference, err, ErrInvalidReference)
		}
	}
}

func TestReferenceValidateRejectsZeroAndForgedValues(t *testing.T) {
	t.Parallel()

	tests := []Reference{
		{},
		{kind: KindIdentity, key: "identity/v2"},
		{kind: KindEpoch, key: "epoch/v1/" + strings.Repeat("x", 120)},
		{kind: Kind("unknown"), key: "identity/v1"},
	}
	for _, reference := range tests {
		if err := reference.Validate(); !errors.Is(err, ErrInvalidReference) {
			t.Errorf("Reference(%+v).Validate() error = %v, want %v", reference, err, ErrInvalidReference)
		}
	}
}
