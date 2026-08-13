package credentialauthorization

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	testSessionID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000001")
	testDeviceID  = domain.DeviceID(
		"cc134750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e",
	)
)

func TestValidateTransitionClampsCredentialTimes(t *testing.T) {
	t.Parallel()

	first := validAuthorization()
	if err := ValidateTransition(nil, first); err != nil {
		t.Fatalf("ValidateTransition(first) error = %v", err)
	}

	successor := validAuthorization()
	successor.Epoch = 2
	successor.IssuedAt = "2024-01-01T00:25:00Z"
	successor.NotBefore = "2024-01-01T00:28:00Z"
	successor.AuthorizationChainIndex = 2
	if err := ValidateTransition(&first, successor); err != nil {
		t.Fatalf("ValidateTransition(successor) error = %v", err)
	}

	late := successor
	late.IssuedAt = "2024-01-02T00:00:00Z"
	late.NotBefore = late.IssuedAt
	if err := ValidateTransition(&first, late); err != nil {
		t.Fatalf("ValidateTransition(late) error = %v", err)
	}
}

func TestPrimaryKeyIncludesSessionIdentity(t *testing.T) {
	t.Parallel()

	first := validAuthorization()
	second := first
	second.SessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000002",
	)
	if first.PrimaryKey() == second.PrimaryKey() {
		t.Fatal("credential primary key collapsed distinct sessions")
	}
}

func TestValidateTransitionRejectsClampViolations(t *testing.T) {
	t.Parallel()

	first := validAuthorization()
	tests := []struct {
		name   string
		mutate func(*Authorization)
		want   error
	}{
		{
			name: "first not before",
			mutate: func(value *Authorization) {
				value.NotBefore = "2024-01-01T00:00:01Z"
			},
			want: ErrNotBeforeClampMismatch,
		},
		{
			name: "early successor",
			mutate: func(value *Authorization) {
				value.Epoch = 2
				value.IssuedAt = "2024-01-01T00:24:59Z"
				value.NotBefore = "2024-01-01T00:28:00Z"
			},
			want: ErrIssuedAtBelowRenewalFloor,
		},
		{
			name: "wrong overlap clamp",
			mutate: func(value *Authorization) {
				value.Epoch = 2
				value.IssuedAt = "2024-01-01T00:25:00Z"
				value.NotBefore = "2024-01-01T00:27:59Z"
			},
			want: ErrNotBeforeClampMismatch,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			next := validAuthorization()
			test.mutate(&next)
			var previous *Authorization
			if next.Epoch > 1 {
				previous = &first
				next.AuthorizationChainIndex = 2
			}
			if err := ValidateTransition(previous, next); !errors.Is(err, test.want) {
				t.Fatalf("ValidateTransition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func validAuthorization() Authorization {
	value := Authorization{
		SessionID:                testSessionID,
		DeviceID:                 testDeviceID,
		Epoch:                    1,
		Role:                     RoleEditor,
		IssuedAt:                 "2024-01-01T00:00:00Z",
		NotBefore:                "2024-01-01T00:00:00Z",
		ValiditySeconds:          ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements: []ClockEndorsement{{
			DeviceID: testDeviceID,
		}},
		AuthorizationChainIndex: 1,
	}
	value.KeyDigest = sha256.Sum256(value.EpochPublicKey[:])
	return value
}
