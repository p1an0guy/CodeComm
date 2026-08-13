package credentialauthority

import (
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	testSessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000001",
	)
	otherSessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000002",
	)
	testCheckpointID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000003",
	)
)

func TestAuthorityValidateAcceptsGenesisAndHandoff(t *testing.T) {
	t.Parallel()

	for _, value := range []Authority{
		validGenesis(),
		validHandoff(2),
	} {
		if err := value.Validate(); err != nil {
			t.Errorf("Authority.Validate(%q) error = %v", value.ActivationSource, err)
		}
	}
}

func TestAuthorityValidateRejectsMalformedRows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		base   Authority
		mutate func(*Authority)
		want   error
	}{
		{
			name: "invalid session",
			base: validGenesis(),
			mutate: func(value *Authority) {
				value.SessionID = ""
			},
			want: ErrInvalidSessionID,
		},
		{
			name: "invalid voter count",
			base: validGenesis(),
			mutate: func(value *Authority) {
				value.VoterDeviceIDs = voterIDs(2)
			},
			want: ErrInvalidVoterCount,
		},
		{
			name: "invalid voter ID",
			base: validGenesis(),
			mutate: func(value *Authority) {
				value.VoterDeviceIDs[0] = ""
			},
			want: ErrInvalidVoterDeviceID,
		},
		{
			name: "unsorted voters",
			base: validHandoff(2),
			mutate: func(value *Authority) {
				value.VoterDeviceIDs[0], value.VoterDeviceIDs[1] =
					value.VoterDeviceIDs[1], value.VoterDeviceIDs[0]
			},
			want: ErrVotersNotSortedUnique,
		},
		{
			name: "zero version",
			base: validGenesis(),
			mutate: func(value *Authority) {
				value.VoterSetVersion = 0
			},
			want: ErrInvalidVoterSetVersion,
		},
		{
			name: "unknown source",
			base: validGenesis(),
			mutate: func(value *Authority) {
				value.ActivationSource = ActivationSource("unknown")
			},
			want: ErrInvalidActivationSource,
		},
		{
			name: "genesis after version one",
			base: validGenesis(),
			mutate: func(value *Authority) {
				value.VoterSetVersion = 2
			},
			want: ErrInvalidActivationVersion,
		},
		{
			name: "handoff at version one",
			base: validHandoff(2),
			mutate: func(value *Authority) {
				value.VoterSetVersion = 1
			},
			want: ErrInvalidActivationVersion,
		},
		{
			name: "invalid proof voter",
			base: validHandoff(2),
			mutate: func(value *Authority) {
				value.ActivationProofs[0].VoterDeviceID = ""
			},
			want: ErrInvalidProofVoter,
		},
		{
			name: "proof order",
			base: validHandoff(2),
			mutate: func(value *Authority) {
				value.ActivationProofs[0], value.ActivationProofs[1] =
					value.ActivationProofs[1], value.ActivationProofs[0]
			},
			want: ErrProofOrder,
		},
		{
			name: "malformed proof object",
			base: validHandoff(2),
			mutate: func(value *Authority) {
				value.ActivationProofs[0].CanonicalJSON = []byte(`[]`)
			},
			want: ErrInvalidProofObject,
		},
		{
			name: "genesis checkpoint",
			base: validGenesis(),
			mutate: func(value *Authority) {
				value.ActivationCheckpointEventID = testCheckpointID
			},
			want: ErrGenesisHandoffFields,
		},
		{
			name: "genesis proof",
			base: validGenesis(),
			mutate: func(value *Authority) {
				value.ActivationProofs = validHandoff(2).ActivationProofs
			},
			want: ErrGenesisHandoffFields,
		},
		{
			name: "handoff checkpoint",
			base: validHandoff(2),
			mutate: func(value *Authority) {
				value.ActivationCheckpointEventID = ""
			},
			want: ErrHandoffCheckpoint,
		},
		{
			name: "handoff proof count",
			base: validHandoff(2),
			mutate: func(value *Authority) {
				value.ActivationProofs = value.ActivationProofs[:2]
			},
			want: ErrHandoffProofCount,
		},
		{
			name: "handoff signer",
			base: validHandoff(2),
			mutate: func(value *Authority) {
				value.PriorAuthoritySigner = ""
			},
			want: ErrHandoffPriorAuthority,
		},
		{
			name: "handoff signature",
			base: validHandoff(2),
			mutate: func(value *Authority) {
				value.PriorAuthorityHandoff = nil
			},
			want: ErrHandoffPriorAuthority,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			value := test.base.Clone()
			test.mutate(&value)
			if err := value.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Authority.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAuthorityCloneDoesNotAliasMutableInput(t *testing.T) {
	t.Parallel()

	original := validHandoff(2)
	clone := original.Clone()
	clone.VoterDeviceIDs[0] = voterID('e')
	clone.ActivationProofs[0].VoterDeviceID = voterID('e')
	clone.ActivationProofs[0].CanonicalJSON[0] = '['
	clone.PriorAuthorityHandoff[0] ^= 0xff

	if original.VoterDeviceIDs[0] != voterID('1') ||
		original.ActivationProofs[0].VoterDeviceID != voterID('1') ||
		string(original.ActivationProofs[0].CanonicalJSON) != `{"voter":1}` ||
		original.PriorAuthorityHandoff[0] != 0x61 {
		t.Fatalf("Clone() aliases original: %#v", original)
	}
}

func TestAuthorityTransitionAcceptsActivationAndRecovery(t *testing.T) {
	t.Parallel()

	before := validGenesis()
	after := validHandoff(3)
	if err := ValidateTransition(OperationActivate, before, after); err != nil {
		t.Fatalf("activation transition error = %v", err)
	}

	recovered := Authority{
		SessionID:        otherSessionID,
		VoterDeviceIDs:   []domain.DeviceID{voterID('1')},
		VoterSetVersion:  1,
		ActivationSource: ActivationGenesis,
	}
	if err := ValidateTransition(OperationRecoveryReset, after, recovered); err != nil {
		t.Fatalf("recovery transition error = %v", err)
	}
}

func TestAuthorityTransitionRejectsUnsafeChanges(t *testing.T) {
	t.Parallel()

	before := validGenesis()
	after := validHandoff(2)
	tests := []struct {
		name      string
		operation Operation
		mutate    func(*Authority)
		want      error
	}{
		{
			name:      "unknown operation",
			operation: Operation("unknown"),
			want:      ErrInvalidOperation,
		},
		{
			name:      "handoff activation version one",
			operation: OperationActivate,
			mutate: func(value *Authority) {
				value.VoterSetVersion = before.VoterSetVersion
			},
			want: ErrInvalidActivationVersion,
		},
		{
			name:      "activation changes session",
			operation: OperationActivate,
			mutate: func(value *Authority) {
				value.SessionID = otherSessionID
			},
			want: ErrSessionChanged,
		},
		{
			name:      "signer outside prior authority",
			operation: OperationActivate,
			mutate: func(value *Authority) {
				value.PriorAuthoritySigner = voterID('f')
			},
			want: ErrPriorSignerNotAuthority,
		},
		{
			name:      "recovery keeps session",
			operation: OperationRecoveryReset,
			mutate: func(value *Authority) {
				*value = validGenesis()
			},
			want: ErrInvalidRecoveryAuthority,
		},
		{
			name:      "recovery has multiple voters",
			operation: OperationRecoveryReset,
			mutate: func(value *Authority) {
				*value = validGenesis()
				value.SessionID = otherSessionID
				value.VoterDeviceIDs = voterIDs(3)
			},
			want: ErrInvalidRecoveryAuthority,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			next := after.Clone()
			if test.mutate != nil {
				test.mutate(&next)
			}
			if err := ValidateTransition(
				test.operation,
				before,
				next,
			); !errors.Is(err, test.want) {
				t.Fatalf("ValidateTransition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAuthorityTransitionRejectsSameHandoffVersion(t *testing.T) {
	t.Parallel()

	before := validHandoff(2)
	after := validHandoff(2)
	if err := ValidateTransition(
		OperationActivate,
		before,
		after,
	); !errors.Is(err, ErrAuthorityVersionNotAdvanced) {
		t.Fatalf(
			"ValidateTransition() error = %v, want %v",
			err,
			ErrAuthorityVersionNotAdvanced,
		)
	}
}

func TestAuthorityQueriesReturnCopies(t *testing.T) {
	t.Parallel()

	value := validHandoff(2)
	if !value.Contains(voterID('2')) || value.Contains(voterID('f')) {
		t.Fatal("Contains() returned the wrong membership result")
	}
	got := value.VoterIDs()
	if !reflect.DeepEqual(got, value.VoterDeviceIDs) {
		t.Fatalf("VoterIDs() = %v, want %v", got, value.VoterDeviceIDs)
	}
	got[0] = voterID('e')
	if value.VoterDeviceIDs[0] != voterID('1') {
		t.Fatal("VoterIDs() aliases authority storage")
	}
}

func validGenesis() Authority {
	return Authority{
		SessionID:        testSessionID,
		VoterDeviceIDs:   voterIDs(3),
		VoterSetVersion:  1,
		ActivationSource: ActivationGenesis,
	}
}

func validHandoff(version uint64) Authority {
	ids := voterIDs(3)
	signature := [ed25519.SignatureSize]byte{}
	signature[0] = 0x61
	return Authority{
		SessionID:                   testSessionID,
		VoterDeviceIDs:              ids,
		VoterSetVersion:             version,
		ActivationSource:            ActivationHandoff,
		ActivationCheckpointEventID: testCheckpointID,
		ActivationProofs: []ActivationProof{
			{VoterDeviceID: ids[0], CanonicalJSON: []byte(`{"voter":1}`)},
			{VoterDeviceID: ids[1], CanonicalJSON: []byte(`{"voter":2}`)},
			{VoterDeviceID: ids[2], CanonicalJSON: []byte(`{"voter":3}`)},
		},
		PriorAuthoritySigner:  ids[0],
		PriorAuthorityHandoff: &signature,
	}
}

func voterIDs(count int) []domain.DeviceID {
	result := make([]domain.DeviceID, count)
	for index := range result {
		result[index] = voterID(byte('1' + index))
	}
	return result
}

func voterID(fill byte) domain.DeviceID {
	return domain.DeviceID("cc1" + strings.Repeat(string(fill), 64))
}
