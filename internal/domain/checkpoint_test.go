package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckpointValidate(t *testing.T) {
	t.Parallel()

	valid := Checkpoint{
		SessionID:                "01890f47-3e72-7000-8000-000000000001",
		WorkspaceID:              "550e8400-e29b-41d4-a716-446655440000",
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           DeviceID("cc1" + strings.Repeat("1", 64)),
		Term:                     1,
		CoveredAppliedLogIndex:   1,
		DigestVersion:            1,
		ProjectionSchemaVersion:  1,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Checkpoint.Validate() error = %v", err)
	}

	invalidIdentity := valid
	invalidIdentity.SessionID = ""
	if err := invalidIdentity.Validate(); !errors.Is(
		err,
		ErrInvalidCheckpointIdentity,
	) {
		t.Fatalf("invalid identity error = %v", err)
	}

	invalidNumber := valid
	invalidNumber.Term = 0
	if err := invalidNumber.Validate(); !errors.Is(
		err,
		ErrInvalidCheckpointNumber,
	) {
		t.Fatalf("invalid number error = %v", err)
	}

	overBound := valid
	overBound.CoveredResultIndex = MaxSafeInteger + 1
	if err := overBound.Validate(); !errors.Is(
		err,
		ErrInvalidCheckpointNumber,
	) {
		t.Fatalf("over-bound number error = %v", err)
	}

	chainAhead := valid
	chainAhead.CoveredChainIndex = 2
	chainAhead.CoveredResultIndex = 1
	if err := chainAhead.Validate(); !errors.Is(
		err,
		ErrInvalidCheckpointNumber,
	) {
		t.Fatalf("chain-ahead number error = %v", err)
	}
}
