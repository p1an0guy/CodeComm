package store

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestExportReplicationWatermarkReturnsOneVerifiedCurrentCut(
	t *testing.T,
) {
	fixture := newResultRangeFixture(t)

	got, err := fixture.store.ExportReplicationWatermark(
		context.Background(),
		fixture.authorityDeviceID,
	)
	if err != nil {
		t.Fatalf("ExportReplicationWatermark(): %v", err)
	}
	digest, err := fixture.store.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(): %v", err)
	}
	if got.SessionID != domain.UUIDv7(testSessionID) ||
		got.WorkspaceID != testWorkspaceID ||
		got.RecoveryGeneration != 0 ||
		got.ResultIndex != fixture.second.Heads.ResultIndex ||
		got.ResultHash != fixture.second.Heads.ResultHash ||
		got.ChainIndex != fixture.second.Heads.ChainIndex ||
		got.ChainHash != fixture.second.Heads.ChainHash ||
		got.ProjectionAccumulator !=
			fixture.second.Heads.ProjectionAccumulator ||
		got.ProjectionStateDigest != digest ||
		got.Authority.VoterSetVersion != 1 ||
		!got.Authority.Contains(fixture.authorityDeviceID) {
		t.Fatalf("ExportReplicationWatermark() = %+v", got)
	}

	local, err := fixture.store.LocalState().ExportReplicationWatermark(
		context.Background(),
		fixture.authorityDeviceID,
	)
	if err != nil || !reflect.DeepEqual(local, got) {
		t.Fatalf("LocalState.ExportReplicationWatermark() = (%+v, %v)", local, err)
	}
}

func TestExportReplicationWatermarkRejectsUnauthorizedSignerAndCorruption(
	t *testing.T,
) {
	t.Run("unauthorized signer", func(t *testing.T) {
		fixture := newResultRangeFixture(t)
		encoded := string(fixture.authorityDeviceID)
		last := byte('f')
		if encoded[len(encoded)-1] == last {
			last = 'e'
		}
		other := domain.DeviceID(encoded[:len(encoded)-1] + string(last))
		if _, err := fixture.store.ExportReplicationWatermark(
			context.Background(),
			other,
		); !errors.Is(err, ErrResultRangeAuthorityNotCovered) {
			t.Fatalf("ExportReplicationWatermark() error = %v", err)
		}
	})

	t.Run("commitment corruption", func(t *testing.T) {
		fixture := newResultRangeFixture(t)
		commitmentExecute(
			t,
			fixture.store,
			`UPDATE consensus_state
			    SET result_hash = zeroblob(32)
			  WHERE singleton = 1;`,
		)
		if _, err := fixture.store.ExportReplicationWatermark(
			context.Background(),
			fixture.authorityDeviceID,
		); err == nil {
			t.Fatal("ExportReplicationWatermark() accepted corruption")
		}
	})
}

func TestExportReplicationWatermarkValidatesCapabilityAndContext(
	t *testing.T,
) {
	fixture := newResultRangeFixture(t)
	//lint:ignore SA1012 This test verifies the explicit nil-context contract.
	if _, err := fixture.store.ExportReplicationWatermark(nil, fixture.authorityDeviceID); !errors.Is(
		err,
		ErrInvalidOptions,
	) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := fixture.store.ExportReplicationWatermark(
		context.Background(),
		"",
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid signer error = %v", err)
	}
	if _, err := (LocalState{}).ExportReplicationWatermark(
		context.Background(),
		fixture.authorityDeviceID,
	); !errors.Is(err, ErrInvalidLocalState) {
		t.Fatalf("zero LocalState error = %v", err)
	}
}
