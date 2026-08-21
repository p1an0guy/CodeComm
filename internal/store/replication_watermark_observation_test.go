package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/replication"
	"zombiezen.com/go/sqlite"
)

func TestRecordSettledReplicationAcknowledgementPersistsAndReopens(
	t *testing.T,
) {
	fixture := newResultBatchImportFixture(t)
	if _, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		fixture.request,
	); err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(): %v", err)
	}
	acknowledgement := resultBatchWatermarkAcknowledgement(t, fixture)
	request := VerifiedReplicationWatermarkObservation{
		RelayPeerID:     fixture.request.RelayPeerID,
		Acknowledgement: acknowledgement,
		VerifiedAt:      "2026-08-19T20:01:00Z",
	}
	if err := fixture.target.RecordSettledReplicationAcknowledgement(
		context.Background(),
		request,
	); err != nil {
		t.Fatalf("RecordSettledReplicationAcknowledgement(): %v", err)
	}
	if err := fixture.target.RecordSettledReplicationAcknowledgement(
		context.Background(),
		request,
	); err != nil {
		t.Fatalf("RecordSettledReplicationAcknowledgement(retry): %v", err)
	}
	replacement := request
	replacement.RelayPeerID = resultBatchWatermarkRelayDeviceID(t, 19)
	replacement.VerifiedAt = "2026-08-19T20:02:00Z"
	if err := fixture.target.RecordSettledReplicationAcknowledgement(
		context.Background(),
		replacement,
	); err != nil {
		t.Fatalf("RecordSettledReplicationAcknowledgement(replacement): %v", err)
	}
	assertCounts(t, fixture.target, map[string]int64{
		"replication_watermark_observations": 1,
	})
	assertStoredWatermarkObservationSource(
		t,
		fixture.target,
		replacement.RelayPeerID,
		replacement.VerifiedAt,
	)

	input := acknowledgement.Unsigned().Input()
	input.ResultHash[0] ^= 0xff
	unsigned, err := replication.NewUnsignedAcknowledgement(input)
	if err != nil {
		t.Fatalf("NewUnsignedAcknowledgement(invalid replacement): %v", err)
	}
	invalid, err := replication.SignAcknowledgement(
		unsigned,
		resultBatchPrivateKey(1),
	)
	if err != nil {
		t.Fatalf("SignAcknowledgement(invalid replacement): %v", err)
	}
	if err := fixture.target.RecordSettledReplicationAcknowledgement(
		context.Background(),
		VerifiedReplicationWatermarkObservation{
			RelayPeerID:     resultBatchWatermarkRelayDeviceID(t, 20),
			Acknowledgement: invalid,
			VerifiedAt:      "2026-08-19T20:03:00Z",
		},
	); !errors.Is(err, ErrInvalidReplicationWatermarkObservation) {
		t.Fatalf("invalid replacement error = %v", err)
	}
	assertStoredWatermarkObservationSource(
		t,
		fixture.target,
		replacement.RelayPeerID,
		replacement.VerifiedAt,
	)

	progress, err := fixture.target.SettledReplicationProgress(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("SettledReplicationProgress(): %v", err)
	}
	metadata := acknowledgement.Unsigned().Metadata()
	if progress.Blocker != nil ||
		len(progress.Observations) != 1 ||
		progress.Observations[0].SignerDeviceID !=
			metadata.ServerDeviceID ||
		progress.Observations[0].AuthorityVersion !=
			metadata.ServerAuthorityVersion ||
		progress.Observations[0].VerifiedResultIndex !=
			metadata.ResultIndex ||
		progress.Observations[0].ServerAppliedResultIndex !=
			metadata.ServerAppliedResultIndex {
		t.Fatalf("settled progress = %+v", progress)
	}

	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened := openTestStore(t, path, nil)
	if err := reopened.VerifyCommitmentHistory(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifyCommitmentHistory(reopen): %v", err)
	}
}

func TestRecordSettledReplicationAcknowledgementRejectsWrongCutAndTamper(
	t *testing.T,
) {
	fixture := newResultBatchImportFixture(t)
	if _, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		fixture.request,
	); err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(): %v", err)
	}
	valid := resultBatchWatermarkAcknowledgement(t, fixture)
	input := valid.Unsigned().Input()
	input.ResultHash[0] ^= 0xff
	unsigned, err := replication.NewUnsignedAcknowledgement(input)
	if err != nil {
		t.Fatalf("NewUnsignedAcknowledgement(wrong cut): %v", err)
	}
	wrong, err := replication.SignAcknowledgement(
		unsigned,
		resultBatchPrivateKey(1),
	)
	if err != nil {
		t.Fatalf("SignAcknowledgement(wrong cut): %v", err)
	}
	if err := fixture.target.RecordSettledReplicationAcknowledgement(
		context.Background(),
		VerifiedReplicationWatermarkObservation{
			RelayPeerID:     fixture.request.RelayPeerID,
			Acknowledgement: wrong,
			VerifiedAt:      "2026-08-19T20:01:00Z",
		},
	); !errors.Is(err, ErrInvalidReplicationWatermarkObservation) {
		t.Fatalf("wrong-cut observation error = %v", err)
	}
	assertCounts(t, fixture.target, map[string]int64{
		"replication_watermark_observations": 0,
	})

	if err := fixture.target.RecordSettledReplicationAcknowledgement(
		context.Background(),
		VerifiedReplicationWatermarkObservation{
			RelayPeerID:     fixture.request.RelayPeerID,
			Acknowledgement: valid,
			VerifiedAt:      "2026-08-19T20:01:00Z",
		},
	); err != nil {
		t.Fatalf("RecordSettledReplicationAcknowledgement(valid): %v", err)
	}
	commitmentExecute(
		t,
		fixture.target,
		`UPDATE replication_watermark_observations
		    SET signature = zeroblob(64);`,
	)
	if err := fixture.target.VerifyCommitmentHistory(
		context.Background(),
	); !errors.Is(err, ErrInvalidReplicationWatermarkObservation) {
		t.Fatalf("tampered observation verification error = %v", err)
	}
}

func resultBatchWatermarkAcknowledgement(
	t *testing.T,
	fixture resultBatchImportFixture,
) replication.Acknowledgement {
	t.Helper()
	view, err := fixture.target.VerifiedSettledNonvoterView(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("VerifiedSettledNonvoterView(): %v", err)
	}
	metadata := fixture.request.Batch.Unsigned().Metadata()
	unsigned, err := replication.NewUnsignedAcknowledgement(
		replication.AcknowledgementInput{
			SessionID:                view.SessionID,
			WorkspaceID:              view.WorkspaceID,
			RecoveryGeneration:       view.RecoveryGeneration,
			ServerDeviceID:           metadata.ServerDeviceID,
			ServerAuthorityVersion:   metadata.ServerAuthorityVersion,
			ResultIndex:              view.Heads.ResultIndex,
			ResultHash:               chain.Digest(view.Heads.ResultHash),
			ChainIndex:               view.Heads.ChainIndex,
			ChainHash:                chain.Digest(view.Heads.ChainHash),
			ProjectionAccumulator:    chain.Digest(view.Heads.ProjectionAccumulator),
			ProjectionStateDigest:    chain.Digest(view.ProjectionStateDigest),
			ServerAppliedResultIndex: view.Heads.ResultIndex,
		},
	)
	if err != nil {
		t.Fatalf("NewUnsignedAcknowledgement(): %v", err)
	}
	acknowledgement, err := replication.SignAcknowledgement(
		unsigned,
		resultBatchPrivateKey(1),
	)
	if err != nil {
		t.Fatalf("SignAcknowledgement(): %v", err)
	}
	return acknowledgement
}

func resultBatchWatermarkRelayDeviceID(
	t *testing.T,
	seed byte,
) domain.DeviceID {
	t.Helper()
	privateKey := resultBatchPrivateKey(seed)
	defer clear(privateKey)
	deviceID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("device.DeriveID(watermark relay): %v", err)
	}
	return deviceID
}

func assertStoredWatermarkObservationSource(
	t *testing.T,
	database *Store,
	wantRelay domain.DeviceID,
	wantVerifiedAt domain.Timestamp,
) {
	t.Helper()
	var relay domain.DeviceID
	var verifiedAt domain.Timestamp
	if err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return queryOne(
				conn,
				`SELECT relay_peer_device_id, verified_at
				   FROM replication_watermark_observations;`,
				func(stmt *sqlite.Stmt) {
					relay = domain.DeviceID(stmt.ColumnText(0))
					verifiedAt = domain.Timestamp(stmt.ColumnText(1))
				},
			)
		},
	); err != nil {
		t.Fatalf("read stored watermark observation: %v", err)
	}
	if relay != wantRelay || verifiedAt != wantVerifiedAt {
		t.Fatalf(
			"stored observation source = (%s, %s), want (%s, %s)",
			relay,
			verifiedAt,
			wantRelay,
			wantVerifiedAt,
		)
	}
}
