package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
)

func TestHistoricalAttestationMissingPrefixFailsExplicitScrub(t *testing.T) {
	t.Parallel()

	fixture, stage, root, _ := logicalSnapshotInstallFixture(t)
	installed, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	)
	if err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(): %v", err)
	}
	tail := logicalSnapshotTailBatch(t, fixture, installed.Heads)
	imported, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		tail,
	)
	if err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(tail): %v", err)
	}
	successor := logicalSnapshotInstallSuccessorState(
		t,
		fixture,
		imported.Heads,
	)
	if _, err := fixture.target.InstallSuccessor(
		context.Background(),
		successor,
	); err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}
	if err := fixture.target.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`DELETE FROM replication_attestations
				  WHERE attestation_id = ?1;`,
				logicalSnapshotAttestationID(root),
			)
		},
	); err != nil {
		t.Fatalf("delete historical snapshot prefix: %v", err)
	}

	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(missing historical prefix): %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close(reopened): %v", err)
		}
	}()
	if err := reopened.VerifyCommitmentHistory(
		context.Background(),
	); !errors.Is(err, ErrReplicaEvidenceMode) {
		t.Fatalf(
			"VerifyCommitmentHistory(missing historical prefix) error = %v, want evidence failure",
			err,
		)
	}
}

func TestHistoricalGenesisAuthorityUsesFirstAcceptedEvent(t *testing.T) {
	t.Parallel()

	authority := resultRangeTestAuthorityDevice(t)
	secondaryKey := resultBatchPrivateKey(2)
	defer clear(secondaryKey)
	secondaryPublic := bytes.Clone(
		secondaryKey.Public().(ed25519.PublicKey),
	)
	secondaryID, err := device.DeriveID(secondaryPublic)
	if err != nil {
		t.Fatalf("DeriveID(secondary): %v", err)
	}
	secondary := device.Device{
		ID:                secondaryID,
		Role:              device.RoleEditor,
		IdentityPublicKey: secondaryPublic,
		DaemonVersion:     "1.0.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	initial := resultBatchInitialState(t, authority.ID)
	initial.Projections.Devices = append(
		initial.Projections.Devices,
		secondary,
	)
	initial.Projections.AuditCounters = append(
		initial.Projections.AuditCounters,
		auditcounter.Counter{DeviceID: secondaryID},
	)

	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "authority", "state.db"),
		nil,
	)
	heads, err := database.Initialize(context.Background(), initial)
	if err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	rejected := rejectedApplyRequest(
		t,
		historicalTestSignedTaskEvent(
			t,
			secondaryKey,
			testAuditEventID,
			1,
		),
		heads,
	)
	rejected.LogIndex = 1
	rejectedResult, err := database.Apply(context.Background(), rejected)
	if err != nil {
		t.Fatalf("Apply(rejected bootstrap predecessor): %v", err)
	}
	accepted := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	accepted.LogIndex = 2
	accepted.Projections.Tasks = []task.Task{resultBatchTaskProjection()}
	accepted.Audit[0].ResultIndex = rejectedResult.Heads.ResultIndex + 1
	if _, err := database.Apply(context.Background(), accepted); err != nil {
		t.Fatalf("Apply(first accepted event): %v", err)
	}

	var signer domain.DeviceID
	err = database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			state, found, err := readConsensusState(conn)
			if err != nil {
				return err
			}
			if !found {
				return errors.New("active consensus state is missing")
			}
			identities, err := historicalIdentityCatalog(conn)
			if err != nil {
				return err
			}
			signer, err = historicalGenesisAuthoritySigner(
				conn,
				state,
				identities,
			)
			return err
		},
	)
	if err != nil {
		t.Fatalf("historicalGenesisAuthoritySigner(): %v", err)
	}
	if signer != authority.ID {
		t.Fatalf(
			"genesis authority signer = %q, want first accepted signer %q",
			signer,
			authority.ID,
		)
	}
}

func historicalTestSignedTaskEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	eventID domain.UUIDv7,
	sequence uint64,
) event.SignedEvent {
	t.Helper()
	deviceID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := event.NewMCPBinding(
		deviceID,
		testAgentSessionID,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             event.KindTaskCreated,
			EntityID:         event.StringEntityID(string(testTaskID)),
			RationaleSummary: "create historical test task",
			Actions:          []event.Action{},
			Payload:          []byte(`{}`),
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      domain.UUIDv7(testSessionID),
			WorkspaceID:    testWorkspaceID,
			CreatedAt:      testAppliedAt,
			OriginSequence: sequence,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
