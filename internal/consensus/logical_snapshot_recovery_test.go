package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	logicalSnapshotRecoverySessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000091",
	)
	logicalSnapshotRecoveryAgentID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000092",
	)
	logicalSnapshotRecoveryRootID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000093",
	)
	logicalSnapshotRecoveryLeaseID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000094",
	)
	logicalSnapshotRecoveryPlanID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000095",
	)
	logicalSnapshotRecoveryMemoryID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000096",
	)
	logicalSnapshotRecoverySecondSessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000097",
	)
)

func TestGenerationZeroBoundaryVerifierVerifiesSignedSuccessor(
	t *testing.T,
) {
	for _, role := range []device.Role{
		device.RoleOwner,
		device.RoleEditor,
	} {
		role := role
		t.Run(string(role), func(t *testing.T) {
			fixture := newLogicalSnapshotRecoveryFixture(t, role)
			verifier, err := NewGenerationZeroBoundaryVerifier(
				fixture.source,
			)
			if err != nil {
				t.Fatalf(
					"NewGenerationZeroBoundaryVerifier(): %v",
					err,
				)
			}

			successor, err := verifier.VerifySuccessorBoundary(
				testContext(t),
				fixture.predecessor,
				fixture.payload,
			)
			if err != nil {
				t.Fatalf("VerifySuccessorBoundary(): %v", err)
			}
			if successor.SessionID !=
				logicalSnapshotRecoverySessionID ||
				successor.WorkspaceID != nodeTestWorkspaceID ||
				successor.RecoveryGeneration != 1 ||
				successor.Predecessor != fixture.predecessor.Heads ||
				successor.DigestVersion != 1 ||
				successor.ProjectionSchemaVersion != 1 ||
				!bytes.Equal(
					successor.GenesisJSON,
					fixture.payload.GenesisJSON,
				) ||
				!bytes.Equal(
					successor.RecoveryAuthorizationJSON,
					fixture.payload.RecoveryAuthorizationJSON,
				) {
				t.Fatalf("verified successor metadata = %+v", successor)
			}

			gotRows, gotDigest := logicalSnapshotRecoveryProjectionState(
				t,
				successor.Projections,
			)
			wantRows, wantDigest :=
				logicalSnapshotRecoveryProjectionState(
					t,
					fixture.expected,
				)
			if !reflect.DeepEqual(gotRows, wantRows) {
				t.Fatalf(
					"verified transform rows differ:\ngot=%#v\nwant=%#v",
					gotRows,
					wantRows,
				)
			}
			if gotDigest != wantDigest ||
				gotDigest != fixture.payload.BoundaryTransformDigest {
				t.Fatalf(
					"verified transform digest = %x, want %x",
					gotDigest,
					wantDigest,
				)
			}

			altered := successor
			altered.Projections.Tasks = append(
				[]task.Task(nil),
				successor.Projections.Tasks...,
			)
			altered.Projections.Tasks[0].Title = "altered after verification"
			if _, err := fixture.source.InstallSuccessor(
				testContext(t),
				altered,
			); !errors.Is(err, store.ErrApplyConflict) {
				t.Fatalf(
					"InstallSuccessor(altered projections) error = %v, want %v",
					err,
					store.ErrApplyConflict,
				)
			}

			if _, err := fixture.source.InstallSuccessor(
				testContext(t),
				successor,
			); err != nil {
				t.Fatalf("InstallSuccessor(verified): %v", err)
			}
			view, err := fixture.source.View(testContext(t))
			if err != nil {
				t.Fatalf("View(successor): %v", err)
			}
			if view.SessionID != logicalSnapshotRecoverySessionID ||
				view.RecoveryGeneration != 1 ||
				chain.Digest(view.ProjectionStateDigest) != wantDigest {
				t.Fatalf("installed successor view = %+v", view)
			}
			snapshot, _, err := decodeReducerStateView(view)
			if err != nil {
				t.Fatalf("decodeReducerStateView(successor): %v", err)
			}
			assertLogicalSnapshotRecoveryTransform(
				t,
				snapshot,
				fixture,
			)

			if err := fixture.source.Close(); err != nil {
				t.Fatalf("Close(successor): %v", err)
			}
			reopened, err := store.Open(
				context.Background(),
				store.Options{Path: fixture.path},
			)
			if err != nil {
				t.Fatalf("store.Open(recovered): %v", err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			reopenedView, err := reopened.View(testContext(t))
			if err != nil {
				t.Fatalf("View(reopened successor): %v", err)
			}
			if reopenedView.SessionID !=
				logicalSnapshotRecoverySessionID ||
				reopenedView.Heads != view.Heads ||
				reopenedView.ProjectionStateDigest !=
					view.ProjectionStateDigest {
				t.Fatalf(
					"reopened successor differs:\ngot=%+v\nwant=%+v",
					reopenedView,
					view,
				)
			}
		})
	}
}

func TestGenerationZeroBoundaryVerifierRejectsSuccessorTampering(
	t *testing.T,
) {
	type testCase struct {
		name    string
		role    device.Role
		payload func(
			*testing.T,
			*logicalSnapshotRecoveryFixture,
		) logicalsnapshot.GenesisPayload
	}
	tests := []testCase{
		{
			name: "predecessor genesis digest",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["predecessor_genesis_digest"] =
					logicalSnapshotRecoveryEncodedDigest(0x11)
			}),
		},
		{
			name: "predecessor chain head",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["predecessor_chain_hash"] =
					logicalSnapshotRecoveryEncodedDigest(0x12)
			}),
		},
		{
			name: "predecessor result head",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["predecessor_result_hash"] =
					logicalSnapshotRecoveryEncodedDigest(0x13)
			}),
		},
		{
			name: "predecessor projection accumulator",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["predecessor_projection_accumulator"] =
					logicalSnapshotRecoveryEncodedDigest(0x14)
			}),
		},
		{
			name: "digest version",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["digest_version"] = uint64(2)
			}),
		},
		{
			name: "projection schema version",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["projection_schema_version"] = uint64(2)
			}),
		},
		{
			name: "generation does not succeed predecessor",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["recovery_generation"] = uint64(2)
			}),
		},
		{
			name: "successor reuses session",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["session_id"] = string(nodeTestSessionID)
			}),
		},
		{
			name: "unknown recovering member",
			role: device.RoleOwner,
			payload: func(
				t *testing.T,
				fixture *logicalSnapshotRecoveryFixture,
			) logicalsnapshot.GenesisPayload {
				privateKey, _, id :=
					logicalSnapshotRecoveryIdentity(t, 0x44)
				defer clear(privateKey)
				return fixture.signedPayload(
					t,
					func(body map[string]any) {
						body["recovering_device_id"] = string(id)
					},
					privateKey,
					privateKey,
				)
			},
		},
		{
			name: "revoked recovering member",
			role: device.RoleOwner,
			payload: func(
				t *testing.T,
				fixture *logicalSnapshotRecoveryFixture,
			) logicalsnapshot.GenesisPayload {
				return fixture.signedPayload(
					t,
					func(body map[string]any) {
						body["recovering_device_id"] =
							string(fixture.revokedID)
					},
					fixture.revokedPrivate,
					fixture.revokedPrivate,
				)
			},
		},
		{
			name: "recovering identity signature",
			role: device.RoleOwner,
			payload: func(
				t *testing.T,
				fixture *logicalSnapshotRecoveryFixture,
			) logicalsnapshot.GenesisPayload {
				payload := fixture.signedPayload(t, nil, nil, nil)
				tamperLogicalSnapshotRecoverySignature(
					t,
					&payload,
					"recovering_identity_signature",
				)
				return payload
			},
		},
		{
			name: "owner quorum signature uses recovery key",
			role: device.RoleOwner,
			payload: func(
				t *testing.T,
				fixture *logicalSnapshotRecoveryFixture,
			) logicalsnapshot.GenesisPayload {
				return fixture.signedPayload(
					t,
					nil,
					fixture.recoveringPrivate,
					fixture.predecessorRecoveryPrivate,
				)
			},
		},
		{
			name: "editor quorum signature uses identity key",
			role: device.RoleEditor,
			payload: func(
				t *testing.T,
				fixture *logicalSnapshotRecoveryFixture,
			) logicalsnapshot.GenesisPayload {
				return fixture.signedPayload(
					t,
					nil,
					fixture.recoveringPrivate,
					fixture.recoveringPrivate,
				)
			},
		},
		{
			name: "authorization differs from successor body",
			role: device.RoleOwner,
			payload: func(
				t *testing.T,
				fixture *logicalSnapshotRecoveryFixture,
			) logicalsnapshot.GenesisPayload {
				payload := fixture.signedPayload(t, nil, nil, nil)
				payload.RecoveryAuthorizationJSON =
					canonicalLogicalSnapshotRecoveryJSON(
						t,
						map[string]any{"different": true},
					)
				return payload
			},
		},
		{
			name: "reuses predecessor recovery key",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["recovery_public_key"] = codec.EncodeBase64URL(
					ed25519.NewKeyFromSeed(
						bytes.Repeat(
							[]byte{0x71},
							ed25519.SeedSize,
						),
					).Public().(ed25519.PublicKey),
				)
			}),
		},
		{
			name: "reuses enrolled identity key",
			role: device.RoleOwner,
			payload: func(
				t *testing.T,
				fixture *logicalSnapshotRecoveryFixture,
			) logicalsnapshot.GenesisPayload {
				return fixture.signedPayload(
					t,
					func(body map[string]any) {
						body["recovery_public_key"] =
							codec.EncodeBase64URL(
								fixture.otherIdentityPublic,
							)
					},
					nil,
					nil,
				)
			},
		},
		{
			name: "data loss asserted without rollback",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["repository_data_loss_confirmed"] = true
			}),
		},
		{
			name: "object format differs from canonical commit",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["object_format"] = string(domain.GitObjectSHA256)
			}),
		},
		{
			name: "post transform digest",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["post_transform_state_digest"] =
					logicalSnapshotRecoveryEncodedDigest(0x13)
			}),
		},
		{
			name: "unknown successor member",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				body["unexpected"] = true
			}),
		},
		{
			name: "missing successor member",
			role: device.RoleOwner,
			payload: recoveryPayloadMutation(func(body map[string]any) {
				delete(body, "object_format")
			}),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newLogicalSnapshotRecoveryFixture(
				t,
				test.role,
			)
			verifier, err := NewGenerationZeroBoundaryVerifier(
				fixture.source,
			)
			if err != nil {
				t.Fatalf(
					"NewGenerationZeroBoundaryVerifier(): %v",
					err,
				)
			}
			if _, err := verifier.VerifySuccessorBoundary(
				testContext(t),
				fixture.predecessor,
				test.payload(t, fixture),
			); !errors.Is(
				err,
				ErrLogicalSnapshotSuccessorBoundaryInvalid,
			) {
				t.Fatalf(
					"VerifySuccessorBoundary(tampered) error = %v, want %v",
					err,
					ErrLogicalSnapshotSuccessorBoundaryInvalid,
				)
			}
		})
	}
}

func TestGenerationZeroBoundaryVerifierRejectsHistoricalRecoveryKeyReuse(
	t *testing.T,
) {
	fixture := newLogicalSnapshotRecoveryFixture(t, device.RoleOwner)
	verifier, err := NewGenerationZeroBoundaryVerifier(fixture.source)
	if err != nil {
		t.Fatalf("NewGenerationZeroBoundaryVerifier(): %v", err)
	}
	first, err := verifier.VerifySuccessorBoundary(
		testContext(t),
		fixture.predecessor,
		fixture.payload,
	)
	if err != nil {
		t.Fatalf("VerifySuccessorBoundary(first): %v", err)
	}
	if _, err := fixture.source.InstallSuccessor(
		testContext(t),
		first,
	); err != nil {
		t.Fatalf("InstallSuccessor(first): %v", err)
	}
	predecessor, err := fixture.source.View(testContext(t))
	if err != nil {
		t.Fatalf("View(first successor): %v", err)
	}
	predecessorGenesisDigest, err := chain.GenesisDigest(
		predecessor.GenesisJSON,
	)
	if err != nil {
		t.Fatalf("GenesisDigest(first successor): %v", err)
	}
	second := fixture.signedPayload(
		t,
		func(body map[string]any) {
			body["session_id"] =
				string(logicalSnapshotRecoverySecondSessionID)
			body["recovery_generation"] = uint64(2)
			body["predecessor_genesis_digest"] =
				codec.EncodeBase64URL(predecessorGenesisDigest[:])
			body["predecessor_chain_index"] =
				predecessor.Heads.ChainIndex
			body["predecessor_chain_hash"] =
				codec.EncodeBase64URL(predecessor.Heads.ChainHash[:])
			body["predecessor_result_index"] =
				predecessor.Heads.ResultIndex
			body["predecessor_result_hash"] =
				codec.EncodeBase64URL(predecessor.Heads.ResultHash[:])
			body["predecessor_projection_accumulator"] =
				codec.EncodeBase64URL(
					predecessor.Heads.ProjectionAccumulator[:],
				)
			body["recovery_public_key"] = codec.EncodeBase64URL(
				fixture.predecessorRecoveryPrivate.
					Public().(ed25519.PublicKey),
			)
		},
		nil,
		nil,
	)
	if _, err := verifier.VerifySuccessorBoundary(
		testContext(t),
		predecessor,
		second,
	); !errors.Is(err, ErrLogicalSnapshotSuccessorBoundaryInvalid) {
		t.Fatalf(
			"VerifySuccessorBoundary(reused historical key) error = %v, want %v",
			err,
			ErrLogicalSnapshotSuccessorBoundaryInvalid,
		)
	}
}

type logicalSnapshotRecoveryFixture struct {
	source                     *store.Store
	path                       string
	initial                    store.InitialState
	predecessor                store.StateView
	expected                   store.ProjectionWrites
	payload                    logicalsnapshot.GenesisPayload
	body                       map[string]any
	recoveringID               domain.DeviceID
	recoveringPrivate          ed25519.PrivateKey
	predecessorRecoveryPrivate ed25519.PrivateKey
	successorRecoveryPrivate   ed25519.PrivateKey
	otherIdentityPublic        ed25519.PublicKey
	revokedID                  domain.DeviceID
	revokedPrivate             ed25519.PrivateKey
}

func newLogicalSnapshotRecoveryFixture(
	t *testing.T,
	recoveringRole device.Role,
) *logicalSnapshotRecoveryFixture {
	t.Helper()

	initial, ownerPrivate, ownerID := nodeTestInitialState(t)
	editorPrivate, editorPublic, editorID :=
		logicalSnapshotRecoveryIdentity(t, 0x32)
	revokedPrivate, revokedPublic, revokedID :=
		logicalSnapshotRecoveryIdentity(t, 0x33)
	predecessorRecoveryPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x71}, ed25519.SeedSize),
	)
	successorRecoveryPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x72}, ed25519.SeedSize),
	)
	t.Cleanup(func() {
		clear(ownerPrivate)
		clear(editorPrivate)
		clear(revokedPrivate)
		clear(predecessorRecoveryPrivate)
		clear(successorRecoveryPrivate)
	})

	initial.Projections.Devices[0].EntityVersion = 7
	initial.Projections.Devices = append(
		initial.Projections.Devices,
		device.Device{
			ID:                editorID,
			Role:              device.RoleEditor,
			IdentityPublicKey: editorPublic,
			DaemonVersion:     "0.2.0",
			MaxApplyLevel:     1,
			Status:            device.StatusActive,
			EntityVersion:     5,
		},
		device.Device{
			ID:                revokedID,
			Role:              device.RoleEditor,
			IdentityPublicKey: revokedPublic,
			DaemonVersion:     "0.1.0",
			MaxApplyLevel:     1,
			Status:            device.StatusRevoked,
			EntityVersion:     4,
		},
	)
	initial.Projections.AuditCounters[0].AcceptedCount = 9
	initial.Projections.AuditCounters = append(
		initial.Projections.AuditCounters,
		auditcounter.Counter{
			DeviceID:      editorID,
			AcceptedCount: 7,
		},
		auditcounter.Counter{
			DeviceID:      revokedID,
			AcceptedCount: 5,
		},
	)
	initial.Projections.OriginScopes = []store.OriginScopeRow{{
		DeviceID:     editorID,
		ScopeKind:    store.OriginScopeKindAgent,
		ScopeID:      logicalSnapshotRecoveryAgentID,
		LastSequence: 3,
	}}
	initial.Projections.AgentSessions = []agentsession.Session{{
		ID:            logicalSnapshotRecoveryAgentID,
		DeviceID:      editorID,
		ClientKind:    agentsession.ClientKindCodex,
		State:         agentsession.StateWorking,
		WorkingRootID: logicalSnapshotRecoveryRootID,
		EntityVersion: 4,
	}}
	initial.Projections.Tasks = []task.Task{{
		ID:                  nodeTestTaskID1,
		Title:               "claimed before recovery",
		Body:                "must be released by the boundary",
		State:               task.StateClaimed,
		Priority:            task.PriorityNormal,
		OwnerDeviceID:       editorID,
		OwnerAgentSessionID: logicalSnapshotRecoveryAgentID,
		EntityVersion:       6,
		CreatedAt:           nodeTestTimestamp1,
		UpdatedAt:           nodeTestTimestamp2,
	}}
	activeLease, err := lease.New(
		lease.Fields{
			ID:                   logicalSnapshotRecoveryLeaseID,
			HolderDeviceID:       editorID,
			HolderAgentSessionID: logicalSnapshotRecoveryAgentID,
			Scope:                lease.ScopeTask,
			TaskID:               nodeTestTaskID1,
			TTLSeconds:           300,
			Status:               lease.StatusActive,
			EntityVersion:        8,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("lease.New(predecessor): %v", err)
	}
	initial.Projections.Leases = []lease.Lease{activeLease}
	revision, err := plan.NewRevision(
		logicalSnapshotRecoveryPlanID,
		"",
		"Recovery plan",
		"Retained immutable plan body",
		[]domain.UUIDv7{nodeTestTaskID1},
		ownerID,
		nodeTestTimestamp1,
	)
	if err != nil {
		t.Fatalf("plan.NewRevision(): %v", err)
	}
	initial.Projections.PlanRevisions = []plan.Revision{revision}
	initial.Projections.PlanCurrent[0].RevisionID =
		logicalSnapshotRecoveryPlanID
	initial.Projections.PlanCurrent[0].EntityVersion = 6
	record, err := memory.NewRecord(
		logicalSnapshotRecoveryMemoryID,
		memory.ScopeTask,
		nodeTestTaskID1,
		"decision",
		"Retained immutable memory",
		"",
		nodeTestTimestamp1,
	)
	if err != nil {
		t.Fatalf("memory.NewRecord(): %v", err)
	}
	initial.Projections.MemoryRecords = []memory.Record{record}
	initial.Projections.CanonicalRefs[0].EntityVersion = 5
	initial.Projections.SessionPolicy[0].EntityVersion = 4

	path := filepath.Join(t.TempDir(), "recovery", "state.db")
	source, err := store.Open(
		context.Background(),
		store.Options{Path: path},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	if _, err := source.Initialize(
		context.Background(),
		initial,
	); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	predecessor, err := source.View(testContext(t))
	if err != nil {
		t.Fatalf("View(predecessor): %v", err)
	}
	if _, _, err := decodeReducerStateView(predecessor); err != nil {
		t.Fatalf("decodeReducerStateView(predecessor): %v", err)
	}

	recoveringID := ownerID
	recoveringPrivate := ownerPrivate
	otherIdentityPublic := editorPublic
	if recoveringRole == device.RoleEditor {
		recoveringID = editorID
		recoveringPrivate = editorPrivate
		otherIdentityPublic = bytes.Clone(
			ownerPrivate.Public().(ed25519.PublicKey),
		)
	}
	expected := expectedLogicalSnapshotRecoveryWrites(
		t,
		initial.Projections,
		recoveringID,
	)
	_, transformDigest := logicalSnapshotRecoveryProjectionState(
		t,
		expected,
	)
	predecessorGenesisDigest, err := chain.GenesisDigest(
		predecessor.GenesisJSON,
	)
	if err != nil {
		t.Fatalf("chain.GenesisDigest(predecessor): %v", err)
	}
	body := map[string]any{
		"canonical_commit": string(
			initial.Projections.CanonicalRefs[0].CommitOID,
		),
		"digest_version": uint64(1),
		"object_format": string(
			initial.Projections.CanonicalRefs[0].
				CommitOID.ObjectFormat(),
		),
		"post_transform_state_digest": codec.EncodeBase64URL(
			transformDigest[:],
		),
		"predecessor_chain_hash": codec.EncodeBase64URL(
			predecessor.Heads.ChainHash[:],
		),
		"predecessor_chain_index": predecessor.Heads.ChainIndex,
		"predecessor_genesis_digest": codec.EncodeBase64URL(
			predecessorGenesisDigest[:],
		),
		"predecessor_projection_accumulator": codec.EncodeBase64URL(
			predecessor.Heads.ProjectionAccumulator[:],
		),
		"predecessor_result_hash": codec.EncodeBase64URL(
			predecessor.Heads.ResultHash[:],
		),
		"predecessor_result_index":        predecessor.Heads.ResultIndex,
		"projection_schema_version":       uint64(1),
		"quorum_recovery_signer_kind":     recoveryIdentitySignerKind,
		"recovering_device_id":            string(recoveringID),
		"recovering_identity_signer_kind": recoveryIdentitySignerKind,
		"recovery_generation":             uint64(1),
		"recovery_public_key": codec.EncodeBase64URL(
			successorRecoveryPrivate.Public().(ed25519.PublicKey),
		),
		"repository_data_loss_confirmed": false,
		"session_id":                     string(logicalSnapshotRecoverySessionID),
		"workspace_id":                   string(nodeTestWorkspaceID),
	}
	if recoveringRole == device.RoleEditor {
		body["quorum_recovery_signer_kind"] = recoveryKeySignerKind
	}
	fixture := &logicalSnapshotRecoveryFixture{
		source:                     source,
		path:                       path,
		initial:                    initial,
		predecessor:                predecessor,
		expected:                   expected,
		body:                       body,
		recoveringID:               recoveringID,
		recoveringPrivate:          recoveringPrivate,
		predecessorRecoveryPrivate: predecessorRecoveryPrivate,
		successorRecoveryPrivate:   successorRecoveryPrivate,
		otherIdentityPublic:        bytes.Clone(otherIdentityPublic),
		revokedID:                  revokedID,
		revokedPrivate:             revokedPrivate,
	}
	fixture.payload = fixture.signedPayload(t, nil, nil, nil)
	return fixture
}

func expectedLogicalSnapshotRecoveryWrites(
	t *testing.T,
	predecessor store.ProjectionWrites,
	recoveringID domain.DeviceID,
) store.ProjectionWrites {
	t.Helper()

	expected := predecessor
	expected.OriginScopes = nil
	expected.AuditCounters = make(
		[]auditcounter.Counter,
		len(predecessor.Devices),
	)
	expected.Devices = make([]device.Device, len(predecessor.Devices))
	for index, current := range predecessor.Devices {
		expected.AuditCounters[index] = auditcounter.Counter{
			DeviceID: current.ID,
		}
		next := current
		next.IdentityPublicKey = bytes.Clone(current.IdentityPublicKey)
		next.EntityVersion = 1
		switch {
		case current.ID == recoveringID:
			next.Role = device.RoleOwner
			next.Status = device.StatusActive
		case current.Status != device.StatusRevoked:
			next.Status = device.StatusRequiresReadmission
		}
		expected.Devices[index] = next
	}

	expected.Tasks = append([]task.Task(nil), predecessor.Tasks...)
	for index := range expected.Tasks {
		next := expected.Tasks[index]
		if next.OwnerDeviceID != "" {
			next.State = task.StateReady
			next.StateReason = nil
			next.OwnerDeviceID = ""
			next.OwnerAgentSessionID = ""
			next.IntendedDeviceID = ""
			next.LastReleaseReason = task.ReleaseRecovery
		}
		next.EntityVersion = 1
		expected.Tasks[index] = next
	}
	expected.PlanCurrent = append(
		[]plan.Current(nil),
		predecessor.PlanCurrent...,
	)
	expected.PlanCurrent[0].SessionID =
		logicalSnapshotRecoverySessionID
	expected.PlanCurrent[0].EntityVersion = 1

	expected.Leases = make([]lease.Lease, len(predecessor.Leases))
	for index, current := range predecessor.Leases {
		status := current.Status
		reason := current.ReleaseReason
		if status == lease.StatusActive {
			status = lease.StatusReleased
			reason = lease.ReleaseRecovery
		}
		patterns := current.PathPatterns()
		rawPatterns := make([]string, len(patterns))
		for patternIndex, pattern := range patterns {
			rawPatterns[patternIndex] = pattern.String()
		}
		next, err := lease.New(
			lease.Fields{
				ID:                   current.ID,
				HolderDeviceID:       current.HolderDeviceID,
				HolderAgentSessionID: current.HolderAgentSessionID,
				Scope:                current.Scope,
				TaskID:               current.TaskID,
				TTLSeconds:           current.TTLSeconds,
				Status:               status,
				ReleaseReason:        reason,
				EntityVersion:        1,
			},
			rawPatterns,
		)
		if err != nil {
			t.Fatalf("lease.New(expected successor): %v", err)
		}
		expected.Leases[index] = next
	}

	target, err := voterset.New(
		logicalSnapshotRecoverySessionID,
		[]domain.DeviceID{recoveringID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(expected successor): %v", err)
	}
	expected.VoterSet = []voterset.Set{target}
	expected.CredentialAuthority = []store.CredentialAuthorityRow{{
		SessionID:        logicalSnapshotRecoverySessionID,
		VoterDeviceIDs:   []domain.DeviceID{recoveringID},
		VoterSetVersion:  1,
		ActivationSource: credentialauthority.ActivationGenesis,
	}}

	expected.AgentSessions = append(
		[]agentsession.Session(nil),
		predecessor.AgentSessions...,
	)
	for index := range expected.AgentSessions {
		next := expected.AgentSessions[index]
		next.State = agentsession.StateEnded
		next.ResumeState = agentsession.StateAbsent
		next.EndReason = agentsession.EndReasonRecovery
		next.EntityVersion = 1
		expected.AgentSessions[index] = next
	}
	expected.CanonicalRefs = append(
		[]publication.CanonicalRef(nil),
		predecessor.CanonicalRefs...,
	)
	expected.CanonicalRefs[0].EntityVersion = 1
	expected.SessionPolicy = append(
		[]policy.Policy(nil),
		predecessor.SessionPolicy...,
	)
	expected.SessionPolicy[0].SessionID =
		logicalSnapshotRecoverySessionID
	expected.SessionPolicy[0].EntityVersion = 1
	return expected
}

func (fixture *logicalSnapshotRecoveryFixture) signedPayload(
	t *testing.T,
	mutate func(map[string]any),
	identitySigner ed25519.PrivateKey,
	quorumSigner ed25519.PrivateKey,
) logicalsnapshot.GenesisPayload {
	t.Helper()

	body := make(map[string]any, len(fixture.body))
	for name, value := range fixture.body {
		body[name] = value
	}
	if mutate != nil {
		mutate(body)
	}
	if identitySigner == nil {
		identitySigner = fixture.recoveringPrivate
	}
	if quorumSigner == nil {
		quorumSigner = fixture.recoveringPrivate
		if body["quorum_recovery_signer_kind"] ==
			recoveryKeySignerKind {
			quorumSigner = fixture.predecessorRecoveryPrivate
		}
	}
	authorization := canonicalLogicalSnapshotRecoveryJSON(t, body)
	identitySignature, err := codecommcrypto.SignEd25519(
		identitySigner,
		codec.SignatureGenesis,
		authorization,
	)
	if err != nil {
		t.Fatalf("SignEd25519(identity): %v", err)
	}
	quorumSignature, err := codecommcrypto.SignEd25519(
		quorumSigner,
		codec.SignatureQuorumRecovery,
		authorization,
	)
	if err != nil {
		t.Fatalf("SignEd25519(quorum recovery): %v", err)
	}
	complete := make(map[string]any, len(body)+2)
	for name, value := range body {
		complete[name] = value
	}
	complete["recovering_identity_signature"] =
		codec.EncodeBase64URL(identitySignature)
	complete["quorum_recovery_signature"] =
		codec.EncodeBase64URL(quorumSignature)

	encodedDigest, ok :=
		body["post_transform_state_digest"].(string)
	if !ok {
		t.Fatal("successor body lacks post-transform digest")
	}
	digestBytes, err := codec.DecodeBase64URLExact(
		encodedDigest,
		len(chain.Digest{}),
	)
	if err != nil {
		t.Fatalf("DecodeBase64URLExact(transform digest): %v", err)
	}
	var transformDigest chain.Digest
	copy(transformDigest[:], digestBytes)
	return logicalsnapshot.GenesisPayload{
		GenesisJSON: canonicalLogicalSnapshotRecoveryJSON(
			t,
			complete,
		),
		RecoveryAuthorizationJSON: authorization,
		BoundaryTransformDigest:   transformDigest,
	}
}

func recoveryPayloadMutation(
	mutate func(map[string]any),
) func(
	*testing.T,
	*logicalSnapshotRecoveryFixture,
) logicalsnapshot.GenesisPayload {
	return func(
		t *testing.T,
		fixture *logicalSnapshotRecoveryFixture,
	) logicalsnapshot.GenesisPayload {
		return fixture.signedPayload(t, mutate, nil, nil)
	}
}

func logicalSnapshotRecoveryProjectionState(
	t *testing.T,
	writes store.ProjectionWrites,
) ([]chain.LogicalRow, chain.Digest) {
	t.Helper()
	versions := chain.Versions{
		Digest:           1,
		ProjectionSchema: 1,
	}
	scratch, err := store.NewProjectionScratch(nil, versions)
	if err != nil {
		t.Fatalf("NewProjectionScratch(): %v", err)
	}
	if _, err := scratch.Apply(writes); err != nil {
		t.Fatalf("ProjectionScratch.Apply(): %v", err)
	}
	digest, err := scratch.StateDigest(versions)
	if err != nil {
		t.Fatalf("ProjectionScratch.StateDigest(): %v", err)
	}
	return scratch.Rows(), digest
}

func assertLogicalSnapshotRecoveryTransform(
	t *testing.T,
	snapshot reducer.Snapshot,
	fixture *logicalSnapshotRecoveryFixture,
) {
	t.Helper()
	if len(snapshot.OriginScopes) != 0 {
		t.Fatalf(
			"successor retained %d origin scopes",
			len(snapshot.OriginScopes),
		)
	}
	for id, counter := range snapshot.AuditCounters {
		if counter.CredentialEpoch != 0 ||
			counter.AcceptedCount != 0 {
			t.Fatalf("audit counter %s was not reset: %+v", id, counter)
		}
	}
	recovering := snapshot.Devices[fixture.recoveringID]
	if recovering.Role != device.RoleOwner ||
		recovering.Status != device.StatusActive ||
		recovering.EntityVersion != 1 {
		t.Fatalf("recovering member = %+v", recovering)
	}
	revoked := snapshot.Devices[fixture.revokedID]
	if revoked.Status != device.StatusRevoked ||
		revoked.EntityVersion != 1 {
		t.Fatalf("revoked member = %+v", revoked)
	}
	session := snapshot.AgentSessions[logicalSnapshotRecoveryAgentID]
	if session.State != agentsession.StateEnded ||
		session.EndReason != agentsession.EndReasonRecovery ||
		session.EntityVersion != 1 {
		t.Fatalf("recovered agent session = %+v", session)
	}
	releasedTask := snapshot.Tasks[nodeTestTaskID1]
	if releasedTask.State != task.StateReady ||
		releasedTask.OwnerDeviceID != "" ||
		releasedTask.OwnerAgentSessionID != "" ||
		releasedTask.LastReleaseReason != task.ReleaseRecovery ||
		releasedTask.EntityVersion != 1 {
		t.Fatalf("recovered task = %+v", releasedTask)
	}
	releasedLease := snapshot.Leases[logicalSnapshotRecoveryLeaseID]
	if releasedLease.Status != lease.StatusReleased ||
		releasedLease.ReleaseReason != lease.ReleaseRecovery ||
		releasedLease.EntityVersion != 1 {
		t.Fatalf("recovered lease = %+v", releasedLease)
	}
	if snapshot.PlanCurrent.SessionID !=
		logicalSnapshotRecoverySessionID ||
		snapshot.PlanCurrent.RevisionID !=
			logicalSnapshotRecoveryPlanID ||
		snapshot.PlanCurrent.EntityVersion != 1 {
		t.Fatalf("recovered current plan = %+v", snapshot.PlanCurrent)
	}
	if _, exists :=
		snapshot.PlanRevisions[logicalSnapshotRecoveryPlanID]; !exists {
		t.Fatal("immutable plan revision was not retained")
	}
	if _, exists :=
		snapshot.MemoryRecords[logicalSnapshotRecoveryMemoryID]; !exists {
		t.Fatal("immutable memory record was not retained")
	}
	if snapshot.VoterSet.VoterSetVersion != 1 ||
		!reflect.DeepEqual(
			snapshot.VoterSet.VoterDeviceIDs(),
			[]domain.DeviceID{fixture.recoveringID},
		) ||
		snapshot.CredentialAuthority.VoterSetVersion != 1 ||
		!reflect.DeepEqual(
			snapshot.CredentialAuthority.VoterDeviceIDs,
			[]domain.DeviceID{fixture.recoveringID},
		) {
		t.Fatalf(
			"recovered authority = (%+v, %+v)",
			snapshot.VoterSet,
			snapshot.CredentialAuthority,
		)
	}
}

func logicalSnapshotRecoveryIdentity(
	t *testing.T,
	seed byte,
) (ed25519.PrivateKey, ed25519.PublicKey, domain.DeviceID) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
	publicKey := bytes.Clone(
		privateKey.Public().(ed25519.PublicKey),
	)
	id, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	return privateKey, publicKey, id
}

func tamperLogicalSnapshotRecoverySignature(
	t *testing.T,
	payload *logicalsnapshot.GenesisPayload,
	name string,
) {
	t.Helper()
	var members map[string]json.RawMessage
	if err := decodeStrictJSON(payload.GenesisJSON, &members); err != nil {
		t.Fatalf("decode successor genesis: %v", err)
	}
	var encoded string
	if err := decodeStrictJSON(members[name], &encoded); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	signature, err := codec.DecodeBase64URLExact(
		encoded,
		ed25519.SignatureSize,
	)
	if err != nil {
		t.Fatalf("decode %s bytes: %v", name, err)
	}
	signature[0] ^= 0xff
	members[name], err = json.Marshal(codec.EncodeBase64URL(signature))
	if err != nil {
		t.Fatalf("json.Marshal(%s): %v", name, err)
	}
	payload.GenesisJSON = canonicalLogicalSnapshotRecoveryJSON(
		t,
		members,
	)
}

func canonicalLogicalSnapshotRecoveryJSON(
	t *testing.T,
	value any,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(): %v", err)
	}
	return canonical
}

func logicalSnapshotRecoveryEncodedDigest(fill byte) string {
	return codec.EncodeBase64URL(
		bytes.Repeat([]byte{fill}, len(chain.Digest{})),
	)
}
