package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
)

const (
	daemonReadmissionIntegrationChildMarker = "CODECOMM_TEST_DAEMON_READMISSION_CHILD"
	daemonReadmissionPredecessorSessionID   = domain.UUIDv7(
		"018f47de-89ab-7def-8123-9123456789ab",
	)
)

type daemonReadmissionFixture struct {
	initial        store.InitialState
	predecessor    store.StateView
	successorState store.SuccessorState
	successor      store.StateView
}

func TestDaemonProductionReadmissionComposition(t *testing.T) {
	if os.Getenv(daemonReadmissionIntegrationChildMarker) != "1" {
		runDaemonReadmissionIntegrationChild(t)
		return
	}
	registerDaemonIntegrationChildResult(t)
	runDaemonProductionReadmissionComposition(t)
}

func runDaemonProductionReadmissionComposition(t *testing.T) {
	t.Helper()

	selectedAddress, listeners := reserveDaemonMeshIntegrationListeners(t, 2)
	root := t.TempDir()
	credentialClock := newDaemonMeshIntegrationCredentialClock(
		time.Now().UTC().Truncate(time.Second),
	)
	owners := newDaemonMeshIntegrationNodes(
		t,
		root,
		selectedAddress,
		listeners[:1],
		credentialClock.Now,
	)
	owner := owners[0]
	retained := newDaemonMeshIntegrationRetainedNode(
		t,
		root,
		selectedAddress,
		listeners[1],
		credentialClock.Now,
	)
	t.Cleanup(func() {
		cleanupDaemonMeshIntegrationNodes(t, owner, retained)
		clear(owner.privateKey)
		clear(retained.privateKey)
	})

	fixture := newDaemonReadmissionFixture(t, owner, retained)
	initializeDaemonMeshIntegrationStore(
		t,
		retained.statePath,
		fixture.initial,
	)
	assertDaemonReadmissionPredecessor(
		t,
		retained.statePath,
		fixture.predecessor,
	)
	installDaemonReadmissionSuccessor(t, owner.statePath, fixture)
	seedDaemonMeshIntegrationRaft(
		t,
		owner.consensusDir,
		owner.deviceID,
		daemonMeshIntegrationBootstrap(owners),
	)

	owner.start(t, owners)
	waitForDaemonMeshIntegrationCluster(
		t,
		owners,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				[]domain.DeviceID{owner.deviceID},
			) &&
				daemonMeshIntegrationTarget(
					statuses,
					1,
					[]domain.DeviceID{owner.deviceID},
				) &&
				statuses[0].Session.SessionID ==
					string(daemonTestSessionID) &&
				statuses[0].Session.WorkspaceID ==
					string(daemonTestWorkspaceID) &&
				statuses[0].Session.RecoveryGeneration == 1 &&
				daemonMeshIntegrationMemberStatus(
					statuses,
					owner.deviceID,
					device.StatusActive,
					1,
				) &&
				daemonMeshIntegrationMemberStatus(
					statuses,
					retained.deviceID,
					device.StatusRequiresReadmission,
					1,
				)
		},
	)

	operator := dialDaemonMeshIntegrationOperator(t, owner.localEndpoint)
	expectedVersion := uint64(1)
	subject := retained.deviceID
	joined := completeDaemonMeshPairingJoin(
		t,
		owner,
		operator,
		selectedAddress,
		credentialClock.Now,
		daemonMeshPairingJoinOptions{
			request: pairingservice.CreateInviteRequest{
				Mode:                   pairing.ModeReadmission,
				SubjectDeviceID:        &subject,
				ExpectedEntityVersion:  &expectedVersion,
				Role:                   device.RoleEditor,
				InitialCredentialEpoch: 1,
			},
			credentials: retained.credentials,
			statePath:   retained.statePath,
		},
	)
	if err := operator.Close(); err != nil {
		t.Fatalf("close readmission operator client: %v", err)
	}
	assertDaemonReadmissionReview(t, retained, joined, expectedVersion)

	waitForDaemonMeshIntegrationCluster(
		t,
		owners,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				[]domain.DeviceID{owner.deviceID},
			) &&
				daemonMeshIntegrationTarget(
					statuses,
					1,
					[]domain.DeviceID{owner.deviceID},
				) &&
				daemonMeshIntegrationMemberStatus(
					statuses,
					retained.deviceID,
					device.StatusActive,
					2,
				)
		},
	)
	assertDaemonReadmissionDurableState(
		t,
		retained,
		owner,
		fixture.predecessor,
		credentialClock.Now(),
	)
	if _, err := readDaemonMeshIntegrationStatus(
		retained.localEndpoint,
	); err == nil {
		t.Fatal("readmitted IPC was available before daemon startup")
	}
	if _, err := os.Stat(retained.consensusDir); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("readmitted device had Raft state before startup: %v", err)
	}

	retained.start(t, owners)
	waitForDaemonReadmissionIPC(t, retained, owner.deviceID)
	if _, err := os.Stat(retained.consensusDir); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("settled readmission daemon created Raft state: %v", err)
	}
	stopDaemonMeshIntegrationNodes(t, retained, owner)

	assertDaemonReadmissionDurableState(
		t,
		retained,
		owner,
		fixture.predecessor,
		credentialClock.Now(),
	)
	assertDaemonReadmissionReopens(t, retained.statePath)
}

func newDaemonReadmissionFixture(
	t *testing.T,
	owner *daemonMeshIntegrationNode,
	retained *daemonMeshIntegrationNode,
) daemonReadmissionFixture {
	t.Helper()
	if owner == nil || retained == nil || owner.deviceID == retained.deviceID {
		t.Fatal("invalid readmission fixture devices")
	}

	initial, unusedPrivate, _ := daemonTestInitialState(t)
	clear(unusedPrivate)
	recoveryPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x71}, ed25519.SeedSize),
	)
	defer clear(recoveryPrivate)
	initial.SessionID = daemonReadmissionPredecessorSessionID
	initial.GenesisJSON = daemonReadmissionCanonicalJSON(t, map[string]any{
		"recovery_generation": uint64(0),
		"recovery_public_key": codec.EncodeBase64URL(
			recoveryPrivate.Public().(ed25519.PublicKey),
		),
		"session_id":   daemonReadmissionPredecessorSessionID,
		"workspace_id": daemonTestWorkspaceID,
	})
	ownerMember := daemonReadmissionMember(
		owner,
		device.RoleOwner,
		device.StatusActive,
		1,
	)
	retainedMember := daemonReadmissionMember(
		retained,
		device.RoleEditor,
		device.StatusActive,
		1,
	)
	initial.Projections.Devices = []device.Device{
		ownerMember,
		retainedMember,
	}
	sort.Slice(initial.Projections.Devices, func(left, right int) bool {
		return initial.Projections.Devices[left].ID <
			initial.Projections.Devices[right].ID
	})
	initial.Projections.AuditCounters = []auditcounter.Counter{
		{DeviceID: owner.deviceID},
		{DeviceID: retained.deviceID},
	}
	sort.Slice(
		initial.Projections.AuditCounters,
		func(left, right int) bool {
			return initial.Projections.AuditCounters[left].DeviceID <
				initial.Projections.AuditCounters[right].DeviceID
		},
	)
	initial.Projections.PlanCurrent =
		append(initial.Projections.PlanCurrent[:0:0], initial.Projections.PlanCurrent...)
	initial.Projections.PlanCurrent[0].SessionID =
		daemonReadmissionPredecessorSessionID
	initial.Projections.PlanCurrent[0].EntityVersion = 1
	target, err := voterset.New(
		daemonReadmissionPredecessorSessionID,
		[]domain.DeviceID{owner.deviceID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(predecessor): %v", err)
	}
	initial.Projections.VoterSet = []voterset.Set{target}
	initial.Projections.CredentialAuthority =
		[]store.CredentialAuthorityRow{{
			SessionID:        daemonReadmissionPredecessorSessionID,
			VoterDeviceIDs:   []domain.DeviceID{owner.deviceID},
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		}}
	initial.Projections.SessionPolicy =
		append(initial.Projections.SessionPolicy[:0:0], initial.Projections.SessionPolicy...)
	initial.Projections.SessionPolicy[0].SessionID =
		daemonReadmissionPredecessorSessionID
	initial.Projections.SessionPolicy[0].EntityVersion = 1

	sourcePath := filepath.Join(t.TempDir(), "verified-recovery-source", "state.db")
	source, err := store.Open(
		context.Background(),
		store.Options{Path: sourcePath},
	)
	if err != nil {
		t.Fatalf("open recovery source: %v", err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Fatalf("close recovery source: %v", err)
		}
	}()
	if _, err := source.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("initialize recovery source: %v", err)
	}
	predecessor, err := source.View(context.Background())
	if err != nil {
		t.Fatalf("read recovery predecessor: %v", err)
	}

	payload := daemonReadmissionSuccessorPayload(
		t,
		initial,
		predecessor,
		owner,
		retained,
	)
	verifier, err := consensus.NewGenerationZeroBoundaryVerifier(source)
	if err != nil {
		t.Fatalf("NewGenerationZeroBoundaryVerifier(): %v", err)
	}
	verifiedInitial, err := verifier.VerifyInitialBoundary(
		context.Background(),
		logicalsnapshot.GenesisPayload{
			GenesisJSON: initial.GenesisJSON,
			BoundaryTransformDigest: chain.Digest(
				predecessor.ProjectionStateDigest,
			),
		},
	)
	if err != nil {
		t.Fatalf("VerifyInitialBoundary(): %v", err)
	}
	if verifiedInitial.SessionID != initial.SessionID ||
		verifiedInitial.WorkspaceID != initial.WorkspaceID ||
		!bytes.Equal(verifiedInitial.GenesisJSON, initial.GenesisJSON) {
		t.Fatalf("verified initial boundary differs: %+v", verifiedInitial)
	}
	successorState, err := verifier.VerifySuccessorBoundary(
		context.Background(),
		predecessor,
		payload,
	)
	if err != nil {
		t.Fatalf("VerifySuccessorBoundary(): %v", err)
	}
	if _, err := source.InstallSuccessor(
		context.Background(),
		successorState,
	); err != nil {
		t.Fatalf("InstallSuccessor(verified): %v", err)
	}
	successor, err := source.View(context.Background())
	if err != nil {
		t.Fatalf("read verified successor: %v", err)
	}
	if successor.SessionID != daemonTestSessionID ||
		successor.WorkspaceID != daemonTestWorkspaceID ||
		successor.RecoveryGeneration != 1 ||
		chain.Digest(successor.ProjectionStateDigest) !=
			payload.BoundaryTransformDigest {
		t.Fatalf("verified successor boundary = %+v", successor)
	}
	return daemonReadmissionFixture{
		initial:        initial,
		predecessor:    predecessor,
		successorState: successorState,
		successor:      successor,
	}
}

func daemonReadmissionSuccessorPayload(
	t *testing.T,
	initial store.InitialState,
	predecessor store.StateView,
	owner *daemonMeshIntegrationNode,
	retained *daemonMeshIntegrationNode,
) logicalsnapshot.GenesisPayload {
	t.Helper()

	expected := initial.Projections
	expected.Devices = []device.Device{
		daemonReadmissionMember(
			owner,
			device.RoleOwner,
			device.StatusActive,
			1,
		),
		daemonReadmissionMember(
			retained,
			device.RoleEditor,
			device.StatusRequiresReadmission,
			1,
		),
	}
	sort.Slice(expected.Devices, func(left, right int) bool {
		return expected.Devices[left].ID < expected.Devices[right].ID
	})
	expected.AuditCounters = []auditcounter.Counter{
		{DeviceID: owner.deviceID},
		{DeviceID: retained.deviceID},
	}
	sort.Slice(expected.AuditCounters, func(left, right int) bool {
		return expected.AuditCounters[left].DeviceID <
			expected.AuditCounters[right].DeviceID
	})
	expected.PlanCurrent =
		append(expected.PlanCurrent[:0:0], expected.PlanCurrent...)
	expected.PlanCurrent[0].SessionID = daemonTestSessionID
	expected.PlanCurrent[0].EntityVersion = 1
	target, err := voterset.New(
		daemonTestSessionID,
		[]domain.DeviceID{owner.deviceID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(successor): %v", err)
	}
	expected.VoterSet = []voterset.Set{target}
	expected.CredentialAuthority = []store.CredentialAuthorityRow{{
		SessionID:        daemonTestSessionID,
		VoterDeviceIDs:   []domain.DeviceID{owner.deviceID},
		VoterSetVersion:  1,
		ActivationSource: credentialauthority.ActivationGenesis,
	}}
	expected.CanonicalRefs =
		append(expected.CanonicalRefs[:0:0], expected.CanonicalRefs...)
	expected.CanonicalRefs[0].EntityVersion = 1
	expected.SessionPolicy =
		append(expected.SessionPolicy[:0:0], expected.SessionPolicy...)
	expected.SessionPolicy[0].SessionID = daemonTestSessionID
	expected.SessionPolicy[0].EntityVersion = 1

	versions := chain.Versions{Digest: 1, ProjectionSchema: 1}
	scratch, err := store.NewProjectionScratch(nil, versions)
	if err != nil {
		t.Fatalf("NewProjectionScratch(): %v", err)
	}
	if _, err := scratch.Apply(expected); err != nil {
		t.Fatalf("ProjectionScratch.Apply(): %v", err)
	}
	transformDigest, err := scratch.StateDigest(versions)
	if err != nil {
		t.Fatalf("ProjectionScratch.StateDigest(): %v", err)
	}
	predecessorGenesisDigest, err := chain.GenesisDigest(
		predecessor.GenesisJSON,
	)
	if err != nil {
		t.Fatalf("chain.GenesisDigest(predecessor): %v", err)
	}
	successorRecoveryPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x72}, ed25519.SeedSize),
	)
	defer clear(successorRecoveryPrivate)
	canonical := expected.CanonicalRefs[0]
	body := map[string]any{
		"canonical_commit": string(canonical.CommitOID),
		"digest_version":   uint64(1),
		"object_format":    string(canonical.CommitOID.ObjectFormat()),
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
		"quorum_recovery_signer_kind":     "identity",
		"recovering_device_id":            string(owner.deviceID),
		"recovering_identity_signer_kind": "identity",
		"recovery_generation":             uint64(1),
		"recovery_public_key": codec.EncodeBase64URL(
			successorRecoveryPrivate.Public().(ed25519.PublicKey),
		),
		"repository_data_loss_confirmed": false,
		"session_id":                     string(daemonTestSessionID),
		"workspace_id":                   string(daemonTestWorkspaceID),
	}
	authorization := daemonReadmissionCanonicalJSON(t, body)
	identitySignature, err := codecommcrypto.SignEd25519(
		owner.privateKey,
		codec.SignatureGenesis,
		authorization,
	)
	if err != nil {
		t.Fatalf("sign recovering identity: %v", err)
	}
	quorumSignature, err := codecommcrypto.SignEd25519(
		owner.privateKey,
		codec.SignatureQuorumRecovery,
		authorization,
	)
	if err != nil {
		t.Fatalf("sign quorum recovery: %v", err)
	}
	complete := make(map[string]any, len(body)+2)
	for name, value := range body {
		complete[name] = value
	}
	complete["recovering_identity_signature"] =
		codec.EncodeBase64URL(identitySignature)
	complete["quorum_recovery_signature"] =
		codec.EncodeBase64URL(quorumSignature)
	return logicalsnapshot.GenesisPayload{
		GenesisJSON: daemonReadmissionCanonicalJSON(t, complete),
		RecoveryAuthorizationJSON: bytes.Clone(
			authorization,
		),
		BoundaryTransformDigest: transformDigest,
	}
}

func installDaemonReadmissionSuccessor(
	t *testing.T,
	path string,
	fixture daemonReadmissionFixture,
) {
	t.Helper()
	initializeDaemonMeshIntegrationStore(t, path, fixture.initial)
	database, err := store.Open(
		context.Background(),
		store.Options{Path: path},
	)
	if err != nil {
		t.Fatalf("open owner predecessor: %v", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			t.Fatalf("close owner successor: %v", err)
		}
	}()
	predecessor, err := database.View(context.Background())
	if err != nil {
		t.Fatalf("read owner predecessor: %v", err)
	}
	if predecessor.SessionID != fixture.predecessor.SessionID ||
		predecessor.WorkspaceID != fixture.predecessor.WorkspaceID ||
		predecessor.Heads != fixture.predecessor.Heads ||
		predecessor.ProjectionStateDigest !=
			fixture.predecessor.ProjectionStateDigest {
		t.Fatalf("owner predecessor differs: %+v", predecessor)
	}
	if _, err := database.InstallSuccessor(
		context.Background(),
		fixture.successorState,
	); err != nil {
		t.Fatalf("install proven owner successor: %v", err)
	}
	successor, err := database.View(context.Background())
	if err != nil {
		t.Fatalf("read installed owner successor: %v", err)
	}
	if successor.SessionID != fixture.successor.SessionID ||
		successor.WorkspaceID != fixture.successor.WorkspaceID ||
		successor.RecoveryGeneration != fixture.successor.RecoveryGeneration ||
		successor.Heads != fixture.successor.Heads ||
		successor.ProjectionStateDigest !=
			fixture.successor.ProjectionStateDigest ||
		!reflect.DeepEqual(
			successor.ProjectionRows,
			fixture.successor.ProjectionRows,
		) {
		t.Fatalf(
			"installed owner successor differs:\ngot=%+v\nwant=%+v",
			successor,
			fixture.successor,
		)
	}
}

func daemonReadmissionMember(
	node *daemonMeshIntegrationNode,
	role device.Role,
	status device.Status,
	entityVersion uint64,
) device.Device {
	return device.Device{
		ID:                node.deviceID,
		Role:              role,
		IdentityPublicKey: bytes.Clone(node.privateKey.Public().(ed25519.PublicKey)),
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            status,
		EntityVersion:     entityVersion,
	}
}

func daemonReadmissionCanonicalJSON(t *testing.T, value any) []byte {
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

func assertDaemonReadmissionPredecessor(
	t *testing.T,
	path string,
	want store.StateView,
) {
	t.Helper()
	database, err := store.Open(
		context.Background(),
		store.Options{Path: path},
	)
	if err != nil {
		t.Fatalf("open retained predecessor: %v", err)
	}
	defer func() { _ = database.Close() }()
	if err := database.VerifyCommitmentHistory(context.Background()); err != nil {
		t.Fatalf("verify retained predecessor history: %v", err)
	}
	mode, err := database.ReplicaEvidenceMode(context.Background())
	if err != nil || mode != store.ReplicaEvidenceRaft {
		t.Fatalf("retained predecessor evidence = (%q, %v)", mode, err)
	}
	got, err := database.View(context.Background())
	if err != nil {
		t.Fatalf("read retained predecessor: %v", err)
	}
	if got.SessionID != want.SessionID ||
		got.WorkspaceID != want.WorkspaceID ||
		got.RecoveryGeneration != 0 ||
		got.Heads != want.Heads ||
		got.ProjectionStateDigest != want.ProjectionStateDigest ||
		!reflect.DeepEqual(got.ProjectionRows, want.ProjectionRows) {
		t.Fatalf("retained predecessor differs:\ngot=%+v\nwant=%+v", got, want)
	}
}

func assertDaemonReadmissionReview(
	t *testing.T,
	retained *daemonMeshIntegrationNode,
	joined daemonMeshPairingJoinResult,
	expectedVersion uint64,
) {
	t.Helper()
	if joined.result.SessionID != daemonTestSessionID ||
		joined.result.WorkspaceID != daemonTestWorkspaceID ||
		joined.result.RecoveryGeneration != 1 ||
		joined.result.DeviceID != retained.deviceID ||
		joined.result.StatePath != retained.statePath ||
		joined.result.Resumed ||
		joined.review.Mode != pairing.ModeReadmission ||
		joined.review.Core.JoinerDeviceID != retained.deviceID ||
		joined.review.SubjectDeviceID == nil ||
		*joined.review.SubjectDeviceID != retained.deviceID ||
		joined.review.ExpectedEntityVersion == nil ||
		*joined.review.ExpectedEntityVersion != expectedVersion ||
		joined.review.Role != device.RoleEditor ||
		joined.review.Core.InitialEpochBinding.Epoch != 1 ||
		!bytes.Equal(
			joined.review.Core.JoinerIdentityPublicKey[:],
			retained.privateKey.Public().(ed25519.PublicKey),
		) {
		t.Fatalf("readmission join/review = %+v", joined)
	}
}

func assertDaemonReadmissionDurableState(
	t *testing.T,
	retained *daemonMeshIntegrationNode,
	owner *daemonMeshIntegrationNode,
	predecessor store.StateView,
	now time.Time,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()
	database, err := store.Open(ctx, store.Options{Path: retained.statePath})
	if err != nil {
		t.Fatalf("open readmitted state: %v", err)
	}
	if err := database.VerifyCommitmentHistory(ctx); err != nil {
		_ = database.Close()
		t.Fatalf("verify readmitted commitments: %v", err)
	}
	mode, err := database.ReplicaEvidenceMode(ctx)
	if err != nil || mode != store.ReplicaEvidenceSettledNonvoter {
		_ = database.Close()
		t.Fatalf("readmitted evidence = (%q, %v)", mode, err)
	}
	current, err := database.VerifiedSettledNonvoterView(ctx)
	if err != nil {
		_ = database.Close()
		t.Fatalf("VerifiedSettledNonvoterView(): %v", err)
	}
	if current.SessionID != daemonTestSessionID ||
		current.WorkspaceID != daemonTestWorkspaceID ||
		current.RecoveryGeneration != 1 ||
		current.CurrentTerm != nil ||
		current.LastRaftAppliedLogIndex != nil {
		_ = database.Close()
		t.Fatalf("readmitted settled view = %+v", current)
	}
	generationZero, err := database.VerifiedGenerationZeroView(ctx)
	if err != nil {
		_ = database.Close()
		t.Fatalf("VerifiedGenerationZeroView(): %v", err)
	}
	if generationZero.SessionID != predecessor.SessionID ||
		generationZero.WorkspaceID != predecessor.WorkspaceID ||
		generationZero.RecoveryGeneration != 0 ||
		generationZero.Heads != predecessor.Heads ||
		generationZero.ProjectionStateDigest !=
			predecessor.ProjectionStateDigest ||
		!reflect.DeepEqual(
			generationZero.ProjectionRows,
			predecessor.ProjectionRows,
		) {
		_ = database.Close()
		t.Fatalf(
			"retained generation zero differs:\ngot=%+v\nwant=%+v",
			generationZero,
			predecessor,
		)
	}
	root, found, err := database.VerifiedStandaloneLogicalSnapshotBaseline(ctx)
	if err != nil || !found {
		_ = database.Close()
		t.Fatalf("readmitted snapshot baseline = (%t, %v)", found, err)
	}
	input := root.Unsigned().Input()
	if input.SessionID != current.SessionID ||
		input.WorkspaceID != current.WorkspaceID ||
		input.RecoveryGeneration != current.RecoveryGeneration ||
		input.ChainIndex != current.Heads.ChainIndex ||
		input.ResultIndex != current.Heads.ResultIndex ||
		store.Digest(input.ChainHash) != current.Heads.ChainHash ||
		store.Digest(input.ResultHash) != current.Heads.ResultHash ||
		store.Digest(input.ProjectionAccumulator) !=
			current.Heads.ProjectionAccumulator ||
		store.Digest(input.ProjectionStateDigest) !=
			current.ProjectionStateDigest {
		_ = database.Close()
		t.Fatalf("readmitted snapshot/view mismatch:\nroot=%+v\nview=%+v", input, current)
	}
	marker, markerFound, err := database.LocalState().
		RebootstrapInstallMarker(ctx)
	if err != nil || markerFound {
		_ = database.Close()
		t.Fatalf("readmission marker = (%+v, %t, %v)", marker, markerFound, err)
	}
	status, err := database.LocalState().StatusSnapshot(
		ctx,
		retained.deviceID,
		1,
	)
	if err != nil {
		_ = database.Close()
		t.Fatalf("readmitted durable status: %v", err)
	}
	if status.Member.ID != retained.deviceID ||
		status.Member.Role != device.RoleEditor ||
		status.Member.Status != device.StatusActive ||
		status.Member.EntityVersion != 2 ||
		status.VoterSet.VoterSetVersion != 1 ||
		status.CredentialAuthority.VoterSetVersion != 1 ||
		!sameDaemonMeshIntegrationDeviceIDs(
			status.VoterSet.VoterDeviceIDs(),
			[]domain.DeviceID{owner.deviceID},
		) ||
		!sameDaemonMeshIntegrationDeviceIDs(
			status.CredentialAuthority.VoterDeviceIDs(),
			[]domain.DeviceID{owner.deviceID},
		) {
		_ = database.Close()
		t.Fatalf("readmitted durable status = %+v", status)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close readmitted state: %v", err)
	}

	replica, err := consensus.OpenSettledReplica(
		ctx,
		consensus.SettledReplicaOptions{
			StatePath:     retained.statePath,
			OriginBootID:  daemonTestVerifyBootID,
			LocalDeviceID: retained.deviceID,
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(readmitted): %v", err)
	}
	admission, err := replica.PeerAdmissionSnapshot()
	if err != nil {
		_ = replica.Close()
		t.Fatalf("readmitted PeerAdmissionSnapshot(): %v", err)
	}
	member, memberFound := admission.Member(retained.deviceID)
	authority, authorityFound := admission.CredentialAuthority()
	epoch, epochFound := admission.CurrentCredentialEpoch(retained.deviceID)
	authorization, authorizationFound :=
		admission.ActiveCredentialAuthorizationAt(retained.deviceID, now)
	if !memberFound ||
		member.ID != retained.deviceID ||
		member.Role != device.RoleEditor ||
		member.Status != device.StatusActive ||
		member.EntityVersion != 2 ||
		!bytes.Equal(
			member.IdentityPublicKey,
			retained.privateKey.Public().(ed25519.PublicKey),
		) ||
		!authorityFound ||
		authority.SessionID != daemonTestSessionID ||
		authority.VoterSetVersion != 1 ||
		!sameDaemonMeshIntegrationDeviceIDs(
			authority.VoterDeviceIDs,
			[]domain.DeviceID{owner.deviceID},
		) ||
		!epochFound ||
		epoch != 1 ||
		!authorizationFound ||
		authorization.DeviceID != retained.deviceID ||
		authorization.Epoch != 1 ||
		authorization.Role != credentialauthorization.RoleEditor {
		_ = replica.Close()
		t.Fatalf(
			"readmitted admission = member(%+v,%t) authority(%+v,%t) epoch(%d,%t) authorization(%+v,%t)",
			member,
			memberFound,
			authority,
			authorityFound,
			epoch,
			epochFound,
			authorization,
			authorizationFound,
		)
	}
	if err := replica.Close(); err != nil {
		t.Fatalf("close readmitted replica: %v", err)
	}

	identityPrivate, err := retained.credentials.Get(
		ctx,
		credentialstore.IdentityReference(),
	)
	if err != nil || len(identityPrivate) != ed25519.PrivateKeySize {
		clear(identityPrivate)
		t.Fatalf("load retained identity = (%d bytes, %v)", len(identityPrivate), err)
	}
	identityPublic := ed25519.PrivateKey(identityPrivate).
		Public().(ed25519.PublicKey)
	identityID, deriveErr := device.DeriveID(identityPublic)
	if deriveErr != nil ||
		identityID != retained.deviceID ||
		!bytes.Equal(identityPublic, member.IdentityPublicKey) {
		clear(identityPrivate)
		t.Fatalf("retained identity = (%s, %v)", identityID, deriveErr)
	}
	clear(identityPrivate)
	epochReference, err := credentialstore.EpochReference(
		daemonTestSessionID,
		retained.deviceID,
		1,
	)
	if err != nil {
		t.Fatalf("readmitted epoch reference: %v", err)
	}
	epochPrivate, err := retained.credentials.Get(ctx, epochReference)
	if err != nil || len(epochPrivate) != ed25519.PrivateKeySize {
		clear(epochPrivate)
		t.Fatalf("load readmitted epoch = (%d bytes, %v)", len(epochPrivate), err)
	}
	epochPublic := ed25519.PrivateKey(epochPrivate).
		Public().(ed25519.PublicKey)
	if !bytes.Equal(epochPublic, authorization.EpochPublicKey[:]) {
		clear(epochPrivate)
		t.Fatal("readmitted epoch key does not match authorization")
	}
	clear(epochPrivate)
}

func waitForDaemonReadmissionIPC(
	t *testing.T,
	retained *daemonMeshIntegrationNode,
	ownerID domain.DeviceID,
) {
	t.Helper()
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-retained.exited:
			retained.running = false
			t.Fatalf(
				"readmitted daemon exited before IPC: %v",
				retained.exitErr,
			)
		default:
		}
		status, err := readDaemonMeshIntegrationStatus(retained.localEndpoint)
		if err == nil {
			if status.Session.SessionID != string(daemonTestSessionID) ||
				status.Session.WorkspaceID != string(daemonTestWorkspaceID) ||
				status.Session.RecoveryGeneration != 1 ||
				status.Session.LocalDeviceID != string(retained.deviceID) ||
				status.Session.MemberRole != string(device.RoleEditor) ||
				status.Session.MemberStatus != string(device.StatusActive) ||
				status.Session.AppliedTerm != nil ||
				status.Session.AppliedRaftIndex != nil ||
				status.Consensus.State != "settled" ||
				status.Consensus.Role != "nonvoter" ||
				status.Consensus.StrongWrites != "waiting" ||
				!daemonMeshIntegrationTarget(
					[]ui.Snapshot{status},
					1,
					[]domain.DeviceID{ownerID},
				) ||
				!daemonMeshIntegrationMemberStatus(
					[]ui.Snapshot{status},
					retained.deviceID,
					device.StatusActive,
					2,
				) {
				t.Fatalf("readmitted daemon IPC status = %+v", status)
			}
			return
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("readmitted daemon IPC did not become available: %v", lastErr)
}

func assertDaemonReadmissionReopens(t *testing.T, path string) {
	t.Helper()
	for attempt := 1; attempt <= 2; attempt++ {
		database, err := store.Open(
			context.Background(),
			store.Options{Path: path},
		)
		if err != nil {
			t.Fatalf("reopen readmitted state %d: %v", attempt, err)
		}
		verifyErr := database.VerifyCommitmentHistory(context.Background())
		view, viewErr := database.VerifiedSettledNonvoterView(
			context.Background(),
		)
		closeErr := database.Close()
		if verifyErr != nil ||
			viewErr != nil ||
			closeErr != nil ||
			view.SessionID != daemonTestSessionID ||
			view.WorkspaceID != daemonTestWorkspaceID ||
			view.RecoveryGeneration != 1 ||
			view.CurrentTerm != nil ||
			view.LastRaftAppliedLogIndex != nil {
			t.Fatalf(
				"readmitted reopen %d = view(%+v,%v) verify(%v) close(%v)",
				attempt,
				view,
				viewErr,
				verifyErr,
				closeErr,
			)
		}
	}
}

func runDaemonReadmissionIntegrationChild(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationProcessTimeout,
	)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestDaemonProductionReadmissionComposition$",
		"-test.count=1",
		"-test.v",
		daemonMeshChildWatchdogArgument(
			daemonMeshIntegrationProcessTimeout,
		),
	)
	command.Env = append(
		daemonTestEnvironment(os.Environ()),
		daemonReadmissionIntegrationChildMarker+"=1",
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf(
			"readmission integration child timed out after %s: %v\n%s",
			daemonMeshIntegrationProcessTimeout,
			ctx.Err(),
			output,
		)
	}
	requireDaemonIntegrationChildResult(t, "readmission integration", output, err)
}
