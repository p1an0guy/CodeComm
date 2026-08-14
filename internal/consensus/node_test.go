package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/reducer"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

func TestSingleNodeStatusReportsReadyOneVoterAndDurableWork(t *testing.T) {
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	waitForNodeLeader(t, node)

	signed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"status task",
	)
	if _, err := node.Apply(testContext(t), signed); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	snapshot, err := node.Status(testContext(t))
	if err != nil {
		t.Fatalf("Status(): %v", err)
	}
	if snapshot.Runtime.State != coordstatus.ConsensusReady ||
		snapshot.Runtime.Role != coordstatus.RoleLeader ||
		snapshot.Runtime.LeaderDeviceID != deviceID ||
		snapshot.Runtime.StrongWrites != coordstatus.StrongWritesAvailable ||
		snapshot.Runtime.QuorumRequired != 1 ||
		len(snapshot.Runtime.LiveVoterDeviceIDs) != 1 ||
		snapshot.Runtime.LiveVoterDeviceIDs[0] != deviceID ||
		snapshot.Durable.Member.ID != deviceID ||
		snapshot.Durable.TaskTotal != 1 ||
		len(snapshot.Durable.Tasks) != 1 ||
		snapshot.Durable.Tasks[0].ID != nodeTestTaskID1 {
		t.Fatalf("Status() = %#v", snapshot)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("Status().Validate(): %v", err)
	}
}

func TestApplyAtGenerationAppliesExactLineage(t *testing.T) {
	node, identityPrivate, deviceID := openApplyAtGenerationTestNode(t)
	initialAdmission, err := node.PeerAdmissionSnapshot()
	if err != nil {
		t.Fatalf("PeerAdmissionSnapshot(initial): %v", err)
	}
	if index, valid := initialAdmission.AppliedChainIndex(); !valid || index != 0 {
		t.Fatalf(
			"initial admission chain index = (%d, %t), want (0, true)",
			index,
			valid,
		)
	}
	signed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"generation-fenced task",
	)

	result, err := node.ApplyAtGeneration(
		testContext(t),
		nodeTestSessionID,
		0,
		signed,
	)
	if err != nil {
		t.Fatalf("ApplyAtGeneration(): %v", err)
	}
	if result.Duplicate ||
		result.Outcome.Status != store.OutcomeAccepted ||
		result.Heads.ChainIndex != 1 ||
		result.Heads.ResultIndex != 1 {
		t.Fatalf("ApplyAtGeneration() = %#v", result)
	}
	lookup, found, err := node.state.LookupCommandResult(
		testContext(t),
		nodeTestEventID1,
	)
	if err != nil {
		t.Fatalf("LookupCommandResult(): %v", err)
	}
	if !found ||
		lookup.SessionID != nodeTestSessionID ||
		lookup.RecoveryGeneration != 0 {
		t.Fatalf("LookupCommandResult() = (%#v, %t)", lookup, found)
	}
	appliedAdmission, err := node.PeerAdmissionSnapshot()
	if err != nil {
		t.Fatalf("PeerAdmissionSnapshot(applied): %v", err)
	}
	if index, valid := appliedAdmission.AppliedChainIndex(); !valid || index != 1 {
		t.Fatalf(
			"applied admission chain index = (%d, %t), want (1, true)",
			index,
			valid,
		)
	}
	member, found := appliedAdmission.Member(deviceID)
	if !found || member.ID != deviceID ||
		!bytes.Equal(member.IdentityPublicKey, identityPrivate.Public().(ed25519.PublicKey)) {
		t.Fatalf("applied admission member = (%+v, %t)", member, found)
	}
}

func TestPeerAdmissionSnapshotFailsClosedOnRevisionMismatch(t *testing.T) {
	node, _, _ := openApplyAtGenerationTestNode(t)

	publication := node.fsm.admission.Load()
	if publication == nil || publication.snapshot == nil ||
		publication.revision < 1 {
		t.Fatalf("initial peer-admission publication = %#v", publication)
	}
	select {
	case <-node.PeerAdmissionChanges():
	default:
		t.Fatal("initial peer-admission publication was not signaled")
	}

	node.fsm.admission.Store(&peerAdmissionPublication{
		revision: publication.revision + 1,
		snapshot: publication.snapshot,
	})
	if snapshot, err := node.PeerAdmissionSnapshot(); snapshot != nil ||
		!errors.Is(err, ErrPeerAdmissionUnavailable) {
		t.Fatalf(
			"PeerAdmissionSnapshot(mismatch) = (%v, %v), want unavailable",
			snapshot,
			err,
		)
	}

	node.fsm.admission.Store(publication)
	if snapshot, err := node.PeerAdmissionSnapshot(); err != nil ||
		snapshot != publication.snapshot {
		t.Fatalf(
			"PeerAdmissionSnapshot(restored) = (%p, %v), want %p",
			snapshot,
			err,
			publication.snapshot,
		)
	}
}

func TestPeerAdmissionChangesCloseOnNodeShutdown(t *testing.T) {
	node, _, _ := openApplyAtGenerationTestNode(t)
	changes := node.PeerAdmissionChanges()
	awaitPeerAdmissionChange(t, changes, "initial publication")

	if err := node.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	select {
	case _, open := <-changes:
		if open {
			t.Fatal("PeerAdmissionChanges() remained open after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PeerAdmissionChanges() did not close with node")
	}
}

func TestPeerAdmissionChangesCloseOnFatalNodeFailure(t *testing.T) {
	node, _, _ := openApplyAtGenerationTestNode(t)
	changes := node.PeerAdmissionChanges()
	awaitPeerAdmissionChange(t, changes, "initial publication")

	terminal := errors.New("terminal test failure")
	node.recordFatal(terminal)
	select {
	case _, open := <-changes:
		if open {
			t.Fatal("PeerAdmissionChanges() remained open after fatal failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PeerAdmissionChanges() did not close after fatal failure")
	}
	if err := node.FatalError(); !errors.Is(err, terminal) {
		t.Fatalf("FatalError() = %v, want %v", err, terminal)
	}
}

func TestAdmissionAccessChangedExcludesAuditAccounting(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		changes reducer.Changes
		want    bool
	}{
		"none": {},
		"audit accounting": {
			changes: reducer.Changes{
				AuditCounters: []auditcounter.Counter{{}},
			},
		},
		"membership": {
			changes: reducer.Changes{
				Devices: []device.Device{{}},
			},
			want: true,
		},
		"credential authorization": {
			changes: reducer.Changes{
				CredentialAuthorizations: []credentialauthorization.Authorization{{}},
			},
			want: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := admissionAccessChanged(test.changes); got != test.want {
				t.Fatalf("admissionAccessChanged() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestPeerAdmissionTracksCredentialRoleAndRevocationApplies(t *testing.T) {
	fixture := openPeerAdmissionTestNode(t)
	changes := fixture.node.PeerAdmissionChanges()
	select {
	case <-changes:
	default:
		t.Fatal("initial peer-admission publication was not signaled")
	}

	readerStop := make(chan struct{})
	readerErrors := make(chan error, 32)
	var readers sync.WaitGroup
	for range 32 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-readerStop:
					return
				default:
					snapshot, err := fixture.node.PeerAdmissionSnapshot()
					if err != nil {
						if errors.Is(err, ErrPeerAdmissionUnavailable) {
							continue
						}
						readerErrors <- err
						return
					}
					sessionID, generation, valid := snapshot.Lineage()
					member, found := snapshot.Member(fixture.peerDeviceID)
					if !valid || sessionID != nodeTestSessionID ||
						generation != 0 || !found ||
						member.ID != fixture.peerDeviceID {
						readerErrors <- errors.New(
							"concurrent reader observed an invalid admission cut",
						)
						return
					}
				}
			}
		}()
	}
	defer func() {
		close(readerStop)
		readers.Wait()
		close(readerErrors)
		for err := range readerErrors {
			t.Errorf("concurrent peer-admission read: %v", err)
		}
	}()

	credentialEvent, authorization, epochPrivateKey :=
		nodeTestCredentialAuthorizationEvent(t, fixture, 1)
	result, err := fixture.node.Apply(testContext(t), credentialEvent)
	if err != nil || result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(credential) = (%#v, %v)", result, err)
	}
	awaitPeerAdmissionChange(t, changes, "credential authorization")

	contentTLS, _, err := transport.IssueContentCertificate(
		authorization,
		epochPrivateKey,
	)
	if err != nil {
		t.Fatalf("IssueContentCertificate(): %v", err)
	}
	contentCertificate, err := transport.ParseContentCertificate(
		contentTLS.Certificate[0],
	)
	if err != nil {
		t.Fatalf("ParseContentCertificate(): %v", err)
	}
	identityTLS, _, err := transport.IssueIdentityCertificate(
		nodeTestSessionID,
		0,
		fixture.peerIdentityPrivate,
	)
	if err != nil {
		t.Fatalf("IssueIdentityCertificate(): %v", err)
	}
	identityCertificate, err := transport.ParseIdentityCertificate(
		identityTLS.Certificate[0],
	)
	if err != nil {
		t.Fatalf("ParseIdentityCertificate(): %v", err)
	}
	verifiers, err := peerauth.NewVerifiers(
		fixture.node.PeerAdmissionSnapshot,
		func() time.Time {
			return time.Date(2026, 8, 14, 12, 5, 0, 0, time.UTC)
		},
	)
	if err != nil {
		t.Fatalf("peerauth.NewVerifiers(): %v", err)
	}
	if err := verifiers.VerifyConsensusPeer(identityCertificate); err != nil {
		t.Fatalf("VerifyConsensusPeer(active) error = %v", err)
	}
	if _, err := verifiers.VerifyContentPeer(contentCertificate); err != nil {
		t.Fatalf("VerifyContentPeer(active) error = %v", err)
	}
	if err := verifiers.RequireOwner(fixture.peerDeviceID); err != nil {
		t.Fatalf("RequireOwner(active owner) error = %v", err)
	}

	roleEvent := nodeTestMembershipEvent(
		t,
		fixture.ownerIdentityPrivate,
		fixture.ownerDeviceID,
		event.KindMembershipRoleChanged,
		fixture.peerDeviceID,
		1,
		map[string]any{
			"device_id": fixture.peerDeviceID,
			"role":      device.RoleEditor,
		},
		nodeTestEventID5,
		2,
	)
	result, err = fixture.node.Apply(testContext(t), roleEvent)
	if err != nil || result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(role change) = (%#v, %v)", result, err)
	}
	awaitPeerAdmissionChange(t, changes, "role change")
	if _, err := verifiers.VerifyContentPeer(contentCertificate); err != nil {
		t.Fatalf("credential stopped authenticating after demotion: %v", err)
	}
	if role, err := verifiers.CurrentRole(fixture.peerDeviceID); err != nil ||
		role != device.RoleEditor {
		t.Fatalf("CurrentRole(demoted) = (%q, %v)", role, err)
	}
	if err := verifiers.RequireOwner(fixture.peerDeviceID); !errors.Is(
		err,
		peerauth.ErrPeerNotAuthorized,
	) {
		t.Fatalf("RequireOwner(demoted) error = %v", err)
	}

	ingress := startPeerAdmissionTestIngress(
		t,
		fixture,
		verifiers,
		changes,
	)
	consensusConnection := ingress.dial(
		t,
		transport.PlaneConsensus,
		identityTLS,
	)
	defer consensusConnection.Close()
	contentConnection := ingress.dial(
		t,
		transport.PlaneContent,
		contentTLS,
	)
	defer contentConnection.Close()
	enteredPlanes := make(map[transport.Plane]bool, 2)
	for range 2 {
		select {
		case peer := <-ingress.entered:
			if peer.DeviceID != fixture.peerDeviceID {
				t.Fatalf(
					"ingress peer = %+v, want device %s",
					peer,
					fixture.peerDeviceID,
				)
			}
			enteredPlanes[peer.Plane] = true
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for peer ingress")
		}
	}
	if !enteredPlanes[transport.PlaneConsensus] ||
		!enteredPlanes[transport.PlaneContent] {
		t.Fatalf("entered ingress planes = %v", enteredPlanes)
	}

	revokeEvent := nodeTestMembershipEvent(
		t,
		fixture.ownerIdentityPrivate,
		fixture.ownerDeviceID,
		event.KindMembershipDeviceRevoked,
		fixture.peerDeviceID,
		2,
		map[string]any{
			"device_id":                  fixture.peerDeviceID,
			"reason":                     "integration test retirement",
			"voter_set":                  []domain.DeviceID{fixture.ownerDeviceID},
			"expected_voter_set_version": uint64(1),
		},
		nodeTestEventID6,
		3,
	)
	result, err = fixture.node.Apply(testContext(t), revokeEvent)
	if err != nil || result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(revocation) = (%#v, %v)", result, err)
	}
	closedPlanes := make(map[transport.Plane]bool, 2)
	for range 2 {
		select {
		case peer := <-ingress.canceled:
			closedPlanes[peer.Plane] = true
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for revoked ingress closure")
		}
	}
	if !closedPlanes[transport.PlaneConsensus] ||
		!closedPlanes[transport.PlaneContent] {
		t.Fatalf("revocation closed planes = %v", closedPlanes)
	}
	assertPeerTLSClosed(t, consensusConnection)
	assertPeerTLSClosed(t, contentConnection)
	if err := verifiers.VerifyConsensusPeer(identityCertificate); !errors.Is(
		err,
		peerauth.ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyConsensusPeer(revoked) error = %v", err)
	}
	if _, err := verifiers.VerifyContentPeer(contentCertificate); !errors.Is(
		err,
		peerauth.ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyContentPeer(revoked) error = %v", err)
	}
}

func TestApplyAtGenerationMismatchDoesNotAdvanceState(t *testing.T) {
	tests := []struct {
		name       string
		sessionID  domain.UUIDv7
		generation uint64
	}{
		{
			name:       "session",
			sessionID:  nodeTestBootID2,
			generation: 0,
		},
		{
			name:       "generation",
			sessionID:  nodeTestSessionID,
			generation: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node, identityPrivate, deviceID :=
				openApplyAtGenerationTestNode(t)
			signed := nodeTestTaskEvent(
				t,
				identityPrivate,
				deviceID,
				nodeTestBootID1,
				nodeTestEventID1,
				nodeTestTaskID1,
				nodeTestTimestamp1,
				1,
				"must not commit",
			)
			before, err := node.View(testContext(t))
			if err != nil {
				t.Fatalf("View(before): %v", err)
			}

			if _, err := node.ApplyAtGeneration(
				testContext(t),
				test.sessionID,
				test.generation,
				signed,
			); !errors.Is(err, ErrLineageMismatch) {
				t.Fatalf(
					"ApplyAtGeneration() error = %v, want ErrLineageMismatch",
					err,
				)
			}
			assertApplyAtGenerationDidNotAdvance(
				t,
				node,
				before,
				nodeTestEventID1,
			)
		})
	}
}

func TestApplyAtGenerationCancellationWhileGateOccupiedDoesNotAdvanceState(
	t *testing.T,
) {
	node, identityPrivate, deviceID := openApplyAtGenerationTestNode(t)
	signed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"canceled generation-fenced task",
	)
	before, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(before): %v", err)
	}

	gateEntered := make(chan struct{})
	releaseGate := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseGate) })
	})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- node.withLineageGate(
			context.Background(),
			func() error {
				close(gateEntered)
				<-releaseGate
				return nil
			},
		)
	}()
	select {
	case <-gateEntered:
	case <-testContext(t).Done():
		t.Fatal("lineage gate holder did not start")
	}

	ctx, cancel := context.WithCancel(context.Background())
	applyDone := make(chan error, 1)
	go func() {
		_, err := node.ApplyAtGeneration(
			ctx,
			nodeTestSessionID,
			0,
			signed,
		)
		applyDone <- err
	}()
	select {
	case err := <-applyDone:
		t.Fatalf("ApplyAtGeneration() bypassed occupied gate: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-applyDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf(
				"ApplyAtGeneration() error = %v, want context.Canceled",
				err,
			)
		}
	case <-testContext(t).Done():
		t.Fatal("canceled ApplyAtGeneration() did not return")
	}

	releaseOnce.Do(func() { close(releaseGate) })
	if err := <-holderDone; err != nil {
		t.Fatalf("lineage gate holder: %v", err)
	}
	assertApplyAtGenerationDidNotAdvance(
		t,
		node,
		before,
		nodeTestEventID1,
	)
}

func TestRunAtGenerationRequiresExactLineage(t *testing.T) {
	node, _, _ := openApplyAtGenerationTestNode(t)
	calls := 0
	if err := node.RunAtGeneration(
		testContext(t),
		nodeTestSessionID,
		0,
		func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			calls++
			return nil
		},
	); err != nil {
		t.Fatalf("RunAtGeneration() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("RunAtGeneration() calls = %d, want 1", calls)
	}

	if err := node.RunAtGeneration(
		testContext(t),
		nodeTestSessionID,
		1,
		func(context.Context) error {
			calls++
			return nil
		},
	); !errors.Is(err, ErrLineageMismatch) {
		t.Fatalf(
			"RunAtGeneration(stale) error = %v, want ErrLineageMismatch",
			err,
		)
	}
	if calls != 1 {
		t.Fatalf("stale RunAtGeneration() invoked callback")
	}

	err := node.RunAtGeneration(
		testContext(t),
		nodeTestSessionID,
		0,
		func(ctx context.Context) error {
			return node.RunAtGeneration(
				ctx,
				nodeTestSessionID,
				0,
				func(context.Context) error { return nil },
			)
		},
	)
	if !errors.Is(err, ErrLineageReentry) {
		t.Fatalf(
			"RunAtGeneration(reentry) error = %v, want ErrLineageReentry",
			err,
		)
	}
}

func TestRunAtGenerationCancellationAllowsClose(t *testing.T) {
	node, _, _ := openApplyAtGenerationTestNode(t)
	entered := make(chan struct{})
	runDone := make(chan error, 1)
	go func() {
		runDone <- node.RunAtGeneration(
			context.Background(),
			nodeTestSessionID,
			0,
			func(ctx context.Context) error {
				close(entered)
				<-ctx.Done()
				return ctx.Err()
			},
		)
	}()
	select {
	case <-entered:
	case <-testContext(t).Done():
		t.Fatal("RunAtGeneration() callback did not start")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- node.Close() }()
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf(
				"RunAtGeneration() error = %v, want context.Canceled",
				err,
			)
		}
	case <-testContext(t).Done():
		t.Fatal("RunAtGeneration() ignored node close")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-testContext(t).Done():
		t.Fatal("Close() did not finish after callback cancellation")
	}
}

const (
	nodeTestSessionID   = domain.UUIDv7("018f47de-89ab-7def-8123-0123456789ab")
	nodeTestWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
	nodeTestBootID1     = domain.UUIDv7("018f47de-89ab-7def-8123-1123456789ab")
	nodeTestBootID2     = domain.UUIDv7("018f47de-89ab-7def-8123-2123456789ab")
	nodeTestEventID1    = domain.UUIDv7("018f47de-89ab-7def-8123-3123456789ab")
	nodeTestEventID2    = domain.UUIDv7("018f47de-89ab-7def-8123-4123456789ab")
	nodeTestEventID3    = domain.UUIDv7("018f47de-89ab-7def-8123-4223456789ab")
	nodeTestEventID4    = domain.UUIDv7("018f47de-89ab-7def-8123-4323456789ab")
	nodeTestEventID5    = domain.UUIDv7("018f47de-89ab-7def-8123-4423456789ab")
	nodeTestEventID6    = domain.UUIDv7("018f47de-89ab-7def-8123-4523456789ab")
	nodeTestTaskID1     = domain.UUIDv7("018f47de-89ab-7def-8123-5123456789ab")
	nodeTestTaskID2     = domain.UUIDv7("018f47de-89ab-7def-8123-6123456789ab")
	nodeTestTaskID3     = domain.UUIDv7("018f47de-89ab-7def-8123-6223456789ab")
	nodeTestTimestamp1  = domain.Timestamp("2026-08-11T12:00:00Z")
	nodeTestTimestamp2  = domain.Timestamp("2026-08-11T12:01:00Z")
	nodeTestTimestamp3  = domain.Timestamp("2026-08-11T12:02:00Z")
)

func TestSingleNodeAppliesSnapshotsAndRestartsWithoutHeadDrift(t *testing.T) {
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	config := nodeTestRaftConfig()
	clock := nodeTestClock()

	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        clock,
		RaftConfig:   config,
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(new): %v", err)
	}
	firstClosed := false
	t.Cleanup(func() {
		if !firstClosed {
			_ = node.Close()
		}
	})
	waitForNodeLeader(t, node)

	first := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"first task",
	)
	firstResult, err := node.Apply(testContext(t), first)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	if firstResult.Duplicate ||
		firstResult.Outcome.Status != store.OutcomeAccepted ||
		firstResult.Outcome.Code != string(reducer.CodeAccepted) ||
		firstResult.Heads.ChainIndex != 1 ||
		firstResult.Heads.ResultIndex != 1 {
		t.Fatalf("Apply(first) = %#v", firstResult)
	}
	if err := node.Barrier(testContext(t)); err != nil {
		t.Fatalf("Barrier(): %v", err)
	}
	if err := node.Snapshot(testContext(t)); err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}

	duplicate, err := node.Apply(testContext(t), first)
	if err != nil {
		t.Fatalf("Apply(exact duplicate): %v", err)
	}
	if !duplicate.Duplicate ||
		!sameNodeCommitmentHeads(duplicate.Heads, firstResult.Heads) {
		t.Fatalf(
			"Apply(exact duplicate) = %#v, first heads = %#v",
			duplicate,
			firstResult.Heads,
		)
	}

	changed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"changed bytes",
	)
	if _, err := node.Apply(testContext(t), changed); !errors.Is(
		err,
		store.ErrIdempotencyConflict,
	) {
		t.Fatalf(
			"Apply(changed duplicate) error = %v, want ErrIdempotencyConflict",
			err,
		)
	}
	second := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID2,
		nodeTestTimestamp2,
		2,
		"second task",
	)
	secondResult, err := node.Apply(testContext(t), second)
	if err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	if secondResult.Heads.ChainIndex != 2 ||
		secondResult.Heads.ResultIndex != 2 {
		t.Fatalf("Apply(second) = %#v", secondResult)
	}
	beforeRestart, err := node.View(context.Background())
	if err != nil {
		t.Fatalf("View(before restart): %v", err)
	}
	if !viewContainsTask(beforeRestart, nodeTestTaskID1) ||
		!viewContainsTask(beforeRestart, nodeTestTaskID2) {
		t.Fatal("pre-restart view is missing a task")
	}

	if err := node.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}
	firstClosed = true

	restarted, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    filepath.Join(root, "state", "state.db"),
			ConsensusDir: filepath.Join(root, "consensus"),
			OriginBootID: nodeTestBootID2,
			Clock:        nodeTestClock(),
			RaftConfig:   config,
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(restart): %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	waitForNodeLeader(t, restarted)
	assertNodeUsesLocalAddress(t, restarted)

	afterRestart, err := restarted.View(context.Background())
	if err != nil {
		t.Fatalf("View(after restart): %v", err)
	}
	if afterRestart.Heads != beforeRestart.Heads ||
		afterRestart.ProjectionStateDigest !=
			beforeRestart.ProjectionStateDigest {
		t.Fatalf(
			"restart drifted commitments:\nbefore: %#v\nafter:  %#v",
			beforeRestart,
			afterRestart,
		)
	}
	replayed, err := restarted.Apply(testContext(t), first)
	if err != nil {
		t.Fatalf("Apply(restart duplicate): %v", err)
	}
	if !replayed.Duplicate || replayed.Heads != beforeRestart.Heads {
		t.Fatalf("Apply(restart duplicate) = %#v", replayed)
	}

	third := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID2,
		nodeTestEventID3,
		nodeTestTaskID3,
		nodeTestTimestamp3,
		1,
		"third task",
	)
	thirdResult, err := restarted.Apply(testContext(t), third)
	if err != nil {
		t.Fatalf("Apply(third): %v", err)
	}
	if thirdResult.Heads.ChainIndex != 3 ||
		thirdResult.Heads.ResultIndex != 3 ||
		thirdResult.Heads.ProjectionAccumulator ==
			beforeRestart.Heads.ProjectionAccumulator {
		t.Fatalf("Apply(third) = %#v", thirdResult)
	}
	finalView, err := restarted.View(context.Background())
	if err != nil {
		t.Fatalf("View(final): %v", err)
	}
	if !viewContainsTask(finalView, nodeTestTaskID1) ||
		!viewContainsTask(finalView, nodeTestTaskID2) ||
		!viewContainsTask(finalView, nodeTestTaskID3) {
		t.Fatal("restart/tail replay lost a task projection")
	}
}

func TestSingleNodeRestartVerifiesAlreadyAppliedLogPrefix(t *testing.T) {
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(new): %v", err)
	}
	waitForNodeLeader(t, node)

	first := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"first task",
	)
	second := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID2,
		nodeTestTimestamp2,
		2,
		"second task",
	)
	if _, err := node.Apply(testContext(t), first); err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	if _, err := node.Apply(testContext(t), second); err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	beforeRestart, err := node.View(context.Background())
	if err != nil {
		t.Fatalf("View(before restart): %v", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}

	var restartClockCalls atomic.Int64
	restarted, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    filepath.Join(root, "state", "state.db"),
			ConsensusDir: filepath.Join(root, "consensus"),
			OriginBootID: nodeTestBootID2,
			Clock: func() (domain.Timestamp, int64, error) {
				restartClockCalls.Add(1)
				return "", 0, errors.New("covered replay must not read the clock")
			},
			RaftConfig: nodeTestRaftConfig(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(restart): %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	waitForNodeLeader(t, restarted)
	if err := restarted.Barrier(testContext(t)); err != nil {
		t.Fatalf("Barrier(restart): %v", err)
	}
	if err := restarted.FatalError(); err != nil {
		t.Fatalf("FatalError(restart): %v", err)
	}
	if calls := restartClockCalls.Load(); calls != 0 {
		t.Fatalf("restart clock calls = %d, want 0", calls)
	}
	afterRestart, err := restarted.View(context.Background())
	if err != nil {
		t.Fatalf("View(after restart): %v", err)
	}
	if afterRestart.Heads != beforeRestart.Heads ||
		afterRestart.ProjectionStateDigest !=
			beforeRestart.ProjectionStateDigest {
		t.Fatalf(
			"covered replay changed durable state:\nbefore: %#v\nafter:  %#v",
			beforeRestart,
			afterRestart,
		)
	}
	assertNodeUsesLocalAddress(t, restarted)
}

func TestConcurrentChangedEventIDNeverCommitsCollision(t *testing.T) {
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(new): %v", err)
	}
	waitForNodeLeader(t, node)

	first := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"first bytes",
	)
	changed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"changed bytes",
	)
	type applyCall struct {
		result store.ApplyResult
		err    error
	}
	start := make(chan struct{})
	calls := make(chan applyCall, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, signed := range []event.SignedEvent{first, changed} {
		signed := signed
		go func() {
			<-start
			result, err := node.Apply(ctx, signed)
			calls <- applyCall{result: result, err: err}
		}()
	}
	close(start)

	var accepted, conflicts int
	for range 2 {
		call := <-calls
		switch {
		case call.err == nil:
			accepted++
			if call.result.Duplicate ||
				call.result.Outcome.Status != store.OutcomeAccepted {
				t.Fatalf("successful concurrent Apply() = %#v", call.result)
			}
		case errors.Is(call.err, store.ErrIdempotencyConflict):
			conflicts++
		default:
			t.Fatalf("concurrent Apply() error = %v", call.err)
		}
	}
	if accepted != 1 || conflicts != 1 {
		t.Fatalf(
			"concurrent results = %d accepted, %d conflicts",
			accepted,
			conflicts,
		)
	}
	if err := node.FatalError(); err != nil {
		t.Fatalf("FatalError(): %v", err)
	}
	beforeRestart, err := node.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if beforeRestart.Heads.ResultIndex != 1 ||
		beforeRestart.LastRaftAppliedLogIndex == nil {
		t.Fatalf("durable state after race = %#v", beforeRestart)
	}
	lastIndex, err := node.stable.LastIndex()
	if err != nil {
		t.Fatalf("Raft LastIndex(): %v", err)
	}
	if lastIndex != *beforeRestart.LastRaftAppliedLogIndex {
		t.Fatalf(
			"Raft last index = %d, SQLite applied index = %d",
			lastIndex,
			*beforeRestart.LastRaftAppliedLogIndex,
		)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}

	restarted, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    filepath.Join(root, "state", "state.db"),
			ConsensusDir: filepath.Join(root, "consensus"),
			OriginBootID: nodeTestBootID2,
			Clock:        nodeTestClock(),
			RaftConfig:   nodeTestRaftConfig(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(restart): %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	waitForNodeLeader(t, restarted)
	if err := restarted.Barrier(testContext(t)); err != nil {
		t.Fatalf("Barrier(restart): %v", err)
	}
	if err := restarted.FatalError(); err != nil {
		t.Fatalf("FatalError(restart): %v", err)
	}
	afterRestart, err := restarted.View(context.Background())
	if err != nil {
		t.Fatalf("View(restart): %v", err)
	}
	if afterRestart.Heads != beforeRestart.Heads ||
		afterRestart.ProjectionStateDigest !=
			beforeRestart.ProjectionStateDigest {
		t.Fatalf(
			"restart after event-ID race drifted state:\nbefore: %#v\nafter:  %#v",
			beforeRestart,
			afterRestart,
		)
	}
}

func TestCanceledApplyRetainsEventIDFlightUntilRaftResolves(t *testing.T) {
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	clockEntered := make(chan struct{})
	releaseClock := make(chan struct{})
	var (
		enterOnce   sync.Once
		releaseOnce sync.Once
	)
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseClock) })
	})
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock: func() (domain.Timestamp, int64, error) {
			enterOnce.Do(func() { close(clockEntered) })
			<-releaseClock
			return "2026-08-11T13:00:00Z", 1, nil
		},
		RaftConfig: nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	waitForNodeLeader(t, node)

	first := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"first bytes",
	)
	changed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"changed bytes",
	)
	type applyCall struct {
		result store.ApplyResult
		err    error
	}
	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan applyCall, 1)
	go func() {
		result, err := node.Apply(ctx, first)
		firstDone <- applyCall{result: result, err: err}
	}()
	select {
	case <-clockEntered:
	case <-testContext(t).Done():
		t.Fatal("first proposal did not reach the FSM")
	}
	beforeChanged, err := node.stable.LastIndex()
	if err != nil {
		t.Fatalf("LastIndex(before changed retry): %v", err)
	}
	cancel()
	select {
	case call := <-firstDone:
		if !errors.Is(call.err, context.Canceled) {
			t.Fatalf("canceled Apply() error = %v, want context.Canceled", call.err)
		}
	case <-testContext(t).Done():
		t.Fatal("canceled Apply() did not return")
	}

	if _, err := node.Apply(
		testContext(t),
		changed,
	); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf(
			"Apply(changed while first unresolved) error = %v, want ErrIdempotencyConflict",
			err,
		)
	}
	afterChanged, err := node.stable.LastIndex()
	if err != nil {
		t.Fatalf("LastIndex(after changed retry): %v", err)
	}
	if afterChanged != beforeChanged {
		t.Fatalf(
			"changed retry appended Raft log %d after unresolved index %d",
			afterChanged,
			beforeChanged,
		)
	}

	releaseOnce.Do(func() { close(releaseClock) })
	if err := node.Barrier(testContext(t)); err != nil {
		t.Fatalf("Barrier(): %v", err)
	}
	duplicate, err := node.Apply(testContext(t), first)
	if err != nil {
		t.Fatalf("Apply(exact retry): %v", err)
	}
	if !duplicate.Duplicate {
		t.Fatalf("exact retry = %#v, want durable duplicate", duplicate)
	}
	if err := node.FatalError(); err != nil {
		t.Fatalf("FatalError(): %v", err)
	}
}

func TestCloseDrainsCommittedApplyBeforeClosingStores(t *testing.T) {
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	clockEntered := make(chan struct{})
	releaseClock := make(chan struct{})
	var (
		enterOnce   sync.Once
		releaseOnce sync.Once
	)
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseClock) })
	})
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock: func() (domain.Timestamp, int64, error) {
			enterOnce.Do(func() { close(clockEntered) })
			<-releaseClock
			return "2026-08-11T13:00:00Z", 1, nil
		},
		RaftConfig: nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	waitForNodeLeader(t, node)
	signed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"close-race task",
	)
	applyDone := make(chan error, 1)
	go func() {
		_, err := node.Apply(context.Background(), signed)
		applyDone <- err
	}()
	select {
	case <-clockEntered:
	case <-testContext(t).Done():
		t.Fatal("proposal did not reach the FSM")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- node.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before the active FSM apply drained: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseClock) })
	if err := <-closeDone; err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if err := <-applyDone; err != nil && !errors.Is(err, ErrNodeClosed) {
		t.Fatalf("Apply() during Close error = %v", err)
	}
	if _, err := node.View(
		context.Background(),
	); !errors.Is(err, ErrNodeClosed) {
		t.Fatalf("View(after Close) error = %v, want ErrNodeClosed", err)
	}

	restarted, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    filepath.Join(root, "state", "state.db"),
			ConsensusDir: filepath.Join(root, "consensus"),
			OriginBootID: nodeTestBootID2,
			Clock:        nodeTestClock(),
			RaftConfig:   nodeTestRaftConfig(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(restart): %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	waitForNodeLeader(t, restarted)
	view, err := restarted.View(context.Background())
	if err != nil {
		t.Fatalf("View(restart): %v", err)
	}
	if !viewContainsTask(view, nodeTestTaskID1) {
		t.Fatal("Close lost a command already committed into the FSM")
	}
}

func TestSingleNodeRestartsAfterSnapshotCompactsEveryLog(t *testing.T) {
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	config := nodeTestRaftConfig()
	config.TrailingLogs = 0
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   config,
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(new): %v", err)
	}
	waitForNodeLeader(t, node)
	signed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"snapshot-backed task",
	)
	if _, err := node.Apply(testContext(t), signed); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if err := node.Snapshot(testContext(t)); err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	lastLogIndex, err := node.stable.LastIndex()
	if err != nil {
		t.Fatalf("Raft LastIndex(): %v", err)
	}
	if lastLogIndex != 0 {
		t.Fatalf("retained last log index = %d, want 0", lastLogIndex)
	}
	beforeRestart, err := node.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}

	restarted, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    filepath.Join(root, "state", "state.db"),
			ConsensusDir: filepath.Join(root, "consensus"),
			OriginBootID: nodeTestBootID2,
			Clock:        nodeTestClock(),
			RaftConfig:   config,
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(restart): %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	waitForNodeLeader(t, restarted)
	afterRestart, err := restarted.View(context.Background())
	if err != nil {
		t.Fatalf("View(restart): %v", err)
	}
	if afterRestart.Heads != beforeRestart.Heads ||
		afterRestart.ProjectionStateDigest !=
			beforeRestart.ProjectionStateDigest {
		t.Fatalf(
			"snapshot-backed restart drifted state:\nbefore: %#v\nafter:  %#v",
			beforeRestart,
			afterRestart,
		)
	}
}

func TestRestartRejectsInflatedSnapshotMetadata(t *testing.T) {
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	waitForNodeLeader(t, node)
	signed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"snapshot metadata task",
	)
	if _, err := node.Apply(testContext(t), signed); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if err := node.Snapshot(testContext(t)); err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	metas, err := node.snapshots.List()
	if err != nil || len(metas) == 0 {
		t.Fatalf("List() = (%#v, %v), want a snapshot", metas, err)
	}
	snapshotID := metas[0].ID
	if err := node.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	metaPath := filepath.Join(
		root,
		"consensus",
		"snapshots",
		snapshotID,
		"meta.json",
	)
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("ReadFile(meta.json): %v", err)
	}
	var diskMeta struct {
		raft.SnapshotMeta
		CRC []byte
	}
	if err := json.Unmarshal(raw, &diskMeta); err != nil {
		t.Fatalf("json.Unmarshal(meta.json): %v", err)
	}
	diskMeta.Index++
	raw, err = json.Marshal(diskMeta)
	if err != nil {
		t.Fatalf("json.Marshal(meta.json): %v", err)
	}
	if err := os.WriteFile(metaPath, raw, 0o600); err != nil {
		t.Fatalf("WriteFile(meta.json): %v", err)
	}

	if _, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    filepath.Join(root, "state", "state.db"),
			ConsensusDir: filepath.Join(root, "consensus"),
			OriginBootID: nodeTestBootID2,
			Clock:        nodeTestClock(),
			RaftConfig:   nodeTestRaftConfig(),
		},
	); !errors.Is(err, ErrSnapshotAnchorCoverage) {
		t.Fatalf(
			"OpenSingleNode(inflated metadata) error = %v, want ErrSnapshotAnchorCoverage",
			err,
		)
	}
}

func TestRestartVerifiesFullHistoryBeforeTrustingSnapshot(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "state.db")
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    statePath,
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	waitForNodeLeader(t, node)
	first := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"first history task",
	)
	second := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID2,
		nodeTestTimestamp2,
		2,
		"second history task",
	)
	rejected := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID3,
		nodeTestTaskID3,
		nodeTestTimestamp3,
		2,
		"reused sequence",
	)
	for _, signed := range []event.SignedEvent{first, second, rejected} {
		if _, err := node.Apply(testContext(t), signed); err != nil {
			t.Fatalf("Apply(%s): %v", signed.Proposal().EventID, err)
		}
	}
	if err := node.Snapshot(testContext(t)); err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	tamperSQLite(
		t,
		statePath,
		`UPDATE command_results
		    SET outcome_json = '{"code":"accepted","status":"accepted","x":1}'
		  WHERE result_index = 1;`,
	)
	if _, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    statePath,
			ConsensusDir: filepath.Join(root, "consensus"),
			OriginBootID: nodeTestBootID2,
			Clock:        nodeTestClock(),
			RaftConfig:   nodeTestRaftConfig(),
		},
	); !errors.Is(err, ErrSnapshotAnchorCoverage) {
		t.Fatalf(
			"OpenSingleNode(tampered history) error = %v, want ErrSnapshotAnchorCoverage",
			err,
		)
	}
}

func TestRetainedRaftCommandSubstitutionHaltsReplay(t *testing.T) {
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	waitForNodeLeader(t, node)
	first := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"first replay task",
	)
	second := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID2,
		nodeTestTimestamp2,
		2,
		"second replay task",
	)
	if _, err := node.Apply(testContext(t), first); err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	if _, err := node.Apply(testContext(t), second); err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	firstLog := findCommandLog(t, node, first.CanonicalBytes())
	if err := node.shutdownRaft(); err != nil {
		t.Fatalf("shutdownRaft(): %v", err)
	}
	firstLog.Data = second.CanonicalBytes()
	if err := node.stable.StoreLog(&firstLog); err != nil {
		t.Fatalf("StoreLog(substituted): %v", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	restarted, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    filepath.Join(root, "state", "state.db"),
			ConsensusDir: filepath.Join(root, "consensus"),
			OriginBootID: nodeTestBootID2,
			Clock:        nodeTestClock(),
			RaftConfig:   nodeTestRaftConfig(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(restart): %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	err = restarted.WaitForLeader(testContext(t))
	if err == nil {
		err = restarted.Barrier(testContext(t))
	}
	if !errors.Is(err, ErrFSMHalted) &&
		!errors.Is(restarted.FatalError(), ErrFSMHalted) {
		t.Fatalf(
			"substituted replay errors = (%v, %v), want ErrFSMHalted",
			err,
			restarted.FatalError(),
		)
	}
}

func TestSnapshotIntegrityFailureHaltsNode(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "state.db")
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    statePath,
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	waitForNodeLeader(t, node)
	first := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"snapshot corruption task",
	)
	if _, err := node.Apply(testContext(t), first); err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	tamperSQLite(
		t,
		statePath,
		`UPDATE command_results
		    SET outcome_json = '{"code":"accepted","status":"accepted","x":1}'
		  WHERE result_index = 1;`,
	)

	if err := node.Snapshot(testContext(t)); err == nil {
		t.Fatal("Snapshot() accepted corrupt history")
	}
	if err := node.FatalError(); !errors.Is(err, ErrFSMHalted) {
		t.Fatalf("FatalError() = %v, want ErrFSMHalted", err)
	}
	second := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID2,
		nodeTestTimestamp2,
		2,
		"must not apply",
	)
	if _, err := node.Apply(
		testContext(t),
		second,
	); !errors.Is(err, ErrFSMHalted) {
		t.Fatalf("Apply(after snapshot halt) error = %v, want ErrFSMHalted", err)
	}
}

func TestOpenRejectsGapAfterLatestSnapshot(t *testing.T) {
	root := t.TempDir()
	consensusDir := filepath.Join(root, "consensus")
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	config := nodeTestRaftConfig()
	config.TrailingLogs = 0
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: consensusDir,
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   config,
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	waitForNodeLeader(t, node)
	first := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"pre-snapshot task",
	)
	if _, err := node.Apply(testContext(t), first); err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	if err := node.Snapshot(testContext(t)); err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	second := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID2,
		nodeTestTimestamp2,
		2,
		"first post-snapshot task",
	)
	third := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID3,
		nodeTestTaskID3,
		nodeTestTimestamp3,
		3,
		"second post-snapshot task",
	)
	if _, err := node.Apply(testContext(t), second); err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	if _, err := node.Apply(testContext(t), third); err != nil {
		t.Fatalf("Apply(third): %v", err)
	}
	secondLog := findCommandLog(t, node, second.CanonicalBytes())
	if err := node.shutdownRaft(); err != nil {
		t.Fatalf("shutdownRaft(): %v", err)
	}
	if err := node.stable.DeleteRange(
		secondLog.Index,
		secondLog.Index,
	); err != nil {
		t.Fatalf("DeleteRange(gap): %v", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	if _, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    filepath.Join(root, "state", "state.db"),
			ConsensusDir: consensusDir,
			OriginBootID: nodeTestBootID2,
			Clock:        nodeTestClock(),
			RaftConfig:   config,
		},
	); !errors.Is(err, ErrRaftLogCoverage) {
		t.Fatalf(
			"OpenSingleNode(gapped logs) error = %v, want ErrRaftLogCoverage",
			err,
		)
	}
}

func TestOpenRejectsMissingSnapshotForCompactedLogs(t *testing.T) {
	root := t.TempDir()
	consensusDir := filepath.Join(root, "consensus")
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	config := nodeTestRaftConfig()
	config.TrailingLogs = 0
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: consensusDir,
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   config,
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	waitForNodeLeader(t, node)
	first := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"pre-snapshot task",
	)
	if _, err := node.Apply(testContext(t), first); err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	if err := node.Snapshot(testContext(t)); err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	metas, err := node.snapshots.List()
	if err != nil || len(metas) == 0 {
		t.Fatalf("List() = (%v, %v), want a snapshot", metas, err)
	}
	second := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID2,
		nodeTestTimestamp2,
		2,
		"post-snapshot task",
	)
	if _, err := node.Apply(testContext(t), second); err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if err := os.RemoveAll(
		filepath.Join(consensusDir, "snapshots", metas[0].ID),
	); err != nil {
		t.Fatalf("RemoveAll(snapshot): %v", err)
	}

	if _, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    filepath.Join(root, "state", "state.db"),
			ConsensusDir: consensusDir,
			OriginBootID: nodeTestBootID2,
			Clock:        nodeTestClock(),
			RaftConfig:   config,
		},
	); !errors.Is(err, ErrRaftLogCoverage) {
		t.Fatalf(
			"OpenSingleNode(missing snapshot) error = %v, want ErrRaftLogCoverage",
			err,
		)
	}
}

func TestWaitForLeaderWaitsForRetainedCommandReplay(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "state.db")
	consensusDir := filepath.Join(root, "consensus")
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	failingClock := func() (domain.Timestamp, int64, error) {
		return "", 0, errors.New("injected apply failure")
	}
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    statePath,
		ConsensusDir: consensusDir,
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        failingClock,
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(first): %v", err)
	}
	waitForNodeLeader(t, node)
	signed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"retained replay task",
	)
	if _, err := node.Apply(
		testContext(t),
		signed,
	); !errors.Is(err, ErrFSMHalted) {
		t.Fatalf("Apply(failing clock) error = %v, want ErrFSMHalted", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}

	clockEntered := make(chan struct{})
	releaseClock := make(chan struct{})
	var clockOnce sync.Once
	replayClock := func() (domain.Timestamp, int64, error) {
		clockOnce.Do(func() { close(clockEntered) })
		<-releaseClock
		return "2026-08-11T13:00:00Z", 1, nil
	}
	restarted, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    statePath,
			ConsensusDir: consensusDir,
			OriginBootID: nodeTestBootID2,
			Clock:        replayClock,
			RaftConfig:   nodeTestRaftConfig(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(restart): %v", err)
	}
	t.Cleanup(func() {
		select {
		case <-releaseClock:
		default:
			close(releaseClock)
		}
		_ = restarted.Close()
	})
	restarted.addressMu.Lock()
	restarted.addressReconciled = true
	restarted.addressMu.Unlock()

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- restarted.WaitForLeader(testContext(t))
	}()
	select {
	case <-clockEntered:
	case err := <-waitDone:
		t.Fatalf("WaitForLeader() returned before replay: %v", err)
	case <-testContext(t).Done():
		t.Fatal("retained command did not begin replay")
	}
	select {
	case err := <-waitDone:
		t.Fatalf("WaitForLeader() returned during replay: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseClock)
	if err := <-waitDone; err != nil {
		t.Fatalf("WaitForLeader() after replay: %v", err)
	}
	view, err := restarted.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if !viewContainsTask(view, nodeTestTaskID1) {
		t.Fatal("WaitForLeader returned without applying retained command")
	}
}

func TestLookupCorruptionLatchesFatalNodeFailure(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "state.db")
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    statePath,
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	waitForNodeLeader(t, node)
	first := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"lookup task",
	)
	if _, err := node.Apply(testContext(t), first); err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	tamperSQLite(
		t,
		statePath,
		`UPDATE command_results
		    SET outcome_json = '{"code":"accepted","status":"accepted","x":1}'
		  WHERE result_index = 1;`,
	)
	if _, err := node.Apply(
		testContext(t),
		first,
	); !errors.Is(err, store.ErrCommandResultCorrupt) {
		t.Fatalf(
			"Apply(corrupt lookup) error = %v, want ErrCommandResultCorrupt",
			err,
		)
	}
	if !errors.Is(node.FatalError(), store.ErrCommandResultCorrupt) {
		t.Fatalf(
			"FatalError() = %v, want ErrCommandResultCorrupt",
			node.FatalError(),
		)
	}
}

func TestCommittedMalformedCommandHaltsSingleNodeFSM(t *testing.T) {
	root := t.TempDir()
	initial, _, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	waitForNodeLeader(t, node)

	future := node.raft.Apply([]byte(`{"not":"an event"}`), time.Second)
	if err := future.Error(); err != nil {
		t.Fatalf("Raft Apply(malformed) transport error: %v", err)
	}
	response, ok := future.Response().(ApplyResponse)
	if !ok || !errors.Is(response.Err, ErrFSMHalted) {
		t.Fatalf("malformed response = %#v", future.Response())
	}

	if !errors.Is(node.FatalError(), ErrFSMHalted) {
		t.Fatalf("FatalError() = %v, want ErrFSMHalted", node.FatalError())
	}
	view, err := node.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if view.Heads.ResultIndex != 0 || view.LastRaftAppliedLogIndex != nil {
		t.Fatalf("malformed command changed SQLite state: %#v", view)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close() after integrity halt: %v", err)
	}
	if !errors.Is(node.FatalError(), ErrFSMHalted) {
		t.Fatalf(
			"FatalError() after Close = %v, want ErrFSMHalted",
			node.FatalError(),
		)
	}
}

func TestCommittedVersionSkewHaltsBeforeRaftWatermark(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]json.RawMessage)
		want   error
	}{
		{
			name: "unknown kind",
			mutate: func(object map[string]json.RawMessage) {
				object["kind"] = json.RawMessage(`"task.future"`)
			},
			want: reducer.ErrKindNotImplemented,
		},
		{
			name: "unsupported apply level",
			mutate: func(object map[string]json.RawMessage) {
				object["kind"] = json.RawMessage(`"task.future"`)
				object["min_apply_level"] = json.RawMessage(`2`)
			},
			want: reducer.ErrApplyLevelUnsupported,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			initial, identityPrivate, deviceID := nodeTestInitialState(t)
			node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
				ServerID:     deviceID,
				StatePath:    filepath.Join(root, "state", "state.db"),
				ConsensusDir: filepath.Join(root, "consensus"),
				OriginBootID: nodeTestBootID1,
				InitialState: &initial,
				Clock:        nodeTestClock(),
				RaftConfig:   nodeTestRaftConfig(),
			})
			if err != nil {
				t.Fatalf("OpenSingleNode(): %v", err)
			}
			t.Cleanup(func() { _ = node.Close() })
			waitForNodeLeader(t, node)

			base := nodeTestTaskEvent(
				t,
				identityPrivate,
				deviceID,
				nodeTestBootID1,
				nodeTestEventID1,
				nodeTestTaskID1,
				nodeTestTimestamp1,
				1,
				"version skew",
			)
			command := nodeTestResignEvent(
				t,
				base.CanonicalBytes(),
				identityPrivate,
				test.mutate,
			)
			future := node.raft.Apply(command, time.Second)
			if err := future.Error(); err != nil {
				t.Fatalf("Raft Apply(version skew) transport error: %v", err)
			}
			response, ok := future.Response().(ApplyResponse)
			if !ok ||
				!errors.Is(response.Err, ErrFSMHalted) ||
				!errors.Is(response.Err, test.want) {
				t.Fatalf(
					"version-skew response = %#v, want ErrFSMHalted wrapping %v",
					future.Response(),
					test.want,
				)
			}
			view, err := node.View(context.Background())
			if err != nil {
				t.Fatalf("View(): %v", err)
			}
			if view.Heads.ResultIndex != 0 ||
				view.Heads.ChainIndex != 0 ||
				view.LastRaftAppliedLogIndex != nil {
				t.Fatalf("version-skew command changed SQLite state: %#v", view)
			}
		})
	}
}

func nodeTestInitialState(
	t *testing.T,
) (store.InitialState, ed25519.PrivateKey, domain.DeviceID) {
	t.Helper()

	identityPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x31}, ed25519.SeedSize),
	)
	identityPublic := append(
		ed25519.PublicKey(nil),
		identityPrivate.Public().(ed25519.PublicKey)...,
	)
	deviceID, err := device.DeriveID(identityPublic)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	member := device.Device{
		ID:                deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: identityPublic,
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	voterSet, err := voterset.New(
		nodeTestSessionID,
		[]domain.DeviceID{deviceID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	recoveryPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x71}, ed25519.SeedSize),
	)
	genesis := map[string]any{
		"recovery_generation": uint64(0),
		"recovery_public_key": codec.EncodeBase64URL(
			recoveryPrivate.Public().(ed25519.PublicKey),
		),
		"session_id":   string(nodeTestSessionID),
		"workspace_id": string(nodeTestWorkspaceID),
	}
	rawGenesis, err := json.Marshal(genesis)
	if err != nil {
		t.Fatalf("json.Marshal(genesis): %v", err)
	}
	genesisJSON, err := codec.CanonicalizeSignedObject(rawGenesis)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(genesis): %v", err)
	}

	canonicalRef := publication.CanonicalRef{
		RefName:       publication.CanonicalRefName,
		CommitOID:     domain.GitOID("sha1:" + strings.Repeat("1", 40)),
		EntityVersion: 1,
	}
	initial := store.InitialState{
		SessionID:               nodeTestSessionID,
		WorkspaceID:             nodeTestWorkspaceID,
		GenesisJSON:             genesisJSON,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
		Projections: store.ProjectionWrites{
			AuditCounters: []auditcounter.Counter{{
				DeviceID: deviceID,
			}},
			PlanCurrent: []plan.Current{{
				SessionID:     nodeTestSessionID,
				EntityVersion: 1,
			}},
			Devices:  []device.Device{member},
			VoterSet: []voterset.Set{voterSet},
			CredentialAuthority: []store.CredentialAuthorityRow{{
				SessionID:        nodeTestSessionID,
				VoterDeviceIDs:   []domain.DeviceID{deviceID},
				VoterSetVersion:  1,
				ActivationSource: credentialauthority.ActivationGenesis,
			}},
			CanonicalRefs: []publication.CanonicalRef{canonicalRef},
			SessionPolicy: []policy.Policy{{
				SessionID:     nodeTestSessionID,
				Values:        policy.DefaultValues(),
				EntityVersion: 1,
			}},
		},
	}
	return initial, identityPrivate, deviceID
}

type peerAdmissionTestFixture struct {
	node                 *SingleNode
	ownerIdentityPrivate ed25519.PrivateKey
	ownerDeviceID        domain.DeviceID
	peerIdentityPrivate  ed25519.PrivateKey
	peerDeviceID         domain.DeviceID
}

func openPeerAdmissionTestNode(t *testing.T) peerAdmissionTestFixture {
	t.Helper()
	initial, ownerPrivate, ownerID := nodeTestInitialState(t)
	peerPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x32}, ed25519.SeedSize),
	)
	peerPublic := bytes.Clone(peerPrivate.Public().(ed25519.PublicKey))
	peerID, err := device.DeriveID(peerPublic)
	if err != nil {
		t.Fatalf("device.DeriveID(peer): %v", err)
	}
	initial.Projections.Devices = append(
		initial.Projections.Devices,
		device.Device{
			ID:                peerID,
			Role:              device.RoleOwner,
			IdentityPublicKey: peerPublic,
			DaemonVersion:     "0.1.0",
			MaxApplyLevel:     1,
			Status:            device.StatusActive,
			EntityVersion:     1,
		},
	)
	initial.Projections.AuditCounters = append(
		initial.Projections.AuditCounters,
		auditcounter.Counter{DeviceID: peerID},
	)

	root := t.TempDir()
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     ownerID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(peer admission): %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	waitForNodeLeader(t, node)
	return peerAdmissionTestFixture{
		node:                 node,
		ownerIdentityPrivate: ownerPrivate,
		ownerDeviceID:        ownerID,
		peerIdentityPrivate:  peerPrivate,
		peerDeviceID:         peerID,
	}
}

type nodeTestCredentialEndorsementWire struct {
	AuthorityVoterSetVersion uint64 `json:"authority_voter_set_version"`
	Epoch                    uint64 `json:"epoch"`
	IssuedAt                 string `json:"issued_at"`
	KeyDigest                string `json:"key_digest"`
	SessionID                string `json:"session_id"`
	SubjectDeviceID          string `json:"subject_device_id"`
}

func nodeTestCredentialAuthorizationEvent(
	t *testing.T,
	fixture peerAdmissionTestFixture,
	sequence uint64,
) (
	event.SignedEvent,
	credentialauthorization.Authorization,
	ed25519.PrivateKey,
) {
	t.Helper()
	epochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x33}, ed25519.SeedSize),
	)
	binding, err := credential.SignBinding(
		nodeTestSessionID,
		fixture.peerDeviceID,
		1,
		epochPrivate.Public().(ed25519.PublicKey),
		fixture.peerIdentityPrivate,
	)
	if err != nil {
		t.Fatalf("credential.SignBinding(): %v", err)
	}
	authorization := credentialauthorization.Authorization{
		SessionID:                nodeTestSessionID,
		DeviceID:                 fixture.peerDeviceID,
		Epoch:                    1,
		EpochPublicKey:           binding.EpochPublicKey,
		KeyDigest:                binding.KeyDigest,
		Role:                     credentialauthorization.RoleOwner,
		IssuedAt:                 "2026-08-14T12:00:00Z",
		NotBefore:                "2026-08-14T12:00:00Z",
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		BindingSignature:         binding.Signature,
		AuthorizationChainIndex:  1,
	}
	endorsementJSON, err := json.Marshal(nodeTestCredentialEndorsementWire{
		AuthorityVoterSetVersion: authorization.AuthorityVoterSetVersion,
		Epoch:                    authorization.Epoch,
		IssuedAt:                 string(authorization.IssuedAt),
		KeyDigest: codec.EncodeBase64URL(
			authorization.KeyDigest[:],
		),
		SessionID:       string(authorization.SessionID),
		SubjectDeviceID: string(authorization.DeviceID),
	})
	if err != nil {
		t.Fatalf("json.Marshal(credential endorsement): %v", err)
	}
	endorsementPreimage, err := codec.CanonicalizeSignedObject(
		endorsementJSON,
	)
	if err != nil {
		t.Fatalf("canonicalize credential endorsement: %v", err)
	}
	endorsementSignature, err := codecommcrypto.SignEd25519(
		fixture.ownerIdentityPrivate,
		codec.SignatureCredentialTimeEndorsement,
		endorsementPreimage,
	)
	if err != nil {
		t.Fatalf("sign credential endorsement: %v", err)
	}
	endorsement := credentialauthorization.ClockEndorsement{
		DeviceID: fixture.ownerDeviceID,
	}
	copy(endorsement.Signature[:], endorsementSignature)
	authorization.ClockEndorsements = []credentialauthorization.ClockEndorsement{
		endorsement,
	}
	if err := authorization.Validate(); err != nil {
		t.Fatalf("credential authorization fixture: %v", err)
	}

	payload := map[string]any{
		"subject_device_id": authorization.DeviceID,
		"epoch_public_key": codec.EncodeBase64URL(
			authorization.EpochPublicKey[:],
		),
		"key_digest": codec.EncodeBase64URL(
			authorization.KeyDigest[:],
		),
		"epoch":                       authorization.Epoch,
		"role":                        authorization.Role,
		"issued_at":                   authorization.IssuedAt,
		"not_before":                  authorization.NotBefore,
		"validity_seconds":            authorization.ValiditySeconds,
		"authority_voter_set_version": authorization.AuthorityVoterSetVersion,
		"clock_endorsements": []map[string]any{{
			"device_id": endorsement.DeviceID,
			"signature": codec.EncodeBase64URL(
				endorsement.Signature[:],
			),
		}},
		"binding_signature": codec.EncodeBase64URL(
			authorization.BindingSignature[:],
		),
	}
	signed := nodeTestSignedCommand(
		t,
		fixture.ownerIdentityPrivate,
		fixture.ownerDeviceID,
		event.ActorDaemon,
		event.KindCredentialAuthorized,
		fixture.peerDeviceID,
		nil,
		payload,
		nodeTestEventID4,
		sequence,
	)
	return signed, authorization, epochPrivate
}

func nodeTestMembershipEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	originDeviceID domain.DeviceID,
	kind event.Kind,
	subjectDeviceID domain.DeviceID,
	expectedVersion uint64,
	payload map[string]any,
	eventID domain.UUIDv7,
	sequence uint64,
) event.SignedEvent {
	t.Helper()
	return nodeTestSignedCommand(
		t,
		privateKey,
		originDeviceID,
		event.ActorHuman,
		kind,
		subjectDeviceID,
		&expectedVersion,
		payload,
		eventID,
		sequence,
	)
}

func nodeTestSignedCommand(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	originDeviceID domain.DeviceID,
	actor event.ActorType,
	kind event.Kind,
	subjectDeviceID domain.DeviceID,
	expectedVersion *uint64,
	payload any,
	eventID domain.UUIDv7,
	sequence uint64,
) event.SignedEvent {
	t.Helper()
	authority, err := event.NewLocalAuthority(
		originDeviceID,
		nodeTestBootID1,
	)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority(): %v", err)
	}
	var binding event.Binding
	switch actor {
	case event.ActorHuman:
		binding, err = authority.OperatorBinding()
	case event.ActorDaemon:
		binding, err = authority.DaemonBinding()
	default:
		t.Fatalf("unsupported actor %q", actor)
	}
	if err != nil {
		t.Fatalf("event binding: %v", err)
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal(command payload): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:                  kind,
			EntityID:              event.StringEntityID(string(subjectDeviceID)),
			ExpectedEntityVersion: expectedVersion,
			Actions:               []event.Action{},
			Payload:               encodedPayload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      nodeTestSessionID,
			WorkspaceID:    nodeTestWorkspaceID,
			CreatedAt:      nodeTestTimestamp1,
			OriginSequence: sequence,
		},
	)
	if err != nil {
		t.Fatalf("event.BuildProposal(%s): %v", kind, err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign(%s): %v", kind, err)
	}
	return signed
}

func awaitPeerAdmissionChange(
	t *testing.T,
	changes <-chan struct{},
	description string,
) {
	t.Helper()
	select {
	case <-changes:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s admission change", description)
	}
}

type peerAdmissionIngress struct {
	address             string
	ownerDeviceID       domain.DeviceID
	ownerIdentityPublic ed25519.PublicKey
	serverAuthorization credentialauthorization.Authorization
	entered             chan transport.AuthenticatedPeer
	canceled            chan transport.AuthenticatedPeer
}

func startPeerAdmissionTestIngress(
	t *testing.T,
	fixture peerAdmissionTestFixture,
	verifiers *peerauth.Verifiers,
	changes <-chan struct{},
) *peerAdmissionIngress {
	t.Helper()
	serverIdentity, _, err := transport.IssueIdentityCertificate(
		nodeTestSessionID,
		0,
		fixture.ownerIdentityPrivate,
	)
	if err != nil {
		t.Fatalf("IssueIdentityCertificate(server): %v", err)
	}
	serverEpochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x34}, ed25519.SeedSize),
	)
	serverBinding, err := credential.SignBinding(
		nodeTestSessionID,
		fixture.ownerDeviceID,
		1,
		serverEpochPrivate.Public().(ed25519.PublicKey),
		fixture.ownerIdentityPrivate,
	)
	if err != nil {
		t.Fatalf("credential.SignBinding(server): %v", err)
	}
	serverAuthorization := credentialauthorization.Authorization{
		SessionID:                nodeTestSessionID,
		DeviceID:                 fixture.ownerDeviceID,
		Epoch:                    1,
		EpochPublicKey:           serverBinding.EpochPublicKey,
		KeyDigest:                serverBinding.KeyDigest,
		Role:                     credentialauthorization.RoleOwner,
		IssuedAt:                 "2026-08-14T12:00:00Z",
		NotBefore:                "2026-08-14T12:00:00Z",
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{{
			DeviceID: fixture.ownerDeviceID,
		}},
		BindingSignature:        serverBinding.Signature,
		AuthorizationChainIndex: 1,
	}
	serverContent, _, err := transport.IssueContentCertificate(
		serverAuthorization,
		serverEpochPrivate,
	)
	if err != nil {
		t.Fatalf("IssueContentCertificate(server): %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for peer ingress: %v", err)
	}
	entered := make(chan transport.AuthenticatedPeer, 2)
	canceled := make(chan transport.AuthenticatedPeer, 2)
	handler := transport.ConnectionHandlerFunc(func(
		ctx context.Context,
		_ *tls.Conn,
	) error {
		peer, ok := transport.AuthenticatedPeerFromContext(ctx)
		if !ok {
			return errors.New("authenticated peer context missing")
		}
		entered <- peer
		<-ctx.Done()
		canceled <- peer
		return ctx.Err()
	})
	ingress, err := transport.NewIngress(transport.IngressOptions{
		Listener: listener,
		TLS: transport.ServerTLSOptions{
			IdentityCertificate: serverIdentity,
			ContentCertificate: func() (tls.Certificate, error) {
				return serverContent, nil
			},
			VerifyPairingPeer:   verifiers.VerifyPairingPeer,
			VerifyConsensusPeer: verifiers.VerifyConsensusPeer,
			VerifyContentPeer:   verifiers.VerifyContentPeer,
		},
		PeerAccessChanges: changes,
		Consensus:         handler,
		Content:           handler,
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("transport.NewIngress(): %v", err)
	}
	serveContext, cancelServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ingress.Serve(serveContext)
	}()
	t.Cleanup(func() {
		cancelServe()
		shutdownContext, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()
		if err := ingress.Shutdown(shutdownContext); err != nil {
			t.Errorf("Ingress.Shutdown(): %v", err)
		}
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("Ingress.Serve(): %v", err)
			}
		case <-shutdownContext.Done():
			t.Errorf("Ingress.Serve() did not stop: %v", shutdownContext.Err())
		}
	})
	return &peerAdmissionIngress{
		address:       listener.Addr().String(),
		ownerDeviceID: fixture.ownerDeviceID,
		ownerIdentityPublic: bytes.Clone(
			fixture.ownerIdentityPrivate.Public().(ed25519.PublicKey),
		),
		serverAuthorization: serverAuthorization,
		entered:             entered,
		canceled:            canceled,
	}
}

func (ingress *peerAdmissionIngress) dial(
	t *testing.T,
	plane transport.Plane,
	certificate tls.Certificate,
) *tls.Conn {
	t.Helper()
	options := transport.ClientTLSOptions{
		Plane:       plane,
		Certificate: certificate,
	}
	switch plane {
	case transport.PlaneConsensus:
		options.VerifyIdentityPeer = func(
			certificate transport.IdentityCertificate,
		) error {
			return certificate.VerifyIdentity(
				nodeTestSessionID,
				0,
				ingress.ownerDeviceID,
				ingress.ownerIdentityPublic,
			)
		}
	case transport.PlaneContent:
		options.VerifyContentPeer = func(
			certificate transport.ContentCertificate,
		) (transport.ContentPeerAdmission, error) {
			now := time.Date(2026, 8, 14, 12, 5, 0, 0, time.UTC)
			if err := certificate.VerifyAuthorization(
				ingress.serverAuthorization,
				now,
			); err != nil {
				return transport.ContentPeerAdmission{}, err
			}
			closeAfter, err := certificate.CloseAfter(now)
			return transport.ContentPeerAdmission{
				CloseAfter: closeAfter,
			}, err
		}
	default:
		t.Fatalf("unsupported peer-admission test plane %q", plane)
	}
	tlsConfig, err := transport.NewClientTLSConfig(options)
	if err != nil {
		t.Fatalf("transport.NewClientTLSConfig(%s): %v", plane, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(
		ctx,
		"tcp",
		ingress.address,
	)
	if err != nil {
		t.Fatalf("dial peer ingress: %v", err)
	}
	connection := tls.Client(raw, tlsConfig)
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		t.Fatalf("TLS handshake (%s): %v", plane, err)
	}
	return connection
}

func assertPeerTLSClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set peer read deadline: %v", err)
	}
	var buffer [1]byte
	if _, err := connection.Read(buffer[:]); err == nil {
		t.Fatal("revoked peer connection remained open")
	} else {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			t.Fatalf("revoked peer connection did not close: %v", err)
		}
	}
}

func openApplyAtGenerationTestNode(
	t *testing.T,
) (*SingleNode, ed25519.PrivateKey, domain.DeviceID) {
	t.Helper()
	root := t.TempDir()
	initial, identityPrivate, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	waitForNodeLeader(t, node)
	return node, identityPrivate, deviceID
}

func assertApplyAtGenerationDidNotAdvance(
	t *testing.T,
	node *SingleNode,
	before store.StateView,
	eventID domain.UUIDv7,
) {
	t.Helper()
	after, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(after): %v", err)
	}
	if after.Heads != before.Heads ||
		!sameOptionalUint64(
			after.LastRaftAppliedLogIndex,
			before.LastRaftAppliedLogIndex,
		) {
		t.Fatalf(
			"failed ApplyAtGeneration() advanced state:\nbefore: %#v\nafter:  %#v",
			before,
			after,
		)
	}
	lookup, found, err := node.state.LookupCommandResult(
		testContext(t),
		eventID,
	)
	if err != nil {
		t.Fatalf("LookupCommandResult(): %v", err)
	}
	if found {
		t.Fatalf("LookupCommandResult() = %#v, true; want no result", lookup)
	}
}

func sameOptionalUint64(left, right *uint64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func nodeTestTaskEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
	bootID domain.UUIDv7,
	eventID domain.UUIDv7,
	taskID domain.UUIDv7,
	createdAt domain.Timestamp,
	sequence uint64,
	title string,
) event.SignedEvent {
	t.Helper()

	authority, err := event.NewLocalAuthority(deviceID, bootID)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority(): %v", err)
	}
	binding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatalf("OperatorBinding(): %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"priority": 2,
		"title":    title,
	})
	if err != nil {
		t.Fatalf("json.Marshal(task payload): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindTaskCreated,
			EntityID: event.StringEntityID(string(taskID)),
			Actions:  []event.Action{},
			Payload:  payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      nodeTestSessionID,
			WorkspaceID:    nodeTestWorkspaceID,
			CreatedAt:      createdAt,
			OriginSequence: sequence,
		},
	)
	if err != nil {
		t.Fatalf("event.BuildProposal(): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign(): %v", err)
	}
	return signed
}

func nodeTestResignEvent(
	t *testing.T,
	complete []byte,
	privateKey ed25519.PrivateKey,
	mutate func(map[string]json.RawMessage),
) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(complete, &object); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	delete(object, "origin_signature")
	mutate(object)
	bodyJSON, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal mutated event body: %v", err)
	}
	body, err := codec.CanonicalizeSignedObject(bodyJSON)
	if err != nil {
		t.Fatalf("canonicalize mutated event body: %v", err)
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureEventOrigin,
		body,
	)
	if err != nil {
		t.Fatalf("sign mutated event body: %v", err)
	}
	signatureJSON, err := json.Marshal(codec.EncodeBase64URL(signature))
	if err != nil {
		t.Fatalf("marshal mutated event signature: %v", err)
	}
	object["origin_signature"] = signatureJSON
	completeJSON, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal mutated event: %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(completeJSON)
	if err != nil {
		t.Fatalf("canonicalize mutated event: %v", err)
	}
	return canonical
}

func nodeTestClock() ApplyClock {
	var calls atomic.Int64
	return func() (domain.Timestamp, int64, error) {
		call := calls.Add(1)
		return domain.Timestamp(
			fmt.Sprintf("2026-08-11T13:00:%02dZ", call),
		), call * int64(time.Second), nil
	}
}

func nodeTestRaftConfig() *raft.Config {
	config := raft.DefaultConfig()
	config.HeartbeatTimeout = 500 * time.Millisecond
	config.ElectionTimeout = 500 * time.Millisecond
	config.CommitTimeout = 10 * time.Millisecond
	config.LeaderLeaseTimeout = 250 * time.Millisecond
	config.SnapshotInterval = time.Hour
	config.SnapshotThreshold = 1_000
	config.TrailingLogs = 32
	config.LogLevel = "ERROR"
	return config
}

func waitForNodeLeader(t *testing.T, node *SingleNode) {
	t.Helper()
	if err := node.WaitForLeader(testContext(t)); err != nil {
		t.Fatalf("WaitForLeader(): %v", err)
	}
}

func assertNodeUsesLocalAddress(t *testing.T, node *SingleNode) {
	t.Helper()
	future := node.raft.GetConfiguration()
	if err := waitFuture(testContext(t), future); err != nil {
		t.Fatalf("GetConfiguration(): %v", err)
	}
	configuration := future.Configuration()
	if len(configuration.Servers) != 1 ||
		configuration.Servers[0].ID != node.serverID ||
		configuration.Servers[0].Suffrage != raft.Voter ||
		configuration.Servers[0].Address != node.Address() {
		t.Fatalf(
			"configuration = %#v, local address = %q",
			configuration,
			node.Address(),
		)
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func viewContainsTask(view store.StateView, taskID domain.UUIDv7) bool {
	for _, row := range view.ProjectionRows {
		if row.Table == "tasks" &&
			bytes.Contains(
				row.Row,
				[]byte(`"task_id":"`+string(taskID)+`"`),
			) {
			return true
		}
	}
	return false
}

func findCommandLog(
	t *testing.T,
	node *SingleNode,
	canonical []byte,
) raft.Log {
	t.Helper()
	first, err := node.stable.FirstIndex()
	if err != nil {
		t.Fatalf("FirstIndex(): %v", err)
	}
	last, err := node.stable.LastIndex()
	if err != nil {
		t.Fatalf("LastIndex(): %v", err)
	}
	for index := first; index <= last; index++ {
		var entry raft.Log
		if err := node.stable.GetLog(index, &entry); err != nil {
			t.Fatalf("GetLog(%d): %v", index, err)
		}
		if entry.Type == raft.LogCommand &&
			bytes.Equal(entry.Data, canonical) {
			return entry
		}
	}
	t.Fatal("command is absent from retained Raft logs")
	return raft.Log{}
}

func tamperSQLite(t *testing.T, path, statement string) {
	t.Helper()
	conn, err := sqlite.OpenConn(path, sqlite.OpenReadWrite)
	if err != nil {
		t.Fatalf("sqlite.OpenConn(): %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("sqlite.Close(): %v", err)
		}
	}()
	if err := sqlitex.Execute(conn, statement, nil); err != nil {
		t.Fatalf("tamper SQLite: %v", err)
	}
}

func sameNodeCommitmentHeads(left, right store.ApplyHeads) bool {
	return left.ChainIndex == right.ChainIndex &&
		left.ChainHash == right.ChainHash &&
		left.ResultIndex == right.ResultIndex &&
		left.ResultHash == right.ResultHash &&
		left.ProjectionAccumulator == right.ProjectionAccumulator &&
		left.DigestVersion == right.DigestVersion &&
		left.ProjectionSchemaVersion == right.ProjectionSchemaVersion
}
