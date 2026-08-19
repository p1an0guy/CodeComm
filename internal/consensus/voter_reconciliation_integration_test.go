package consensus

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/voteractivation"
)

const (
	secureMeshVoterReconciliationChild = "voter-reconciliation"
	secureMeshMinoritySecurityChild    = "minority-security"
)

var (
	meshMinorityMarkerEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8a23-5023456789ab",
	)
	meshMinorityMarkerTaskID = domain.UUIDv7(
		"018f47de-89ab-7def-8b23-5123456789ab",
	)
	meshMinorityMarkerTimestamp = domain.Timestamp(
		"2026-08-11T12:04:00Z",
	)
)

func TestSecureMeshVoterReconciliationTransitions(t *testing.T) {
	if secureMeshRunsInProcess() ||
		os.Getenv(secureMeshChild) == secureMeshVoterReconciliationChild {
		runSecureMeshVoterReconciliationTransitions(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestSecureMeshVoterReconciliationTransitions$",
		"-test.count=1",
	)
	command.Env = secureMeshChildEnvironmentWithMode(
		os.Environ(),
		secureMeshVoterReconciliationChild,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("voter-reconciliation child timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("voter-reconciliation child failed: %v\n%s", err, output)
	}
}

func TestSecureMeshIsolatedMinorityCannotEscalate(t *testing.T) {
	if secureMeshRunsInProcess() ||
		os.Getenv(secureMeshChild) == secureMeshMinoritySecurityChild {
		runSecureMeshIsolatedMinorityCannotEscalate(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestSecureMeshIsolatedMinorityCannotEscalate$",
		"-test.count=1",
	)
	command.Env = secureMeshChildEnvironmentWithMode(
		os.Environ(),
		secureMeshMinoritySecurityChild,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("minority-security child timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("minority-security child failed: %v\n%s", err, output)
	}
}

func runSecureMeshIsolatedMinorityCannotEscalate(t *testing.T) {
	harness := newSecureMeshHarnessWithManualReconciliation(t, true)
	defer harness.close(t)

	isolated := harness.waitForLeader(t, harness.runningNodes())
	all := harness.runningNodes()
	harness.waitForCommittedConfiguration(t, all)
	harness.issueCurrentCredentials(t, isolated)
	harness.applyVoterTarget(
		t,
		isolated,
		[]domain.DeviceID{isolated.identity.deviceID},
		1,
	)
	harness.waitForVoterTarget(
		t,
		all,
		[]domain.DeviceID{isolated.identity.deviceID},
		2,
	)
	for _, candidate := range all {
		if !secureMeshConfigurationEquals(candidate, harness.bootstrap) {
			t.Fatalf(
				"configuration on %s = %#v, want voters %v",
				candidate.identity.deviceID,
				candidate.node.fsm.committedConfiguration(),
				harness.bootstrap,
			)
		}
		assertSecureMeshAuthority(t, candidate, harness.bootstrap, 1)
	}

	before, err := isolated.node.state.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("minority state before partition: %v", err)
	}
	beforeConfiguration := isolated.node.fsm.committedConfiguration()
	if beforeConfiguration == nil {
		t.Fatal("minority has no committed configuration before partition")
	}
	beforeLastIndex, err := isolated.node.stable.LastIndex()
	if err != nil {
		t.Fatalf("minority LastIndex before partition: %v", err)
	}
	beforeCredentialRows := secureMeshProjectionRows(
		before,
		"credential_authorizations",
	)
	if len(beforeCredentialRows) != len(harness.nodes) {
		t.Fatalf(
			"credential rows before partition = %d, want %d",
			len(beforeCredentialRows),
			len(harness.nodes),
		)
	}

	awaitMeshCondition(
		t,
		10*time.Second,
		"established connection to minority",
		func() bool {
			return harness.topology.activeConnectionCount(
				isolated.identity.deviceID,
			) > 0
		},
	)
	selfLeadership := make(chan raft.Observation, 1)
	selfObserver := raft.NewObserver(
		selfLeadership,
		false,
		func(observation *raft.Observation) bool {
			leader, ok := observation.Data.(raft.LeaderObservation)
			return ok &&
				leader.LeaderID == raft.ServerID(isolated.identity.deviceID)
		},
	)
	isolated.node.raft.RegisterObserver(selfObserver)
	defer isolated.node.raft.DeregisterObserver(selfObserver)

	if closed := harness.topology.setPartition(
		isolated.identity.deviceID,
		true,
	); closed == 0 {
		t.Fatal("minority partition closed no established connections")
	}
	if got := harness.topology.activeConnectionCount(
		isolated.identity.deviceID,
	); got != 0 {
		t.Fatalf("minority retained %d established connections", got)
	}
	if _, allowed := harness.topology.resolve(
		harness.nodes[0].identity.deviceID,
		isolated.fakeEndpoint,
	); allowed {
		t.Fatal("minority remained dialable after partition")
	}

	majority := make([]*secureMeshNode, 0, len(all)-1)
	for _, candidate := range all {
		if candidate != isolated {
			majority = append(majority, candidate)
		}
	}
	replacement := harness.waitForLeader(t, majority)
	if replacement == isolated {
		t.Fatal("isolated node remained the cluster leader")
	}
	awaitMeshCondition(
		t,
		5*time.Second,
		"isolated node to relinquish leadership",
		func() bool {
			return !isolated.node.IsLeader() &&
				isolated.node.raft.State() != raft.Leader
		},
	)

	renewal, authorization := harness.credentialRenewalEvent(
		t,
		isolated,
		isolated,
		0xe1,
	)
	applyContext, cancelApply := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	result, applyErr := isolated.node.Apply(applyContext, renewal)
	cancelApply()
	harness.nodes[0].nextSequence--
	if !errors.Is(applyErr, raft.ErrNotLeader) {
		t.Fatalf(
			"isolated credential Apply() = (%#v, %v), want raft.ErrNotLeader",
			result,
			applyErr,
		)
	}

	securityDeadline := time.Now().Add(
		4 * secureMeshRaftConfig().ElectionTimeout,
	)
	for attempt := 1; attempt <= 3; attempt++ {
		reconcileContext, cancelReconcile := context.WithTimeout(
			context.Background(),
			2*time.Second,
		)
		reconcileErr := isolated.node.ReconcileVoterSet(reconcileContext)
		cancelReconcile()
		if !errors.Is(reconcileErr, raft.ErrNotLeader) {
			t.Fatalf(
				"isolated ReconcileVoterSet attempt %d error = %v, want raft.ErrNotLeader",
				attempt,
				reconcileErr,
			)
		}
		assertSecureMeshNeverLed(t, isolated, selfLeadership)
		time.Sleep(secureMeshRaftConfig().ElectionTimeout)
	}
	for time.Now().Before(securityDeadline) {
		assertSecureMeshNeverLed(t, isolated, selfLeadership)
		time.Sleep(20 * time.Millisecond)
	}

	after, err := isolated.node.state.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("minority state after rejected operations: %v", err)
	}
	afterConfiguration := isolated.node.fsm.committedConfiguration()
	afterLastIndex, err := isolated.node.stable.LastIndex()
	if err != nil {
		t.Fatalf("minority LastIndex after rejected operations: %v", err)
	}
	if before.Heads != after.Heads ||
		before.ProjectionStateDigest != after.ProjectionStateDigest ||
		!reflect.DeepEqual(before.ProjectionRows, after.ProjectionRows) ||
		!reflect.DeepEqual(beforeConfiguration, afterConfiguration) ||
		beforeLastIndex != afterLastIndex {
		t.Fatal("isolated minority changed durable state or configuration")
	}
	assertSecureMeshAuthority(t, isolated, harness.bootstrap, 1)
	harness.assertCredentialAbsent(t, isolated, authorization)
	if err := isolated.node.FatalError(); err != nil {
		t.Fatalf("isolated node fatal error: %v", err)
	}

	marker := harness.taskEvent(
		t,
		replacement,
		meshMinorityMarkerEventID,
		meshMinorityMarkerTaskID,
		meshMinorityMarkerTimestamp,
		"majority marker while minority is isolated",
	)
	markerResult, err := replacement.node.Apply(meshTestContext(t), marker)
	if err != nil ||
		markerResult.Outcome.Status != store.OutcomeAccepted ||
		markerResult.Outcome.Code != string(reducer.CodeAccepted) {
		t.Fatalf("majority marker Apply() = (%#v, %v)", markerResult, err)
	}
	harness.waitForTask(t, majority, meshMinorityMarkerTaskID)
	isolatedView, err := isolated.node.state.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("isolated View(marker): %v", err)
	}
	if viewContainsTask(isolatedView, meshMinorityMarkerTaskID) {
		t.Fatal("isolated minority received the majority marker")
	}

	harness.topology.setPartition(isolated.identity.deviceID, false)
	harness.waitForTask(t, all, meshMinorityMarkerTaskID)
	assertMeshViewsConverged(t, all)
	for _, candidate := range all {
		view, err := candidate.node.state.View(meshTestContext(t))
		if err != nil {
			t.Fatalf("post-heal View(%s): %v", candidate.identity.deviceID, err)
		}
		if rows := secureMeshProjectionRows(
			view,
			"credential_authorizations",
		); !reflect.DeepEqual(rows, beforeCredentialRows) {
			t.Fatalf(
				"credential rows changed on %s after healing",
				candidate.identity.deviceID,
			)
		}
		harness.assertCredentialAbsent(t, candidate, authorization)
	}
}

func runSecureMeshVoterReconciliationTransitions(t *testing.T) {
	harness := newSecureMeshHarnessWithManualReconciliation(t, true)
	defer harness.close(t)

	leader := harness.waitForLeader(t, harness.runningNodes())
	harness.waitForCommittedConfiguration(t, harness.runningNodes())
	harness.issueCurrentCredentials(t, leader)
	assertSecureMeshReconciliationCapabilities(t, leader)

	var coverageCalls atomic.Uint64
	harness.coverage.afterCollect = func() {
		coverageCalls.Add(1)
	}

	firstTarget := leader
	var unreachable, secondTarget *secureMeshNode
	for _, candidate := range harness.nodes {
		if candidate == firstTarget {
			continue
		}
		if unreachable == nil {
			unreachable = candidate
			secondTarget = candidate
		}
	}
	if unreachable == nil || secondTarget == nil {
		t.Fatal("secure mesh has no extra voter")
	}

	harness.topology.setPartition(unreachable.identity.deviceID, true)
	if _, allowed := harness.topology.resolve(
		firstTarget.identity.deviceID,
		unreachable.fakeEndpoint,
	); allowed {
		t.Fatal("unreachable extra voter remained dialable")
	}
	harness.applyVoterTarget(
		t,
		firstTarget,
		[]domain.DeviceID{firstTarget.identity.deviceID},
		1,
	)
	reconcileSecureMeshUntil(
		t,
		firstTarget,
		"unreachable-extra 3-to-1 reconciliation",
		func() bool {
			return secureMeshConfigurationEquals(
				firstTarget,
				[]domain.DeviceID{firstTarget.identity.deviceID},
			) && secureMeshAuthorityEquals(
				firstTarget,
				[]domain.DeviceID{firstTarget.identity.deviceID},
				2,
			)
		},
	)
	assertSecureMeshVoterConfiguration(
		t,
		firstTarget,
		[]domain.DeviceID{firstTarget.identity.deviceID},
	)
	assertSecureMeshActivatedAuthority(
		t,
		firstTarget,
		[]domain.DeviceID{firstTarget.identity.deviceID},
		2,
	)

	harness.topology.setPartition(unreachable.identity.deviceID, false)
	harness.applyVoterTarget(
		t,
		firstTarget,
		[]domain.DeviceID{secondTarget.identity.deviceID},
		2,
	)
	reconcileSecureMeshUntil(
		t,
		firstTarget,
		"A-to-B promotion, activation, and leadership transfer",
		func() bool {
			return secondTarget.node.IsLeader() &&
				secureMeshAuthorityEquals(
					secondTarget,
					[]domain.DeviceID{secondTarget.identity.deviceID},
					3,
				)
		},
	)
	transferred := harness.waitForLeader(t, harness.runningNodes())
	if transferred != secondTarget {
		t.Fatalf(
			"leadership transferred to %s, want %s",
			transferred.identity.deviceID,
			secondTarget.identity.deviceID,
		)
	}
	assertSecureMeshVoterConfiguration(
		t,
		secondTarget,
		[]domain.DeviceID{
			firstTarget.identity.deviceID,
			secondTarget.identity.deviceID,
		},
	)
	assertSecureMeshActivatedAuthority(
		t,
		secondTarget,
		[]domain.DeviceID{secondTarget.identity.deviceID},
		3,
	)

	restarted := []*secureMeshNode{firstTarget, secondTarget}
	for _, candidate := range restarted {
		harness.stopNode(t, candidate)
	}
	commitProbeRelease := make(chan struct{})
	commitProbeReleased := false
	releaseCommitProbe := func() {
		if !commitProbeReleased {
			close(commitProbeRelease)
			commitProbeReleased = true
		}
	}
	defer releaseCommitProbe()
	for _, candidate := range restarted {
		candidate.commitProbeRelease = commitProbeRelease
		harness.startNode(t, candidate, false)
		candidate.commitProbeRelease = nil
	}

	var (
		coldLeader    *secureMeshNode
		coldLastIndex uint64
	)
	awaitMeshCondition(
		t,
		15*time.Second,
		"cold leader with blocked commit recovery",
		func() bool {
			for _, candidate := range restarted {
				if candidate.node == nil ||
					candidate.node.raft.State() != raft.Leader ||
					candidate.node.raft.CommitIndex() != 0 {
					continue
				}
				lastIndex, err := candidate.node.stable.LastIndex()
				if err != nil || lastIndex == 0 {
					continue
				}
				var entry raft.Log
				if err := candidate.node.stable.GetLog(
					lastIndex,
					&entry,
				); err != nil || entry.Type != raft.LogNoop {
					continue
				}
				coldLeader = candidate
				coldLastIndex = lastIndex
				return true
			}
			return false
		},
	)
	attemptContext, cancelAttempt := context.WithCancel(
		context.Background(),
	)
	attemptDone := make(chan error, 1)
	go func() {
		attemptDone <- coldLeader.node.ReconcileVoterSet(
			attemptContext,
		)
	}()
	awaitMeshCondition(
		t,
		time.Second,
		"cold reconciliation attempt",
		func() bool {
			return len(coldLeader.node.voterReconcileGate) == 1
		},
	)
	time.Sleep(5 * raftCommitRecoveryPollInterval)
	select {
	case err := <-attemptDone:
		t.Fatalf(
			"cold reconciliation returned before commit recovery: %v",
			err,
		)
	default:
	}
	lastIndex, lastErr := coldLeader.node.stable.LastIndex()
	if lastErr != nil {
		t.Fatalf("LastIndex(cold reconciliation): %v", lastErr)
	}
	for index := coldLastIndex + 1; index <= lastIndex; index++ {
		var entry raft.Log
		if err := coldLeader.node.stable.GetLog(
			index,
			&entry,
		); err != nil {
			t.Fatalf("GetLog(cold reconciliation %d): %v", index, err)
		}
		if entry.Type != raft.LogNoop {
			t.Fatalf(
				"cold reconciliation appended %s at %d before commit recovery",
				entry.Type,
				index,
			)
		}
	}
	cancelAttempt()
	if err := <-attemptDone; !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"canceled cold reconciliation error = %v, want context.Canceled",
			err,
		)
	}
	releaseCommitProbe()
	reconcileSecureMeshClusterUntil(
		t,
		harness,
		"post-restart removal",
		func() bool {
			return secondTarget.node.IsLeader() &&
				secureMeshConfigurationEquals(
					secondTarget,
					[]domain.DeviceID{secondTarget.identity.deviceID},
				)
		},
	)
	assertSecureMeshVoterConfiguration(
		t,
		secondTarget,
		[]domain.DeviceID{secondTarget.identity.deviceID},
	)
	assertSecureMeshActivatedAuthority(
		t,
		secondTarget,
		[]domain.DeviceID{secondTarget.identity.deviceID},
		3,
	)
	if got := coverageCalls.Load(); got < 6 {
		t.Fatalf("canonical coverage collections = %d, want at least 6", got)
	}

	var stalledTarget *secureMeshNode
	for _, candidate := range harness.nodes {
		if candidate == firstTarget || candidate == secondTarget {
			continue
		}
		stalledTarget = candidate
		break
	}
	if stalledTarget == nil {
		t.Fatal("secure mesh lacks a stalled target")
	}
	statusTime := time.Now()
	secondTarget.node.voterReconcileNow = func() time.Time {
		return statusTime
	}
	harness.topology.setPartition(stalledTarget.identity.deviceID, true)
	harness.applyVoterTarget(
		t,
		secondTarget,
		[]domain.DeviceID{stalledTarget.identity.deviceID},
		3,
	)
	err := secondTarget.node.ReconcileVoterSet(
		secureMeshReconciliationContext(t),
	)
	if !errors.Is(err, ErrVoterReconciliationStalled) {
		t.Fatalf("unreachable target reconciliation error = %v", err)
	}
	assertSecureMeshAuthority(
		t,
		secondTarget,
		[]domain.DeviceID{secondTarget.identity.deviceID},
		3,
	)
	statusTime = statusTime.Add(voterReconciliationDeadline)
	err = secondTarget.node.ReconcileVoterSet(
		secureMeshReconciliationContext(t),
	)
	if !errors.Is(err, ErrVoterReconciliationStalled) {
		t.Fatalf("repeated stalled reconciliation error = %v", err)
	}
	status, err := secondTarget.node.Status(
		secureMeshReconciliationContext(t),
	)
	if err != nil {
		t.Fatalf("Status(stalled reconciliation): %v", err)
	}
	blocker := status.Runtime.ReconciliationBlocker
	if status.Runtime.ReconciliationState !=
		coordstatus.ReconciliationReconciling ||
		blocker != coordstatus.ReconciliationBlockerTargetUnavailable &&
			blocker != coordstatus.ReconciliationBlockerProofUnavailable ||
		status.Runtime.ReconciliationDeviceID !=
			stalledTarget.identity.deviceID {
		t.Fatalf("stalled reconciliation status = %#v", status.Runtime)
	}

	harness.renewCredential(
		t,
		secondTarget,
		secondTarget,
		0xd1,
	)
	assertSecureMeshAuthority(
		t,
		secondTarget,
		[]domain.DeviceID{secondTarget.identity.deviceID},
		3,
	)

	harness.applyVoterTarget(
		t,
		secondTarget,
		[]domain.DeviceID{secondTarget.identity.deviceID},
		4,
	)
	reconcileSecureMeshUntil(
		t,
		secondTarget,
		"mid-transit retarget and obsolete-server removal",
		func() bool {
			return secureMeshConfigurationEquals(
				secondTarget,
				[]domain.DeviceID{secondTarget.identity.deviceID},
			) &&
				secureMeshAuthorityEquals(
					secondTarget,
					[]domain.DeviceID{secondTarget.identity.deviceID},
					5,
				)
		},
	)
	transferred = harness.waitForLeader(t, harness.runningNodes())
	if transferred != secondTarget {
		t.Fatalf(
			"retargeted leadership transferred to %s, want %s",
			transferred.identity.deviceID,
			secondTarget.identity.deviceID,
		)
	}
	assertSecureMeshVoterConfiguration(
		t,
		secondTarget,
		[]domain.DeviceID{secondTarget.identity.deviceID},
	)
	assertSecureMeshActivatedAuthority(
		t,
		secondTarget,
		[]domain.DeviceID{secondTarget.identity.deviceID},
		5,
	)

	final := harness.taskEvent(
		t,
		secondTarget,
		meshFinalEventID,
		meshFinalTaskID,
		meshFinalTimestamp,
		"commit after voter replacement",
	)
	result, err := secondTarget.node.Apply(
		secureMeshReconciliationContext(t),
		final,
	)
	if err != nil ||
		result.Outcome.Status != store.OutcomeAccepted ||
		result.Outcome.Code != string(reducer.CodeAccepted) {
		t.Fatalf("post-reconciliation Apply() = (%#v, %v)", result, err)
	}
	harness.waitForTask(
		t,
		[]*secureMeshNode{secondTarget},
		meshFinalTaskID,
	)
}

func (origin *secureMeshCheckpointOrigin) SubmitVoterSetActivation(
	ctx context.Context,
	payload voteractivation.ActivationPayload,
) (store.CommandOutcome, error) {
	if origin == nil ||
		origin.candidate == nil ||
		origin.candidate.node == nil ||
		ctx == nil {
		return store.CommandOutcome{}, ErrVoterActivationOriginUnavailable
	}
	if err := ctx.Err(); err != nil {
		return store.CommandOutcome{}, err
	}
	encoded, err := voteractivation.EncodeActivationPayload(payload)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	input := payload.UnsignedHandoff().Input()
	select {
	case origin.exclusive <- struct{}{}:
		defer func() { <-origin.exclusive }()
	case <-ctx.Done():
		return store.CommandOutcome{}, ctx.Err()
	}
	signed, err := secureMeshSignedCommand(
		origin.candidate,
		event.ActorDaemon,
		event.KindMembershipVoterSetActivated,
		event.StringEntityID(string(input.SessionID)),
		nil,
		encoded,
		secureMeshEventTimestamp(),
	)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	result, err := origin.candidate.node.Apply(ctx, signed)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	return result.Outcome, nil
}

func (harness *secureMeshHarness) issueCurrentCredentials(
	t *testing.T,
	leader *secureMeshNode,
) {
	t.Helper()
	if harness == nil || leader == nil {
		t.Fatal("invalid credential fixture")
	}
	issuedAt := domain.WholeSecondTimestamp(
		time.Now().
			UTC().
			Truncate(time.Second).
			Add(-time.Minute).
			Format(time.RFC3339),
	)
	owner := harness.nodes[0]
	for index, subject := range harness.nodes {
		payload := harness.credentialPayload(
			t,
			subject,
			byte(0xa1+index),
			issuedAt,
		)
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf(
				"encode credential event for %s: %v",
				subject.identity.deviceID,
				err,
			)
		}
		signed, err := secureMeshSignedCommand(
			owner,
			event.ActorDaemon,
			event.KindCredentialAuthorized,
			event.StringEntityID(string(subject.identity.deviceID)),
			nil,
			encoded,
			domain.Timestamp(issuedAt),
		)
		if err != nil {
			t.Fatalf("build credential event for %s: %v", subject.identity.deviceID, err)
		}
		result, err := leader.node.Apply(
			secureMeshReconciliationContext(t),
			signed,
		)
		if err != nil ||
			result.Outcome.Status != store.OutcomeAccepted ||
			result.Outcome.Code != string(reducer.CodeAccepted) {
			t.Fatalf(
				"Apply(credential %s) = (%#v, %v)",
				subject.identity.deviceID,
				result,
				err,
			)
		}
	}
	awaitMeshCondition(
		t,
		15*time.Second,
		"current credentials on every mesh node",
		func() bool {
			at := time.Now()
			for _, candidate := range harness.runningNodes() {
				snapshot, err := candidate.node.PeerAdmissionSnapshot()
				if err != nil {
					return false
				}
				for _, subject := range harness.nodes {
					if _, found := snapshot.ActiveCredentialAuthorizationAt(
						subject.identity.deviceID,
						at,
					); !found {
						return false
					}
				}
			}
			return true
		},
	)
}

func (harness *secureMeshHarness) renewCredential(
	t *testing.T,
	leader *secureMeshNode,
	subject *secureMeshNode,
	keySeed byte,
) {
	t.Helper()
	signed, _ := harness.credentialRenewalEvent(
		t,
		leader,
		subject,
		keySeed,
	)
	result, err := leader.node.Apply(
		secureMeshReconciliationContext(t),
		signed,
	)
	if err != nil ||
		result.Outcome.Status != store.OutcomeAccepted ||
		result.Outcome.Code != string(reducer.CodeAccepted) {
		t.Fatalf("Apply(credential renewal) = (%#v, %v)", result, err)
	}
}

func (harness *secureMeshHarness) credentialRenewalEvent(
	t *testing.T,
	stateSource *secureMeshNode,
	subject *secureMeshNode,
	keySeed byte,
) (event.SignedEvent, credentialauthorization.Authorization) {
	t.Helper()
	if harness == nil || stateSource == nil || subject == nil {
		t.Fatal("invalid credential-renewal fixture")
	}
	admission, err := stateSource.node.PeerAdmissionSnapshot()
	if err != nil {
		t.Fatalf("PeerAdmissionSnapshot(): %v", err)
	}
	currentEpoch, found := admission.CurrentCredentialEpoch(
		subject.identity.deviceID,
	)
	if !found || currentEpoch == 0 {
		t.Fatalf(
			"current credential epoch for %s = (%d, %t)",
			subject.identity.deviceID,
			currentEpoch,
			found,
		)
	}
	previous, found := admission.Authorization(
		credentialauthorization.Key{
			SessionID: nodeTestSessionID,
			DeviceID:  subject.identity.deviceID,
			Epoch:     currentEpoch,
		},
	)
	if !found {
		t.Fatalf("missing prior credential for %s", subject.identity.deviceID)
	}
	previousNotBefore, err := previous.NotBefore.Time()
	if err != nil {
		t.Fatal(err)
	}
	issuedAtTime := previousNotBefore.Add(
		time.Duration(
			credentialauthorization.ValiditySeconds-
				credentialauthorization.RenewalLeadSeconds,
		) * time.Second,
	)
	notBeforeTime := previousNotBefore.Add(
		time.Duration(
			credentialauthorization.ValiditySeconds-
				credentialauthorization.OverlapSeconds,
		) * time.Second,
	)
	if issuedAtTime.After(notBeforeTime) {
		notBeforeTime = issuedAtTime
	}

	view, err := stateSource.node.state.View(
		secureMeshReconciliationContext(t),
	)
	if err != nil {
		t.Fatalf("state.View(credential renewal): %v", err)
	}
	state, err := decodeStateView(view)
	if err != nil {
		t.Fatal(err)
	}
	member, exists := state.Admission.Member(subject.identity.deviceID)
	if !exists {
		t.Fatalf("missing credential subject %s", subject.identity.deviceID)
	}
	epochPrivate := ed25519.NewKeyFromSeed(
		makeRepeatedByte(keySeed, ed25519.SeedSize),
	)
	defer clear(epochPrivate)
	binding, err := credential.SignBinding(
		nodeTestSessionID,
		subject.identity.deviceID,
		currentEpoch+1,
		epochPrivate.Public().(ed25519.PublicKey),
		subject.identity.private,
	)
	if err != nil {
		t.Fatalf("credential.SignBinding(renewal): %v", err)
	}
	authorization := credentialauthorization.Authorization{
		SessionID:      nodeTestSessionID,
		DeviceID:       subject.identity.deviceID,
		Epoch:          currentEpoch + 1,
		EpochPublicKey: binding.EpochPublicKey,
		KeyDigest:      binding.KeyDigest,
		Role:           credentialauthorization.Role(member.Role),
		IssuedAt: domain.WholeSecondTimestamp(
			issuedAtTime.UTC().Format(time.RFC3339),
		),
		NotBefore: domain.WholeSecondTimestamp(
			notBeforeTime.UTC().Format(time.RFC3339),
		),
		ValiditySeconds: credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: state.CredentialAuthority.
			VoterSetVersion,
		BindingSignature:        binding.Signature,
		AuthorizationChainIndex: view.Heads.ChainIndex + 1,
	}
	preimage, err := secureMeshCredentialEndorsementPreimage(authorization)
	if err != nil {
		t.Fatalf("credential renewal endorsement preimage: %v", err)
	}
	endorsements := make(
		[]map[string]any,
		len(state.CredentialAuthority.VoterDeviceIDs),
	)
	authorization.ClockEndorsements = make(
		[]credentialauthorization.ClockEndorsement,
		len(state.CredentialAuthority.VoterDeviceIDs),
	)
	for index, endorserID := range state.CredentialAuthority.VoterDeviceIDs {
		var endorser *secureMeshNode
		for _, candidate := range harness.nodes {
			if candidate.identity.deviceID == endorserID {
				endorser = candidate
				break
			}
		}
		if endorser == nil {
			t.Fatalf("missing authority signer %s", endorserID)
		}
		signature, err := codecommcrypto.SignEd25519(
			endorser.identity.private,
			codec.SignatureCredentialTimeEndorsement,
			preimage,
		)
		if err != nil {
			t.Fatalf("sign renewal endorsement for %s: %v", endorserID, err)
		}
		endorsement := credentialauthorization.ClockEndorsement{
			DeviceID: endorserID,
		}
		copy(endorsement.Signature[:], signature)
		authorization.ClockEndorsements[index] = endorsement
		endorsements[index] = map[string]any{
			"device_id": endorserID,
			"signature": codec.EncodeBase64URL(signature),
		}
	}
	payload, err := json.Marshal(map[string]any{
		"subject_device_id":           authorization.DeviceID,
		"epoch_public_key":            codec.EncodeBase64URL(authorization.EpochPublicKey[:]),
		"key_digest":                  codec.EncodeBase64URL(authorization.KeyDigest[:]),
		"epoch":                       authorization.Epoch,
		"role":                        authorization.Role,
		"issued_at":                   authorization.IssuedAt,
		"not_before":                  authorization.NotBefore,
		"validity_seconds":            authorization.ValiditySeconds,
		"authority_voter_set_version": authorization.AuthorityVoterSetVersion,
		"clock_endorsements":          endorsements,
		"binding_signature": codec.EncodeBase64URL(
			authorization.BindingSignature[:],
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := secureMeshSignedCommand(
		harness.nodes[0],
		event.ActorDaemon,
		event.KindCredentialAuthorized,
		event.StringEntityID(string(subject.identity.deviceID)),
		nil,
		payload,
		secureMeshEventTimestamp(),
	)
	if err != nil {
		t.Fatalf("build credential renewal: %v", err)
	}
	return signed, authorization
}

func (harness *secureMeshHarness) credentialPayload(
	t *testing.T,
	subject *secureMeshNode,
	keySeed byte,
	issuedAt domain.WholeSecondTimestamp,
) map[string]any {
	t.Helper()
	epochPrivate := ed25519.NewKeyFromSeed(
		makeRepeatedByte(keySeed, ed25519.SeedSize),
	)
	defer clear(epochPrivate)
	binding, err := credential.SignBinding(
		nodeTestSessionID,
		subject.identity.deviceID,
		1,
		epochPrivate.Public().(ed25519.PublicKey),
		subject.identity.private,
	)
	if err != nil {
		t.Fatalf("credential.SignBinding(%s): %v", subject.identity.deviceID, err)
	}
	role := device.RoleEditor
	if subject.index == 0 {
		role = device.RoleOwner
	}
	authorization := credentialauthorization.Authorization{
		SessionID:                nodeTestSessionID,
		DeviceID:                 subject.identity.deviceID,
		Epoch:                    1,
		EpochPublicKey:           binding.EpochPublicKey,
		KeyDigest:                binding.KeyDigest,
		Role:                     credentialauthorization.Role(role),
		IssuedAt:                 issuedAt,
		NotBefore:                issuedAt,
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		BindingSignature:         binding.Signature,
		AuthorizationChainIndex:  1,
	}
	preimage, err := secureMeshCredentialEndorsementPreimage(authorization)
	if err != nil {
		t.Fatalf("credential endorsement preimage: %v", err)
	}
	endorsements := make([]map[string]any, len(harness.nodes))
	for index, endorser := range harness.nodes {
		signature, err := codecommcrypto.SignEd25519(
			endorser.identity.private,
			codec.SignatureCredentialTimeEndorsement,
			preimage,
		)
		if err != nil {
			t.Fatalf(
				"sign credential endorsement for %s: %v",
				endorser.identity.deviceID,
				err,
			)
		}
		endorsements[index] = map[string]any{
			"device_id": endorser.identity.deviceID,
			"signature": codec.EncodeBase64URL(signature),
		}
	}
	return map[string]any{
		"subject_device_id":           authorization.DeviceID,
		"epoch_public_key":            codec.EncodeBase64URL(authorization.EpochPublicKey[:]),
		"key_digest":                  codec.EncodeBase64URL(authorization.KeyDigest[:]),
		"epoch":                       authorization.Epoch,
		"role":                        authorization.Role,
		"issued_at":                   authorization.IssuedAt,
		"not_before":                  authorization.NotBefore,
		"validity_seconds":            authorization.ValiditySeconds,
		"authority_voter_set_version": authorization.AuthorityVoterSetVersion,
		"clock_endorsements":          endorsements,
		"binding_signature": codec.EncodeBase64URL(
			authorization.BindingSignature[:],
		),
	}
}

type secureMeshCredentialEndorsementWire struct {
	AuthorityVoterSetVersion uint64 `json:"authority_voter_set_version"`
	Epoch                    uint64 `json:"epoch"`
	IssuedAt                 string `json:"issued_at"`
	KeyDigest                string `json:"key_digest"`
	SessionID                string `json:"session_id"`
	SubjectDeviceID          string `json:"subject_device_id"`
}

func secureMeshCredentialEndorsementPreimage(
	authorization credentialauthorization.Authorization,
) ([]byte, error) {
	encoded, err := json.Marshal(secureMeshCredentialEndorsementWire{
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
		return nil, err
	}
	return codec.CanonicalizeSignedObject(encoded)
}

func (harness *secureMeshHarness) applyVoterTarget(
	t *testing.T,
	leader *secureMeshNode,
	target []domain.DeviceID,
	expectedVersion uint64,
) {
	t.Helper()
	owner := harness.nodes[0]
	payload, err := json.Marshal(map[string]any{"voter_set": target})
	if err != nil {
		t.Fatalf("encode voter target: %v", err)
	}
	signed, err := secureMeshSignedCommand(
		owner,
		event.ActorHuman,
		event.KindMembershipVoterSetChanged,
		event.StringEntityID(string(nodeTestSessionID)),
		&expectedVersion,
		payload,
		secureMeshEventTimestamp(),
	)
	if err != nil {
		t.Fatalf("build voter target: %v", err)
	}
	result, err := leader.node.Apply(
		secureMeshReconciliationContext(t),
		signed,
	)
	if err != nil ||
		result.Outcome.Status != store.OutcomeAccepted ||
		result.Outcome.Code != string(reducer.CodeAccepted) {
		t.Fatalf("Apply(voter target %v) = (%#v, %v)", target, result, err)
	}
}

func (harness *secureMeshHarness) waitForVoterTarget(
	t *testing.T,
	candidates []*secureMeshNode,
	want []domain.DeviceID,
	version uint64,
) {
	t.Helper()
	awaitMeshCondition(
		t,
		15*time.Second,
		fmt.Sprintf("voter target %v at version %d", want, version),
		func() bool {
			for _, candidate := range candidates {
				view, err := candidate.node.state.View(context.Background())
				if err != nil {
					return false
				}
				state, err := decodeStateView(view)
				if err != nil ||
					state.VoterSet.VoterSetVersion != version ||
					!sameDeviceIDs(state.VoterSet.VoterDeviceIDs(), want) {
					return false
				}
			}
			return true
		},
	)
}

func secureMeshSignedCommand(
	origin *secureMeshNode,
	actor event.ActorType,
	kind event.Kind,
	entityID event.EntityID,
	expectedVersion *uint64,
	payload []byte,
	createdAt domain.Timestamp,
) (event.SignedEvent, error) {
	if origin == nil ||
		origin.startCount < 1 ||
		origin.startCount > len(origin.identity.bootIDs) {
		return event.SignedEvent{}, errors.New("invalid secure-mesh origin")
	}
	authority, err := event.NewLocalAuthority(
		origin.identity.deviceID,
		origin.identity.bootIDs[origin.startCount-1],
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	var binding event.Binding
	switch actor {
	case event.ActorHuman:
		binding, err = authority.OperatorBinding()
	case event.ActorDaemon:
		binding, err = authority.DaemonBinding()
	default:
		return event.SignedEvent{}, fmt.Errorf("unsupported actor %q", actor)
	}
	if err != nil {
		return event.SignedEvent{}, err
	}
	generated, err := uuid.NewV7()
	if err != nil {
		return event.SignedEvent{}, err
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:                  kind,
			EntityID:              entityID,
			ExpectedEntityVersion: expectedVersion,
			Actions:               []event.Action{},
			Payload:               payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        domain.UUIDv7(generated.String()),
			SessionID:      nodeTestSessionID,
			WorkspaceID:    nodeTestWorkspaceID,
			CreatedAt:      createdAt,
			OriginSequence: origin.nextSequence,
		},
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	signed, err := event.Sign(proposal, origin.identity.private)
	if err != nil {
		return event.SignedEvent{}, err
	}
	origin.nextSequence++
	return signed, nil
}

func reconcileSecureMeshUntil(
	t *testing.T,
	leader *secureMeshNode,
	description string,
	done func() bool,
) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		ctx, cancel := context.WithTimeout(
			context.Background(),
			20*time.Second,
		)
		err := leader.node.ReconcileVoterSet(ctx)
		cancel()
		lastErr = err
		if done() {
			return
		}
		if err != nil &&
			!errors.Is(err, ErrVoterReconciliationStalled) &&
			!errors.Is(err, ErrCheckpointProofUnavailable) &&
			!errors.Is(err, ErrVoterActivationProofUnavailable) &&
			!errors.Is(err, ErrConsensusAuthorizationUnavailable) &&
			!errors.Is(err, ErrLeadershipEpochChanged) &&
			!errors.Is(err, raft.ErrLeadershipLost) &&
			!errors.Is(err, raft.ErrNotLeader) {
			t.Fatalf("%s failed: %v", description, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: last error %v", description, lastErr)
}

func reconcileSecureMeshClusterUntil(
	t *testing.T,
	harness *secureMeshHarness,
	description string,
	done func() bool,
) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		var leader *secureMeshNode
		for _, candidate := range harness.runningNodes() {
			if !candidate.node.IsLeader() {
				continue
			}
			if leader != nil {
				leader = nil
				break
			}
			leader = candidate
		}
		if leader == nil {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		ctx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		err := leader.node.ReconcileVoterSet(ctx)
		cancel()
		lastErr = err
		if done() {
			return
		}
		if err != nil &&
			!errors.Is(err, context.DeadlineExceeded) &&
			!errors.Is(err, ErrVoterReconciliationStalled) &&
			!errors.Is(err, ErrCheckpointProofUnavailable) &&
			!errors.Is(err, ErrVoterActivationProofUnavailable) &&
			!errors.Is(err, ErrConsensusAuthorizationUnavailable) &&
			!errors.Is(err, ErrLeadershipEpochChanged) &&
			!errors.Is(err, raft.ErrLeadershipLost) &&
			!errors.Is(err, raft.ErrNotLeader) {
			t.Fatalf("%s failed: %v", description, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	logSecureMeshDiagnostics(t, harness)
	t.Fatalf("timed out waiting for %s: last error %v", description, lastErr)
}

func logSecureMeshDiagnostics(t *testing.T, harness *secureMeshHarness) {
	t.Helper()
	for _, candidate := range harness.nodes {
		if candidate.node == nil {
			t.Logf("%s: stopped", candidate.identity.deviceID)
			continue
		}
		leaderAddress, leaderID := candidate.node.raft.LeaderWithID()
		configuration := candidate.node.fsm.committedConfiguration()
		t.Logf(
			"%s: raft=%s leader=%s/%s fatal=%v stats=%v configuration=%#v",
			candidate.identity.deviceID,
			candidate.node.raft.State(),
			leaderID,
			leaderAddress,
			candidate.node.FatalError(),
			candidate.node.raft.Stats(),
			configuration,
		)
	}
}

func assertSecureMeshReconciliationCapabilities(
	t *testing.T,
	candidate *secureMeshNode,
) {
	t.Helper()
	if candidate == nil ||
		candidate.node == nil ||
		candidate.node.coverageGate == nil ||
		candidate.node.checkpointOrigin == nil ||
		candidate.node.checkpointRequester == nil ||
		candidate.node.voterActivationSigner == nil ||
		candidate.node.voterActivationOrigin == nil {
		t.Fatal("secure mesh lacks voter-reconciliation capabilities")
	}
	if candidate.node.readinessGate == nil {
		t.Fatal("secure mesh lacks configuration-readiness gate")
	}
	if _, ok := candidate.node.readinessGate.provider.(*nodeConfigurationReadinessProvider); !ok {
		t.Fatalf(
			"configuration readiness provider = %T, want production provider",
			candidate.node.readinessGate.provider,
		)
	}
}

func assertSecureMeshVoterConfiguration(
	t *testing.T,
	candidate *secureMeshNode,
	want []domain.DeviceID,
) {
	t.Helper()
	if err := candidate.node.Barrier(
		secureMeshReconciliationContext(t),
	); err != nil {
		t.Fatalf("Barrier(%s): %v", candidate.identity.deviceID, err)
	}
	configuration := candidate.node.fsm.committedConfiguration()
	if configuration == nil ||
		!secureMeshConfigurationEquals(candidate, want) {
		t.Fatalf(
			"configuration on %s = %#v, want voters %v",
			candidate.identity.deviceID,
			configuration,
			want,
		)
	}
}

func secureMeshConfigurationEquals(
	candidate *secureMeshNode,
	want []domain.DeviceID,
) bool {
	if candidate == nil || candidate.node == nil {
		return false
	}
	configuration := candidate.node.fsm.committedConfiguration()
	if configuration == nil ||
		len(configuration.Configuration.Servers) != len(want) {
		return false
	}
	expected := make(map[domain.DeviceID]struct{}, len(want))
	for _, id := range want {
		expected[id] = struct{}{}
	}
	for _, server := range configuration.Configuration.Servers {
		id := domain.DeviceID(server.ID)
		if _, exists := expected[id]; !exists ||
			server.Suffrage != raft.Voter ||
			server.Address != raft.ServerAddress(id) {
			return false
		}
	}
	return true
}

func secureMeshProjectionRows(
	view store.StateView,
	table string,
) []chain.LogicalRow {
	rows := make([]chain.LogicalRow, 0)
	for _, row := range view.ProjectionRows {
		if row.Table == table {
			rows = append(rows, row)
		}
	}
	return rows
}

func assertSecureMeshNeverLed(
	t *testing.T,
	candidate *secureMeshNode,
	observations <-chan raft.Observation,
) {
	t.Helper()
	select {
	case observation := <-observations:
		t.Fatalf(
			"isolated node %s became leader: %#v",
			candidate.identity.deviceID,
			observation.Data,
		)
	default:
	}
	if candidate.node.IsLeader() ||
		candidate.node.raft.State() == raft.Leader {
		t.Fatalf(
			"isolated node %s reports leader state",
			candidate.identity.deviceID,
		)
	}
}

func (harness *secureMeshHarness) assertCredentialAbsent(
	t *testing.T,
	candidate *secureMeshNode,
	authorization credentialauthorization.Authorization,
) {
	t.Helper()
	if harness == nil || candidate == nil || candidate.node == nil {
		t.Fatal("invalid credential-absence fixture")
	}
	if authorization.Epoch < 2 {
		t.Fatalf("candidate credential epoch = %d, want at least 2", authorization.Epoch)
	}
	admission, err := candidate.node.PeerAdmissionSnapshot()
	if err != nil {
		t.Fatalf(
			"PeerAdmissionSnapshot(%s): %v",
			candidate.identity.deviceID,
			err,
		)
	}
	if _, found := admission.Authorization(authorization.PrimaryKey()); found {
		t.Fatalf(
			"credential %s epoch %d was authorized on %s",
			authorization.DeviceID,
			authorization.Epoch,
			candidate.identity.deviceID,
		)
	}
	epoch, found := admission.CurrentCredentialEpoch(authorization.DeviceID)
	if !found || epoch != authorization.Epoch-1 {
		t.Fatalf(
			"current credential epoch for %s on %s = (%d, %t), want (%d, true)",
			authorization.DeviceID,
			candidate.identity.deviceID,
			epoch,
			found,
			authorization.Epoch-1,
		)
	}
}

func assertSecureMeshActivatedAuthority(
	t *testing.T,
	candidate *secureMeshNode,
	want []domain.DeviceID,
	version uint64,
) {
	t.Helper()
	view, err := candidate.node.state.View(
		secureMeshReconciliationContext(t),
	)
	if err != nil {
		t.Fatalf("state.View(%s): %v", candidate.identity.deviceID, err)
	}
	state, err := decodeStateView(view)
	if err != nil {
		t.Fatalf("decodeStateView(%s): %v", candidate.identity.deviceID, err)
	}
	if state.VoterSet.VoterSetVersion != version ||
		!sameDeviceIDs(state.VoterSet.VoterDeviceIDs(), want) ||
		state.CredentialAuthority.VoterSetVersion != version ||
		!sameDeviceIDs(state.CredentialAuthority.VoterDeviceIDs, want) ||
		state.CredentialAuthority.ActivationSource !=
			credentialauthority.ActivationHandoff ||
		!state.CredentialAuthority.ActivationCheckpointEventID.Valid() ||
		len(state.CredentialAuthority.ActivationProofs) != len(want) ||
		!state.CredentialAuthority.PriorAuthoritySigner.Valid() ||
		state.CredentialAuthority.PriorAuthorityHandoff == nil {
		t.Fatalf(
			"activated state on %s = target %#v, authority %#v",
			candidate.identity.deviceID,
			state.VoterSet,
			state.CredentialAuthority,
		)
	}
}

func assertSecureMeshAuthority(
	t *testing.T,
	candidate *secureMeshNode,
	want []domain.DeviceID,
	version uint64,
) {
	t.Helper()
	if secureMeshAuthorityEquals(candidate, want, version) {
		return
	}
	view, err := candidate.node.state.View(
		secureMeshReconciliationContext(t),
	)
	if err != nil {
		t.Fatalf("state.View(%s): %v", candidate.identity.deviceID, err)
	}
	state, err := decodeStateView(view)
	if err != nil {
		t.Fatalf("decodeStateView(%s): %v", candidate.identity.deviceID, err)
	}
	t.Fatalf(
		"authority on %s = %#v, want voters %v version %d",
		candidate.identity.deviceID,
		state.CredentialAuthority,
		want,
		version,
	)
}

func secureMeshAuthorityEquals(
	candidate *secureMeshNode,
	want []domain.DeviceID,
	version uint64,
) bool {
	if candidate == nil || candidate.node == nil {
		return false
	}
	view, err := candidate.node.state.View(context.Background())
	if err != nil {
		return false
	}
	state, err := decodeStateView(view)
	return err == nil &&
		state.CredentialAuthority.VoterSetVersion == version &&
		sameDeviceIDs(state.CredentialAuthority.VoterDeviceIDs, want)
}

func secureMeshReconciliationContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func secureMeshEventTimestamp() domain.Timestamp {
	return domain.Timestamp(
		time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
	)
}

func makeRepeatedByte(value byte, size int) []byte {
	result := make([]byte, size)
	for index := range result {
		result[index] = value
	}
	return result
}

var _ VoterActivationOrigin = (*secureMeshCheckpointOrigin)(nil)
