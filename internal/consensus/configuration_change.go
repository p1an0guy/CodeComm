package consensus

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/canonicalcoverage"
	"github.com/ijonahch/codecomm/internal/domain"
)

var (
	ErrInvalidConfigurationChange = errors.New(
		"consensus: invalid Raft configuration change",
	)
	ErrStaleConfigurationChange = errors.New(
		"consensus: Raft configuration change no longer applies",
	)
	ErrLeadershipEpochChanged = errors.New(
		"consensus: leadership epoch changed during configuration reconciliation",
	)
)

type raftLeadershipEpoch struct {
	term uint64
}

type raftConfigurationChangeKind uint8

const (
	raftChangeAddVoter raftConfigurationChangeKind = iota + 1
	raftChangeAddNonvoter
	raftChangeDemoteVoter
	raftChangeRemoveServer
)

type raftConfigurationChange struct {
	kind     raftConfigurationChangeKind
	deviceID domain.DeviceID
}

func (change raftConfigurationChange) validate() error {
	if !change.deviceID.Valid() {
		return ErrInvalidConfigurationChange
	}
	switch change.kind {
	case raftChangeAddVoter,
		raftChangeAddNonvoter,
		raftChangeDemoteVoter,
		raftChangeRemoveServer:
		return nil
	default:
		return ErrInvalidConfigurationChange
	}
}

// changeRaftConfiguration is the only low-level membership-enqueue boundary.
// Production callers are prohibited until the reconciler supplies the
// operation-specific checkpoint, credential, authority, reachability, and
// leadership-transfer prerequisites. Receipt collection is deliberately
// outside raftEnqueue; the final barrier, state cut, freshness check, and
// configuration enqueue are serialized with every application enqueue.
func (node *SingleNode) changeRaftConfiguration(
	ctx context.Context,
	expectedPlan voterReconciliationPlan,
	eligibility voterEligibilitySet,
) (uint64, error) {
	change, planned := reconciliationConfigurationChange(expectedPlan)
	if node == nil ||
		node.raft == nil ||
		node.state == nil ||
		ctx == nil ||
		node.single ||
		!planned ||
		change.validate() != nil ||
		expectedPlan.configurationIndex < 1 ||
		!domain.ValidUnsignedInteger(expectedPlan.configurationIndex) {
		return 0, ErrInvalidConfigurationChange
	}
	eligibility = eligibility.clone()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := node.beginOperation(); err != nil {
		return 0, err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return 0, err
	}
	operationContext, cancel, wait := node.operationContext(ctx)
	defer func() {
		cancel()
		wait()
	}()
	ctx = operationContext

	leadershipEpoch, err := node.readConfigurationLeadershipEpoch()
	if err != nil {
		return 0, err
	}
	if err := node.waitRaftBarrier(ctx); err != nil {
		return 0, err
	}
	if err := node.requireConfigurationLeadershipEpoch(
		leadershipEpoch,
	); err != nil {
		return 0, err
	}

	baselineState, baseline, baselineConfiguration, err :=
		node.configurationChangeCut(ctx)
	if err != nil {
		return 0, err
	}
	if baselineConfiguration.Index != expectedPlan.configurationIndex {
		return 0, ErrStaleConfigurationChange
	}
	if err := validateRaftConfigurationChange(
		baselineState,
		baselineConfiguration.Configuration,
		change,
		node.serverID,
	); err != nil {
		return 0, err
	}
	readinessRequirement, err := configurationReadinessRequirement(
		baselineState,
		baselineConfiguration,
		change,
	)
	if err != nil {
		return 0, err
	}
	readiness, err := node.readinessGate.collect(
		ctx,
		readinessRequirement,
	)
	if err != nil {
		return 0, err
	}
	baselinePlan, err := reconciliationPlanAtCut(
		baselineState,
		baselineConfiguration,
		domain.DeviceID(node.serverID),
		readiness.candidate,
		eligibility,
	)
	if err != nil {
		return 0, errVoterReconciliationChanged
	}
	if err := requireExpectedReconciliationPlan(
		expectedPlan,
		baselinePlan,
	); err != nil {
		return 0, err
	}
	candidate, err := node.coverageGate.Collect(ctx, baseline)
	if err != nil {
		return 0, err
	}

	guard, err := node.acquireRaftEnqueue(ctx)
	if err != nil {
		return 0, err
	}
	ownsGuard := true
	defer func() {
		if ownsGuard {
			guard.release()
		}
	}()

	barrier, err := node.enqueueRaftBarrier(ctx)
	if err != nil {
		return 0, err
	}
	if err, ownsGuard = node.waitRaftFutureWithGuard(
		ctx,
		barrier,
		guard,
	); err != nil {
		return 0, err
	}

	currentState, currentCoverage, committed, err :=
		node.configurationChangeCut(ctx)
	if err != nil {
		return 0, err
	}
	if err := node.coverageGate.VerifyCurrent(
		currentCoverage,
		candidate,
	); err != nil {
		return 0, err
	}
	if err := node.requireConfigurationLeadershipEpoch(
		leadershipEpoch,
	); err != nil {
		return 0, err
	}
	if err := validateRaftConfigurationChange(
		currentState,
		committed.Configuration,
		change,
		node.serverID,
	); err != nil {
		return 0, err
	}
	currentReadiness, err := configurationReadinessRequirement(
		currentState,
		committed,
		change,
	)
	if err != nil {
		return 0, err
	}
	currentPlan, err := reconciliationPlanAtCut(
		currentState,
		committed,
		domain.DeviceID(node.serverID),
		readiness.candidate,
		eligibility,
	)
	if err != nil {
		return 0, errVoterReconciliationChanged
	}
	if err := requireExpectedReconciliationPlan(
		expectedPlan,
		currentPlan,
	); err != nil {
		return 0, err
	}
	if err := node.readinessGate.verifyCurrent(
		currentReadiness,
		readiness,
	); err != nil {
		return 0, err
	}
	if err := node.preEnqueueError(ctx); err != nil {
		return 0, err
	}
	if err := node.requireConfigurationLeadershipEpoch(
		leadershipEpoch,
	); err != nil {
		return 0, err
	}

	future := node.invokeRaftConfigurationChange(
		change,
		committed.Index,
		contextTimeout(ctx),
	)
	if err, ownsGuard = node.waitRaftFutureWithGuard(
		ctx,
		future,
		guard,
	); err != nil {
		return 0, err
	}
	if future.Index() <= committed.Index {
		return 0, node.haltNode(fmt.Errorf(
			"%w: committed index did not advance",
			ErrInvalidRaftTopology,
		))
	}
	return future.Index(), nil
}

func (node *SingleNode) readConfigurationLeadershipEpoch() (
	raftLeadershipEpoch,
	error,
) {
	if node == nil || node.readLeadershipEpoch == nil {
		return raftLeadershipEpoch{}, ErrInvalidNodeOptions
	}
	return node.readLeadershipEpoch()
}

func (node *SingleNode) requireConfigurationLeadershipEpoch(
	expected raftLeadershipEpoch,
) error {
	current, err := node.readConfigurationLeadershipEpoch()
	if err != nil {
		return err
	}
	if current != expected {
		return ErrLeadershipEpochChanged
	}
	return nil
}

func (node *SingleNode) currentLeadershipEpoch() (
	raftLeadershipEpoch,
	error,
) {
	if node == nil || node.raft == nil {
		return raftLeadershipEpoch{}, ErrInvalidNodeOptions
	}
	before, err := raftTerm(node.raft.Stats())
	if err != nil {
		return raftLeadershipEpoch{}, err
	}
	address, leaderID := node.raft.LeaderWithID()
	state := node.raft.State()
	after, err := raftTerm(node.raft.Stats())
	if err != nil {
		return raftLeadershipEpoch{}, err
	}
	if before != after {
		return raftLeadershipEpoch{}, ErrLeadershipEpochChanged
	}
	if state != raft.Leader ||
		leaderID != node.serverID ||
		address != raft.ServerAddress(node.serverID) {
		return raftLeadershipEpoch{}, raft.ErrNotLeader
	}
	return raftLeadershipEpoch{term: before}, nil
}

func raftTerm(stats map[string]string) (uint64, error) {
	termText, exists := stats["term"]
	if !exists {
		return 0, ErrInvalidRaftTopology
	}
	term, err := strconv.ParseUint(termText, 10, 64)
	if err != nil ||
		term < 1 ||
		!domain.ValidUnsignedInteger(term) {
		return 0, ErrInvalidRaftTopology
	}
	return term, nil
}

func sameRaftConfiguration(left, right raft.Configuration) bool {
	if len(left.Servers) != len(right.Servers) {
		return false
	}
	for index := range left.Servers {
		if left.Servers[index] != right.Servers[index] {
			return false
		}
	}
	return true
}

func (node *SingleNode) canonicalCoverageState(
	ctx context.Context,
) (decodedState, canonicalcoverage.Snapshot, error) {
	view, err := node.state.View(ctx)
	if err != nil {
		return decodedState{}, canonicalcoverage.Snapshot{}, err
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		return decodedState{}, canonicalcoverage.Snapshot{}, err
	}
	snapshot, err := decoded.CanonicalCoverageSnapshot()
	if err != nil {
		return decodedState{}, canonicalcoverage.Snapshot{}, err
	}
	return decoded, snapshot, nil
}

func (node *SingleNode) configurationChangeCut(
	ctx context.Context,
) (
	decodedState,
	canonicalcoverage.Snapshot,
	*committedRaftConfiguration,
	error,
) {
	state, coverage, err := node.canonicalCoverageState(ctx)
	if err != nil {
		return decodedState{},
			canonicalcoverage.Snapshot{},
			nil,
			err
	}
	future := node.raft.GetConfiguration()
	if err := waitFuture(ctx, future); err != nil {
		return decodedState{},
			canonicalcoverage.Snapshot{},
			nil,
			err
	}
	configuration := future.Configuration()
	if err := validateDeviceAddressedSnapshotConfiguration(
		configuration,
	); err != nil {
		return decodedState{},
			canonicalcoverage.Snapshot{},
			nil,
			err
	}
	committed := node.fsm.committedConfiguration()
	if committed == nil ||
		committed.Index < 1 ||
		!sameRaftConfiguration(
			committed.Configuration,
			configuration,
		) {
		return decodedState{},
			canonicalcoverage.Snapshot{},
			nil,
			ErrStaleConfigurationChange
	}
	return state, coverage, committed, nil
}

func validateRaftConfigurationChange(
	state decodedState,
	configuration raft.Configuration,
	change raftConfigurationChange,
	localServerID raft.ServerID,
) error {
	if change.validate() != nil {
		return ErrInvalidConfigurationChange
	}
	var (
		current raft.Server
		found   bool
	)
	for _, server := range configuration.Servers {
		if server.ID == raft.ServerID(change.deviceID) {
			current = server
			found = true
			break
		}
	}
	target := state.VoterSet.Contains(change.deviceID)
	switch change.kind {
	case raftChangeAddNonvoter:
		if !target || found {
			return ErrStaleConfigurationChange
		}
	case raftChangeAddVoter:
		if !target || !found || current.Suffrage != raft.Nonvoter {
			return ErrStaleConfigurationChange
		}
	case raftChangeDemoteVoter:
		if target ||
			!found ||
			current.Suffrage != raft.Voter ||
			current.ID == localServerID {
			return ErrStaleConfigurationChange
		}
	case raftChangeRemoveServer:
		if target ||
			!found ||
			current.ID == localServerID ||
			!credentialAuthorityMatchesTarget(state) {
			return ErrStaleConfigurationChange
		}
	default:
		return ErrInvalidConfigurationChange
	}
	return nil
}

func credentialAuthorityMatchesTarget(state decodedState) bool {
	return state.CredentialAuthority.VoterSetVersion ==
		state.VoterSet.VoterSetVersion &&
		sameDeviceIDs(
			state.CredentialAuthority.VoterDeviceIDs,
			state.VoterSet.VoterDeviceIDs(),
		)
}

func (node *SingleNode) invokeRaftConfigurationChange(
	change raftConfigurationChange,
	prevIndex uint64,
	timeoutDuration time.Duration,
) raft.IndexFuture {
	switch change.kind {
	case raftChangeAddVoter:
		return node.raft.AddVoter(
			raft.ServerID(change.deviceID),
			raft.ServerAddress(change.deviceID),
			prevIndex,
			timeoutDuration,
		)
	case raftChangeAddNonvoter:
		return node.raft.AddNonvoter(
			raft.ServerID(change.deviceID),
			raft.ServerAddress(change.deviceID),
			prevIndex,
			timeoutDuration,
		)
	case raftChangeDemoteVoter:
		return node.raft.DemoteVoter(
			raft.ServerID(change.deviceID),
			prevIndex,
			timeoutDuration,
		)
	case raftChangeRemoveServer:
		return node.raft.RemoveServer(
			raft.ServerID(change.deviceID),
			prevIndex,
			timeoutDuration,
		)
	default:
		return invalidConfigurationFuture{ErrInvalidConfigurationChange}
	}
}

type invalidConfigurationFuture struct {
	err error
}

func (future invalidConfigurationFuture) Error() error { return future.err }
func (invalidConfigurationFuture) Index() uint64       { return 0 }
