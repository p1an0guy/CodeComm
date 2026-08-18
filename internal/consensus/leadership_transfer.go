package consensus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

var (
	ErrInvalidLeadershipTransfer = errors.New(
		"consensus: invalid targeted leadership transfer",
	)
	ErrLeadershipTransferTargetMismatch = errors.New(
		"consensus: targeted leadership transfer elected another server",
	)
)

// transferLeadership transfers to one already-promoted target voter. It uses
// the same coverage, current-credential, reachability, configuration-index,
// and enqueue cut as a topology mutation.
func (node *SingleNode) transferLeadership(
	ctx context.Context,
	expectedPlan voterReconciliationPlan,
	eligibility voterEligibilitySet,
) error {
	target := expectedPlan.deviceID
	if node == nil ||
		node.raft == nil ||
		node.state == nil ||
		ctx == nil ||
		node.single ||
		expectedPlan.action !=
			voterReconciliationTransferLeadership ||
		expectedPlan.configurationIndex < 1 ||
		!domain.ValidUnsignedInteger(expectedPlan.configurationIndex) ||
		!target.Valid() ||
		target == domain.DeviceID(node.serverID) {
		return ErrInvalidLeadershipTransfer
	}
	eligibility = eligibility.clone()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := node.beginOperation(); err != nil {
		return err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return err
	}
	operationContext, cancel, wait := node.operationContext(ctx)
	defer func() {
		cancel()
		wait()
	}()
	ctx = operationContext

	leadership, err := node.readConfigurationLeadershipEpoch()
	if err != nil {
		return err
	}
	if err := node.waitRaftBarrier(ctx); err != nil {
		return err
	}
	if err := node.requireConfigurationLeadershipEpoch(leadership); err != nil {
		return err
	}
	baselineState, baselineCoverage, baselineConfiguration, err :=
		node.configurationChangeCut(ctx)
	if err != nil {
		return err
	}
	if baselineConfiguration.Index != expectedPlan.configurationIndex {
		return ErrStaleConfigurationChange
	}
	if err := validateLeadershipTransferTarget(
		baselineState,
		baselineConfiguration.Configuration,
		target,
		node.serverID,
	); err != nil {
		return err
	}
	readinessRequirement, err := leadershipTransferReadinessRequirement(
		baselineState,
		baselineConfiguration,
		target,
	)
	if err != nil {
		return err
	}
	readiness, err := node.readinessGate.collect(
		ctx,
		readinessRequirement,
	)
	if err != nil {
		return err
	}
	baselinePlan, err := reconciliationPlanAtCut(
		baselineState,
		baselineConfiguration,
		domain.DeviceID(node.serverID),
		readiness.candidate,
		eligibility,
	)
	if err != nil {
		return errVoterReconciliationChanged
	}
	if err := requireExpectedReconciliationPlan(
		expectedPlan,
		baselinePlan,
	); err != nil {
		return err
	}
	coverage, err := node.coverageGate.Collect(ctx, baselineCoverage)
	if err != nil {
		return err
	}

	guard, err := node.acquireRaftEnqueue(ctx)
	if err != nil {
		return err
	}
	ownsGuard := true
	defer func() {
		if ownsGuard {
			guard.release()
		}
	}()
	barrier, err := node.enqueueRaftBarrier(ctx)
	if err != nil {
		return err
	}
	if err, ownsGuard = node.waitRaftFutureWithGuard(
		ctx,
		barrier,
		guard,
	); err != nil {
		return err
	}

	currentState, currentCoverage, currentConfiguration, err :=
		node.configurationChangeCut(ctx)
	if err != nil {
		return err
	}
	if err := node.coverageGate.VerifyCurrent(
		currentCoverage,
		coverage,
	); err != nil {
		return err
	}
	if err := node.requireConfigurationLeadershipEpoch(leadership); err != nil {
		return err
	}
	if err := validateLeadershipTransferTarget(
		currentState,
		currentConfiguration.Configuration,
		target,
		node.serverID,
	); err != nil {
		return err
	}
	currentReadiness, err := leadershipTransferReadinessRequirement(
		currentState,
		currentConfiguration,
		target,
	)
	if err != nil {
		return err
	}
	currentPlan, err := reconciliationPlanAtCut(
		currentState,
		currentConfiguration,
		domain.DeviceID(node.serverID),
		readiness.candidate,
		eligibility,
	)
	if err != nil {
		return errVoterReconciliationChanged
	}
	if err := requireExpectedReconciliationPlan(
		expectedPlan,
		currentPlan,
	); err != nil {
		return err
	}
	if err := node.readinessGate.verifyCurrent(
		currentReadiness,
		readiness,
	); err != nil {
		return err
	}
	if err := node.preEnqueueError(ctx); err != nil {
		return err
	}
	if err := node.requireConfigurationLeadershipEpoch(leadership); err != nil {
		return err
	}

	future := node.invokeRaftLeadershipTransfer(target)
	if err, ownsGuard = node.waitRaftFutureWithGuard(
		ctx,
		future,
		guard,
	); err != nil {
		return err
	}
	guard.release()
	ownsGuard = false
	return node.waitForTransferredLeader(ctx, target)
}

func validateLeadershipTransferTarget(
	state decodedState,
	configuration raft.Configuration,
	target domain.DeviceID,
	localServerID raft.ServerID,
) error {
	if !target.Valid() ||
		target == domain.DeviceID(localServerID) ||
		!state.VoterSet.Contains(target) ||
		state.VoterSet.Contains(domain.DeviceID(localServerID)) ||
		!credentialAuthorityMatchesTarget(state) {
		return ErrInvalidLeadershipTransfer
	}
	member, exists := state.Admission.Member(target)
	if !exists || member.Status != device.StatusActive {
		return ErrInvalidLeadershipTransfer
	}
	for _, server := range configuration.Servers {
		if server.ID == raft.ServerID(target) &&
			server.Address == raft.ServerAddress(target) &&
			server.Suffrage == raft.Voter {
			return nil
		}
	}
	return ErrInvalidLeadershipTransfer
}

func (node *SingleNode) invokeRaftLeadershipTransfer(
	target domain.DeviceID,
) raft.Future {
	return node.raft.LeadershipTransferToServer(
		raft.ServerID(target),
		raft.ServerAddress(target),
	)
}

func (node *SingleNode) waitForTransferredLeader(
	ctx context.Context,
	target domain.DeviceID,
) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		address, leaderID := node.raft.LeaderWithID()
		if leaderID != "" {
			if leaderID == node.serverID {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-node.closeStarted:
					return ErrNodeClosed
				case <-node.fatalSet:
					return node.FatalError()
				case <-ticker.C:
				}
				continue
			}
			if leaderID != raft.ServerID(target) ||
				address != raft.ServerAddress(target) {
				return fmt.Errorf(
					"%w: got %s",
					ErrLeadershipTransferTargetMismatch,
					leaderID,
				)
			}
			if node.raft.State() == raft.Leader {
				return ErrLeadershipEpochChanged
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-node.closeStarted:
			return ErrNodeClosed
		case <-node.fatalSet:
			return node.FatalError()
		case <-ticker.C:
		}
	}
}
