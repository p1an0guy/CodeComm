package consensus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/canonicalcoverage"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	ErrVoterReconciliationUnavailable = errors.New(
		"consensus: voter reconciliation capability unavailable",
	)
	ErrVoterReconciliationInvalid = errors.New(
		"consensus: invalid voter reconciliation state",
	)
	ErrVoterReconciliationStalled = errors.New(
		"consensus: voter reconciliation stalled",
	)
	errVoterReconciliationChanged = errors.New(
		"consensus: voter reconciliation input changed",
	)
)

type voterReconciliationStallError struct {
	reason   voterReconciliationReason
	deviceID domain.DeviceID
	cause    error
}

type stagingVoterProofAttempt struct {
	state         decodedState
	configuration committedRaftConfiguration
	target        domain.DeviceID
	checkpoint    store.AppliedCheckpointLookup
}

func (err *voterReconciliationStallError) Error() string {
	if err == nil {
		return ErrVoterReconciliationStalled.Error()
	}
	message := fmt.Sprintf(
		"%s: reason %d",
		ErrVoterReconciliationStalled,
		err.reason,
	)
	if err.deviceID.Valid() {
		message += ": device " + string(err.deviceID)
	}
	if err.cause != nil {
		message += ": " + err.cause.Error()
	}
	return message
}

func (err *voterReconciliationStallError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (err *voterReconciliationStallError) Is(target error) bool {
	return err != nil && target == ErrVoterReconciliationStalled
}

// ReconcileVoterSet drives the current applied voter target to stable Raft
// configuration and credential authority. It persists no cursor: every
// completed action is followed by a fresh barrier and a complete replan.
func (node *SingleNode) ReconcileVoterSet(ctx context.Context) error {
	return node.reconcileVoterSet(ctx)
}

func (node *SingleNode) reconcileVoterSet(ctx context.Context) (
	resultErr error,
) {
	if node == nil ||
		node.raft == nil ||
		node.state == nil ||
		node.fsm == nil ||
		node.voterReconcileGate == nil ||
		ctx == nil ||
		node.single {
		return ErrInvalidNodeOptions
	}
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
	select {
	case node.voterReconcileGate <- struct{}{}:
		defer func() { <-node.voterReconcileGate }()
	case <-ctx.Done():
		return ctx.Err()
	}

	var (
		eligibleVersion uint64
		eligibility     voterEligibilitySet
		observedState   decodedState
		observedPlan    voterReconciliationPlan
		observed        bool
		stable          bool
	)
	defer func() {
		if !observed {
			return
		}
		node.voterReconcileStatus.observe(
			voterReconciliationStatusCutFromState(observedState),
			observedPlan,
			stable,
			node.voterReconciliationTime(),
			resultErr,
		)
	}()
	for {
		state, configuration, ready, cutStable, err :=
			node.voterReconciliationCut(ctx)
		if state.VoterSet.Validate() == nil {
			observedState = state
			observed = true
		}
		if err != nil {
			return err
		}
		if cutStable {
			stable = true
			observedPlan = voterReconciliationPlan{
				action: voterReconciliationStable,
			}
			return nil
		}
		if eligibleVersion != state.VoterSet.VoterSetVersion {
			eligibleVersion = state.VoterSet.VoterSetVersion
			eligibility = initialVoterEligibility(
				state,
				configuration.Configuration,
			)
		}

		input, err := voterReconciliationPlannerInput(
			state,
			*configuration,
			domain.DeviceID(node.serverID),
			ready,
			eligibility.plannerSet(state, configuration),
		)
		if err != nil {
			return node.haltNode(err)
		}
		plan := planVoterReconciliation(input)
		observedPlan = plan
		node.voterReconcileStatus.observe(
			voterReconciliationStatusCutFromState(state),
			plan,
			false,
			node.voterReconciliationTime(),
			nil,
		)
		switch plan.action {
		case voterReconciliationInvalid:
			return node.haltNode(fmt.Errorf(
				"%w: planner reason %d",
				ErrVoterReconciliationInvalid,
				plan.reason,
			))
		case voterReconciliationStalled:
			return &voterReconciliationStallError{
				reason:   plan.reason,
				deviceID: plan.deviceID,
			}
		case voterReconciliationStable:
			stable = true
			return nil
		case voterReconciliationProveNonvoter:
			evidence, err := node.proveStagingVoter(
				ctx,
				state,
				configuration,
				plan.deviceID,
			)
			if err != nil {
				return reconcileActionError(plan, err)
			}
			eligibility[plan.deviceID] = evidence
		case voterReconciliationActivateAuthority:
			if err := node.activateVoterSet(
				ctx,
				state,
				configuration,
			); err != nil {
				if reconciliationInputChanged(err) {
					continue
				}
				return reconcileActionError(plan, err)
			}
		case voterReconciliationTransferLeadership:
			if err := node.transferLeadership(
				ctx,
				plan,
				eligibility,
			); err != nil {
				return reconcileActionError(plan, err)
			}
			return nil
		case voterReconciliationAddNonvoter,
			voterReconciliationPromoteVoter,
			voterReconciliationRemoveVoter,
			voterReconciliationRemoveNonvoter:
			_, ok := reconciliationConfigurationChange(plan)
			if !ok {
				return node.haltNode(ErrVoterReconciliationInvalid)
			}
			if _, err := node.changeRaftConfiguration(
				ctx,
				plan,
				eligibility,
			); err != nil {
				if reconciliationInputChanged(err) {
					continue
				}
				return reconcileActionError(plan, err)
			}
		default:
			return node.haltNode(ErrVoterReconciliationInvalid)
		}
	}
}

func (node *SingleNode) voterReconciliationCut(
	ctx context.Context,
) (
	decodedState,
	*committedRaftConfiguration,
	map[domain.DeviceID]struct{},
	bool,
	error,
) {
	leadership, err := node.readConfigurationLeadershipEpoch()
	if err != nil {
		return decodedState{}, nil, nil, false, err
	}
	if err := node.waitRaftBarrier(ctx); err != nil {
		return decodedState{}, nil, nil, false, err
	}
	if err := node.requireConfigurationLeadershipEpoch(leadership); err != nil {
		return decodedState{}, nil, nil, false, err
	}
	state, _, configuration, err := node.configurationChangeCut(ctx)
	if err != nil {
		return decodedState{}, nil, nil, false, err
	}

	allActive := activeConfiguredSet(state, configuration.Configuration)
	staticInput, err := voterReconciliationPlannerInput(
		state,
		*configuration,
		domain.DeviceID(node.serverID),
		allActive,
		initialVoterEligibility(
			state,
			configuration.Configuration,
		).plannerSet(state, configuration),
	)
	if err != nil {
		return decodedState{}, nil, nil, false,
			node.haltNode(err)
	}
	staticPlan := planVoterReconciliation(staticInput)
	if staticPlan.action == voterReconciliationInvalid {
		return decodedState{}, nil, nil, false,
			node.haltNode(fmt.Errorf(
				"%w: planner reason %d",
				ErrVoterReconciliationInvalid,
				staticPlan.reason,
			))
	}
	if staticPlan.action == voterReconciliationStable {
		return state, configuration, allActive, true, nil
	}
	if err := node.requireVoterReconciliationCapabilities(); err != nil {
		return state, configuration, nil, false, err
	}

	requirement, err := reconciliationReadinessRequirement(
		state,
		configuration,
		domain.DeviceID(node.serverID),
	)
	if err != nil {
		return state, configuration, nil, false,
			node.haltNode(err)
	}
	readiness, err := node.readinessGate.collect(ctx, requirement)
	if err != nil {
		return state, configuration, nil, false, err
	}
	if err := node.requireConfigurationLeadershipEpoch(leadership); err != nil {
		return decodedState{}, nil, nil, false, err
	}
	return state,
		configuration,
		readyConfigurationDevices(readiness.candidate),
		false,
		nil
}

func (node *SingleNode) voterReconciliationTime() time.Time {
	if node == nil || node.voterReconcileNow == nil {
		return time.Now()
	}
	return node.voterReconcileNow()
}

func voterReconciliationPlannerInput(
	state decodedState,
	configuration committedRaftConfiguration,
	localLeader domain.DeviceID,
	ready map[domain.DeviceID]struct{},
	eligible map[domain.DeviceID]struct{},
) (voterReconciliationInput, error) {
	statuses := make(map[domain.DeviceID]device.Status)
	addMember := func(id domain.DeviceID) {
		if _, exists := statuses[id]; exists {
			return
		}
		member, exists := state.Admission.Member(id)
		if exists {
			statuses[id] = member.Status
		}
	}
	for _, server := range configuration.Configuration.Servers {
		addMember(domain.DeviceID(server.ID))
	}
	for _, id := range state.VoterSet.VoterDeviceIDs() {
		addMember(id)
	}
	for _, id := range state.CredentialAuthority.VoterDeviceIDs {
		addMember(id)
	}
	input := voterReconciliationInput{
		target:        state.VoterSet,
		authority:     state.CredentialAuthority.Clone(),
		configuration: configuration,
		localLeaderID: localLeader,
		memberStatus:  statuses,
		reachable:     cloneDeviceIDSet(ready),
		eligible:      cloneDeviceIDSet(eligible),
	}
	plan, _, valid := validateVoterReconciliationInput(input)
	if !valid {
		return voterReconciliationInput{}, fmt.Errorf(
			"%w: planner reason %d",
			ErrVoterReconciliationInvalid,
			plan.reason,
		)
	}
	return input, nil
}

func activeConfiguredSet(
	state decodedState,
	configuration raft.Configuration,
) map[domain.DeviceID]struct{} {
	result := make(map[domain.DeviceID]struct{})
	for _, server := range configuration.Servers {
		id := domain.DeviceID(server.ID)
		member, exists := state.Admission.Member(id)
		if exists && member.Status == device.StatusActive {
			result[id] = struct{}{}
		}
	}
	return result
}

func readyConfigurationDevices(
	candidate ConfigurationReadinessCandidate,
) map[domain.DeviceID]struct{} {
	credentialed := deviceIDSet(candidate.CurrentCredentialDeviceIDs)
	result := make(map[domain.DeviceID]struct{})
	for _, id := range candidate.ReachableDeviceIDs {
		if _, exists := credentialed[id]; exists {
			result[id] = struct{}{}
		}
	}
	return result
}

func cloneDeviceIDSet(
	source map[domain.DeviceID]struct{},
) map[domain.DeviceID]struct{} {
	result := make(map[domain.DeviceID]struct{}, len(source))
	for id := range source {
		result[id] = struct{}{}
	}
	return result
}

func reconciliationConfigurationChange(
	plan voterReconciliationPlan,
) (raftConfigurationChange, bool) {
	change := raftConfigurationChange{deviceID: plan.deviceID}
	switch plan.action {
	case voterReconciliationAddNonvoter:
		change.kind = raftChangeAddNonvoter
	case voterReconciliationPromoteVoter:
		change.kind = raftChangeAddVoter
	case voterReconciliationRemoveVoter,
		voterReconciliationRemoveNonvoter:
		change.kind = raftChangeRemoveServer
	default:
		return raftConfigurationChange{}, false
	}
	return change, change.validate() == nil
}

func (node *SingleNode) proveStagingVoter(
	ctx context.Context,
	state decodedState,
	configuration *committedRaftConfiguration,
	target domain.DeviceID,
) (voterEligibilityEvidence, error) {
	if node.checkpointRequester == nil {
		return voterEligibilityEvidence{},
			ErrVoterReconciliationUnavailable
	}
	if configuration == nil ||
		!configurationHasDeviceSuffrage(
			configuration.Configuration,
			target,
			raft.Nonvoter,
		) {
		return voterEligibilityEvidence{},
			errVoterReconciliationChanged
	}
	checkpoint, err := node.stagingCheckpointForCut(
		ctx,
		state,
		configuration,
		target,
	)
	if err != nil {
		return voterEligibilityEvidence{}, err
	}
	proof, err := requestStagingApplyProof(
		ctx,
		node.checkpointRequester,
		stagingCheckpointExpectation{
			targetDeviceID: target,
			record:         checkpoint.Record,
		},
	)
	if err != nil {
		return voterEligibilityEvidence{}, err
	}
	evidence, err := newStagingVoterEligibility(
		state,
		configuration,
		target,
		proof,
	)
	if err != nil {
		return voterEligibilityEvidence{}, err
	}
	currentState, _, currentConfiguration, err :=
		node.configurationChangeCut(ctx)
	if err != nil {
		return voterEligibilityEvidence{}, err
	}
	if currentConfiguration.Index != configuration.Index ||
		!sameVoterReconciliationState(
			state,
			currentState,
		) ||
		!evidence.validFor(currentState, currentConfiguration) {
		return voterEligibilityEvidence{},
			errVoterReconciliationChanged
	}
	return evidence, nil
}

func (node *SingleNode) stagingCheckpointForCut(
	ctx context.Context,
	state decodedState,
	configuration *committedRaftConfiguration,
	target domain.DeviceID,
) (store.AppliedCheckpointLookup, error) {
	if node == nil || ctx == nil || configuration == nil || !target.Valid() {
		return store.AppliedCheckpointLookup{}, ErrVoterReconciliationInvalid
	}
	attempt := node.stagingProofAttempt
	if attempt != nil &&
		attempt.target == target &&
		sameVoterActivationCut(
			attempt.state,
			&attempt.configuration,
			state,
			configuration,
		) &&
		attempt.checkpoint.Record.Validate() == nil &&
		attempt.checkpoint.Record.CoveredAppliedLogIndex >=
			configuration.Index {
		return attempt.checkpoint, nil
	}

	checkpoint, err := node.ForceCheckpoint(ctx)
	if err != nil {
		return store.AppliedCheckpointLookup{}, err
	}
	currentState, _, currentConfiguration, err :=
		node.configurationChangeCut(ctx)
	if err != nil {
		return store.AppliedCheckpointLookup{}, err
	}
	if !sameVoterActivationCut(
		state,
		configuration,
		currentState,
		currentConfiguration,
	) ||
		checkpoint.Record.CoveredAppliedLogIndex <
			currentConfiguration.Index {
		return store.AppliedCheckpointLookup{},
			errVoterReconciliationChanged
	}
	node.stagingProofAttempt = &stagingVoterProofAttempt{
		state: currentState,
		configuration: committedRaftConfiguration{
			Index:         currentConfiguration.Index,
			Configuration: currentConfiguration.Configuration.Clone(),
		},
		target:     target,
		checkpoint: checkpoint,
	}
	return checkpoint, nil
}

func reconcileActionError(
	plan voterReconciliationPlan,
	cause error,
) error {
	if cause == nil {
		return nil
	}
	return &voterReconciliationStallError{
		reason:   plan.reason,
		deviceID: plan.deviceID,
		cause:    cause,
	}
}

func reconciliationInputChanged(err error) bool {
	return errors.Is(err, errVoterReconciliationChanged) ||
		errors.Is(err, ErrStaleConfigurationChange) ||
		errors.Is(err, ErrConfigurationReadinessChanged) ||
		errors.Is(err, canonicalcoverage.ErrCoverageChanged)
}

func reconciliationPlanAtCut(
	state decodedState,
	configuration *committedRaftConfiguration,
	localLeader domain.DeviceID,
	readiness ConfigurationReadinessCandidate,
	eligibility voterEligibilitySet,
) (voterReconciliationPlan, error) {
	if configuration == nil {
		return voterReconciliationPlan{},
			ErrVoterReconciliationInvalid
	}
	input, err := voterReconciliationPlannerInput(
		state,
		*configuration,
		localLeader,
		readyConfigurationDevices(readiness),
		eligibility.plannerSet(state, configuration),
	)
	if err != nil {
		return voterReconciliationPlan{}, err
	}
	plan := planVoterReconciliation(input)
	if plan.action == voterReconciliationInvalid {
		return voterReconciliationPlan{}, fmt.Errorf(
			"%w: planner reason %d",
			ErrVoterReconciliationInvalid,
			plan.reason,
		)
	}
	return plan, nil
}

func requireExpectedReconciliationPlan(
	expected voterReconciliationPlan,
	actual voterReconciliationPlan,
) error {
	if expected != actual {
		return errVoterReconciliationChanged
	}
	return nil
}

func sameVoterReconciliationState(
	left decodedState,
	right decodedState,
) bool {
	return left.VoterSet.VoterSetVersion ==
		right.VoterSet.VoterSetVersion &&
		sameDeviceIDs(
			left.VoterSet.VoterDeviceIDs(),
			right.VoterSet.VoterDeviceIDs(),
		) &&
		left.CredentialAuthority.VoterSetVersion ==
			right.CredentialAuthority.VoterSetVersion &&
		sameDeviceIDs(
			left.CredentialAuthority.VoterDeviceIDs,
			right.CredentialAuthority.VoterDeviceIDs,
		)
}
