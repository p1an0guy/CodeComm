package consensus

import (
	"errors"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/canonicalcoverage"
	"github.com/ijonahch/codecomm/internal/domain"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
)

const voterReconciliationDeadline = 30 * time.Second

type voterReconciliationStatus struct {
	mu        sync.Mutex
	cut       voterReconciliationStatusCut
	startedAt time.Time
	step      coordstatus.ReconciliationStep
	blocker   coordstatus.ReconciliationBlocker
	deviceID  domain.DeviceID
}

type voterReconciliationStatusCut struct {
	sessionID          domain.UUIDv7
	recoveryGeneration uint64
	targetVersion      uint64
	targetDeviceIDs    []domain.DeviceID
}

func voterReconciliationStatusCutFromState(
	state decodedState,
) voterReconciliationStatusCut {
	return voterReconciliationStatusCut{
		sessionID:          state.VoterSet.SessionID,
		recoveryGeneration: state.recoveryGeneration,
		targetVersion:      state.VoterSet.VoterSetVersion,
		targetDeviceIDs:    state.VoterSet.VoterDeviceIDs(),
	}
}

func (cut voterReconciliationStatusCut) valid() bool {
	return cut.sessionID.Valid() &&
		domain.ValidUnsignedInteger(cut.recoveryGeneration) &&
		cut.targetVersion >= 1 &&
		domain.ValidUnsignedInteger(cut.targetVersion) &&
		sortedUniqueDeviceIDs(cut.targetDeviceIDs)
}

func (cut voterReconciliationStatusCut) same(
	other voterReconciliationStatusCut,
) bool {
	return cut.sessionID == other.sessionID &&
		cut.recoveryGeneration == other.recoveryGeneration &&
		cut.targetVersion == other.targetVersion &&
		sameDeviceIDs(cut.targetDeviceIDs, other.targetDeviceIDs)
}

func (status *voterReconciliationStatus) observe(
	cut voterReconciliationStatusCut,
	plan voterReconciliationPlan,
	stable bool,
	at time.Time,
	err error,
) {
	if status == nil || !cut.valid() || at.IsZero() {
		return
	}
	status.mu.Lock()
	defer status.mu.Unlock()
	if stable {
		status.cut = cut
		status.startedAt = time.Time{}
		status.step = coordstatus.ReconciliationStepComplete
		status.blocker = coordstatus.ReconciliationBlockerNone
		status.deviceID = ""
		return
	}
	if !status.cut.same(cut) || status.startedAt.IsZero() {
		status.cut = cut
		status.startedAt = at
	}
	status.step = reconciliationStatusStep(plan.action)
	status.blocker, status.deviceID = reconciliationStatusBlocker(
		plan,
		err,
	)
}

func (status *voterReconciliationStatus) snapshot(
	cut voterReconciliationStatusCut,
	reconciled bool,
	at time.Time,
) (
	coordstatus.ReconciliationState,
	coordstatus.ReconciliationStep,
	coordstatus.ReconciliationBlocker,
	domain.DeviceID,
) {
	if status == nil || !cut.valid() || at.IsZero() {
		return coordstatus.ReconciliationPending,
			coordstatus.ReconciliationStepObserve,
			coordstatus.ReconciliationBlockerRetrying,
			""
	}
	status.mu.Lock()
	defer status.mu.Unlock()
	if reconciled {
		status.cut = cut
		status.startedAt = time.Time{}
		status.step = coordstatus.ReconciliationStepComplete
		status.blocker = coordstatus.ReconciliationBlockerNone
		status.deviceID = ""
		return coordstatus.ReconciliationStable,
			status.step,
			status.blocker,
			""
	}
	if !status.cut.same(cut) || status.startedAt.IsZero() {
		status.cut = cut
		status.startedAt = at
		status.step = coordstatus.ReconciliationStepObserve
		status.blocker = coordstatus.ReconciliationBlockerNone
		status.deviceID = ""
	}
	state := coordstatus.ReconciliationPending
	if !at.Before(status.startedAt.Add(voterReconciliationDeadline)) {
		state = coordstatus.ReconciliationReconciling
	}
	return state, status.step, status.blocker, status.deviceID
}

func reconciliationStatusStep(
	action voterReconciliationActionKind,
) coordstatus.ReconciliationStep {
	switch action {
	case voterReconciliationAddNonvoter:
		return coordstatus.ReconciliationStepAddNonvoter
	case voterReconciliationProveNonvoter:
		return coordstatus.ReconciliationStepProveNonvoter
	case voterReconciliationPromoteVoter:
		return coordstatus.ReconciliationStepPromoteVoter
	case voterReconciliationActivateAuthority:
		return coordstatus.ReconciliationStepActivateAuthority
	case voterReconciliationTransferLeadership:
		return coordstatus.ReconciliationStepTransferLeadership
	case voterReconciliationRemoveVoter:
		return coordstatus.ReconciliationStepRemoveVoter
	case voterReconciliationRemoveNonvoter:
		return coordstatus.ReconciliationStepRemoveNonvoter
	case voterReconciliationStable:
		return coordstatus.ReconciliationStepComplete
	default:
		return coordstatus.ReconciliationStepObserve
	}
}

func reconciliationStatusBlocker(
	plan voterReconciliationPlan,
	err error,
) (coordstatus.ReconciliationBlocker, domain.DeviceID) {
	deviceID := plan.deviceID
	if err == nil {
		return coordstatus.ReconciliationBlockerNone, deviceID
	}
	var stall *voterReconciliationStallError
	if errors.As(err, &stall) {
		if stall.deviceID.Valid() {
			deviceID = stall.deviceID
		}
		switch stall.reason {
		case voterReconciliationTargetUnavailable:
			return coordstatus.ReconciliationBlockerTargetUnavailable,
				deviceID
		case voterReconciliationNoTransferTarget:
			return coordstatus.ReconciliationBlockerLeadershipTransfer,
				deviceID
		case voterReconciliationNoRemovableVoter:
			return coordstatus.ReconciliationBlockerQuorum, deviceID
		}
	}
	var degraded *canonicalcoverage.DegradedError
	if errors.As(err, &degraded) {
		missing := degraded.MissingVoterDeviceIDs()
		if len(missing) != 0 {
			deviceID = missing[0]
		}
		return coordstatus.ReconciliationBlockerObjectCoverage, deviceID
	}
	switch {
	case errors.Is(err, ErrVoterReconciliationUnavailable),
		errors.Is(err, ErrConfigurationReadinessUnavailable):
		return coordstatus.ReconciliationBlockerCapabilityDisabled, deviceID
	case errors.Is(err, ErrConfigurationQuorumUnavailable),
		errors.Is(err, ErrConfigurationReadinessChanged):
		return coordstatus.ReconciliationBlockerReadiness, deviceID
	case errors.Is(err, ErrCheckpointProofUnavailable):
		return coordstatus.ReconciliationBlockerProofUnavailable, deviceID
	case errors.Is(err, ErrVoterActivationProofUnavailable),
		errors.Is(err, ErrVoterActivationOriginUnavailable):
		return coordstatus.ReconciliationBlockerActivationUnavailable, deviceID
	case errors.Is(err, ErrLeadershipTransferTargetMismatch):
		return coordstatus.ReconciliationBlockerLeadershipTransfer, deviceID
	case errors.Is(err, raft.ErrNotLeader),
		errors.Is(err, raft.ErrLeadershipLost),
		errors.Is(err, ErrLeadershipEpochChanged),
		errors.Is(err, errVoterReconciliationChanged),
		errors.Is(err, ErrStaleConfigurationChange):
		return coordstatus.ReconciliationBlockerRetrying, deviceID
	default:
		return coordstatus.ReconciliationBlockerRetrying, deviceID
	}
}
