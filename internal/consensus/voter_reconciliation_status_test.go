package consensus

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/canonicalcoverage"
	"github.com/ijonahch/codecomm/internal/domain"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
)

func TestVoterReconciliationStatusTracksDeadlineAcrossSteps(
	t *testing.T,
) {
	first := voterReconciliationStatusTestID('1')
	second := voterReconciliationStatusTestID('2')
	cut := voterReconciliationStatusCut{
		sessionID:          nodeTestSessionID,
		recoveryGeneration: 0,
		targetVersion:      2,
		targetDeviceIDs:    []domain.DeviceID{first, second, voterReconciliationStatusTestID('3')},
	}
	startedAt := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	var status voterReconciliationStatus
	status.observe(
		cut,
		voterReconciliationPlan{
			action:   voterReconciliationAddNonvoter,
			deviceID: first,
		},
		false,
		startedAt,
		nil,
	)

	state, step, blocker, deviceID := status.snapshot(
		cut,
		false,
		startedAt.Add(voterReconciliationDeadline-time.Nanosecond),
	)
	if state != coordstatus.ReconciliationPending ||
		step != coordstatus.ReconciliationStepAddNonvoter ||
		blocker != coordstatus.ReconciliationBlockerNone ||
		deviceID != first {
		t.Fatalf(
			"pre-deadline snapshot = (%q, %q, %q, %q)",
			state,
			step,
			blocker,
			deviceID,
		)
	}

	status.observe(
		cut,
		voterReconciliationPlan{
			action:   voterReconciliationPromoteVoter,
			deviceID: second,
		},
		false,
		startedAt.Add(20*time.Second),
		ErrConfigurationQuorumUnavailable,
	)
	state, step, blocker, deviceID = status.snapshot(
		cut,
		false,
		startedAt.Add(voterReconciliationDeadline),
	)
	if state != coordstatus.ReconciliationReconciling ||
		step != coordstatus.ReconciliationStepPromoteVoter ||
		blocker != coordstatus.ReconciliationBlockerReadiness ||
		deviceID != second {
		t.Fatalf(
			"deadline snapshot = (%q, %q, %q, %q)",
			state,
			step,
			blocker,
			deviceID,
		)
	}

	nextCut := cut
	nextCut.targetVersion++
	state, step, blocker, deviceID = status.snapshot(
		nextCut,
		false,
		startedAt.Add(time.Hour),
	)
	if state != coordstatus.ReconciliationPending ||
		step != coordstatus.ReconciliationStepObserve ||
		blocker != coordstatus.ReconciliationBlockerNone ||
		deviceID != "" {
		t.Fatalf(
			"new-target snapshot = (%q, %q, %q, %q)",
			state,
			step,
			blocker,
			deviceID,
		)
	}

	state, step, blocker, deviceID = status.snapshot(
		nextCut,
		true,
		startedAt.Add(time.Hour),
	)
	if state != coordstatus.ReconciliationStable ||
		step != coordstatus.ReconciliationStepComplete ||
		blocker != coordstatus.ReconciliationBlockerNone ||
		deviceID != "" {
		t.Fatalf(
			"stable snapshot = (%q, %q, %q, %q)",
			state,
			step,
			blocker,
			deviceID,
		)
	}
}

func TestVoterReconciliationStatusClassifiesOperatorBlockers(
	t *testing.T,
) {
	plan := voterReconciliationPlan{
		action:   voterReconciliationRemoveVoter,
		deviceID: voterReconciliationStatusTestID('1'),
	}
	_, coverageErr := canonicalcoverage.NewGate(nil)
	tests := []struct {
		name string
		err  error
		want coordstatus.ReconciliationBlocker
	}{
		{
			name: "capability",
			err:  ErrVoterReconciliationUnavailable,
			want: coordstatus.ReconciliationBlockerCapabilityDisabled,
		},
		{
			name: "coverage",
			err:  coverageErr,
			want: coordstatus.ReconciliationBlockerObjectCoverage,
		},
		{
			name: "readiness",
			err:  ErrConfigurationQuorumUnavailable,
			want: coordstatus.ReconciliationBlockerReadiness,
		},
		{
			name: "proof",
			err:  ErrCheckpointProofUnavailable,
			want: coordstatus.ReconciliationBlockerProofUnavailable,
		},
		{
			name: "activation",
			err:  ErrVoterActivationProofUnavailable,
			want: coordstatus.ReconciliationBlockerActivationUnavailable,
		},
		{
			name: "leadership",
			err:  ErrLeadershipEpochChanged,
			want: coordstatus.ReconciliationBlockerRetrying,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, deviceID := reconciliationStatusBlocker(
				plan,
				test.err,
			)
			if got != test.want || deviceID != plan.deviceID {
				t.Fatalf(
					"reconciliationStatusBlocker() = (%q, %q), want (%q, %q)",
					got,
					deviceID,
					test.want,
					plan.deviceID,
				)
			}
		})
	}

	stall := &voterReconciliationStallError{
		reason:   voterReconciliationTargetUnavailable,
		deviceID: voterReconciliationStatusTestID('2'),
		cause:    errors.New("offline"),
	}
	blocker, deviceID := reconciliationStatusBlocker(plan, stall)
	if blocker != coordstatus.ReconciliationBlockerTargetUnavailable ||
		deviceID != stall.deviceID {
		t.Fatalf(
			"stall blocker = (%q, %q)",
			blocker,
			deviceID,
		)
	}
}

func voterReconciliationStatusTestID(value byte) domain.DeviceID {
	return domain.DeviceID("cc1" + strings.Repeat(string(value), 64))
}
