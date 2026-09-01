package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
)

type voterPlacementOperatorStub struct {
	snapshot ui.Snapshot
	result   ui.CommandResult
	err      error
	requests []ui.SetVotersRequest
}

func (stub *voterPlacementOperatorStub) Status(
	context.Context,
) (ui.Snapshot, error) {
	return stub.snapshot, nil
}

func (stub *voterPlacementOperatorStub) SetVoters(
	_ context.Context,
	request ui.SetVotersRequest,
) (ui.CommandResult, error) {
	stub.requests = append(stub.requests, request)
	return stub.result, stub.err
}

func TestGuidedVoterPlacementBindsChoiceToFreshCAS(t *testing.T) {
	current := domain.DeviceID("cc1" + strings.Repeat("1", 64))
	joined := domain.DeviceID("cc1" + strings.Repeat("2", 64))
	accepted := ui.CommandResult{
		EventID: "018f47de-89ab-7def-8123-5123456789ab",
		Status:  store.OutcomeAccepted,
		Code:    "accepted",
	}
	for _, test := range []struct {
		name        string
		input       string
		wantChanged bool
		wantCalls   int
		wantErr     bool
	}{
		{name: "keep current", input: "current\n"},
		{name: "defer", input: "later\n"},
		{name: "empty defers", input: ""},
		{
			name:        "move to joined",
			input:       "joined\nyes\n",
			wantChanged: true,
			wantCalls:   1,
		},
		{name: "decline target confirmation", input: "joined\nno\n", wantErr: true},
		{name: "ambiguous choice", input: "both\n", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			operator := &voterPlacementOperatorStub{
				snapshot: voterPlacementSnapshot(current, joined),
				result:   accepted,
			}
			var prompt bytes.Buffer
			changed, result, err := runGuidedVoterPlacement(
				t.Context(),
				operator,
				"",
				strings.NewReader(test.input),
				&prompt,
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("runGuidedVoterPlacement() error = %v", err)
			}
			if changed != test.wantChanged ||
				len(operator.requests) != test.wantCalls {
				t.Fatalf(
					"runGuidedVoterPlacement() = changed %t, calls %d",
					changed,
					len(operator.requests),
				)
			}
			for _, required := range []string{
				"preferably the device most likely to stay awake and reachable",
				string(current),
				string(joined),
				"can read and work locally but cannot commit strong changes",
				"content links close when its credential expires",
			} {
				if !strings.Contains(prompt.String(), required) {
					t.Fatalf("prompt omitted %q:\n%s", required, prompt.String())
				}
			}
			if test.wantChanged {
				request := operator.requests[0]
				if request.ExpectedVoterSetVersion != 7 ||
					len(request.VoterDeviceIDs) != 1 ||
					request.VoterDeviceIDs[0] != joined ||
					result.EventID != accepted.EventID ||
					result.Status != accepted.Status ||
					result.Code != accepted.Code {
					t.Fatalf(
						"request/result = (%+v, %+v)",
						request,
						result,
					)
				}
				if !strings.Contains(
					prompt.String(),
					"Set voter target at version 7 to "+string(joined),
				) {
					t.Fatalf("confirmation did not bind the CAS:\n%s", prompt.String())
				}
			}
		})
	}
}

func TestGuidedVoterPlacementRequiresOwnerAndStableTwoDeviceTopology(
	t *testing.T,
) {
	current := domain.DeviceID("cc1" + strings.Repeat("1", 64))
	joined := domain.DeviceID("cc1" + strings.Repeat("2", 64))
	third := domain.DeviceID("cc1" + strings.Repeat("3", 64))
	base := voterPlacementSnapshot(current, joined)

	tests := []struct {
		name   string
		mutate func(*ui.Snapshot)
	}{
		{
			name: "local editor",
			mutate: func(snapshot *ui.Snapshot) {
				snapshot.Session.MemberRole = string(device.RoleEditor)
			},
		},
		{
			name: "inactive local member",
			mutate: func(snapshot *ui.Snapshot) {
				snapshot.Session.MemberStatus = string(device.StatusRevoked)
			},
		},
		{
			name: "truncated roster",
			mutate: func(snapshot *ui.Snapshot) {
				snapshot.MembersTruncated = true
				snapshot.MemberTotal = 3
			},
		},
		{
			name: "third active device",
			mutate: func(snapshot *ui.Snapshot) {
				snapshot.Members = append(snapshot.Members, ui.MemberStatus{
					DeviceID:      string(third),
					Role:          string(device.RoleEditor),
					Status:        string(device.StatusActive),
					EntityVersion: 1,
				})
				snapshot.MemberTotal = 3
			},
		},
		{
			name: "transition pending",
			mutate: func(snapshot *ui.Snapshot) {
				snapshot.Consensus.ConfigurationReconciled = false
				snapshot.Consensus.ReconciliationState =
					string(coordstatus.ReconciliationPending)
				snapshot.Consensus.ReconciliationStep =
					string(coordstatus.ReconciliationStepObserve)
			},
		},
		{
			name: "activated target differs",
			mutate: func(snapshot *ui.Snapshot) {
				snapshot.Consensus.ActivatedVoterDeviceIDs =
					[]string{string(joined)}
			},
		},
		{
			name:   "unknown expected joiner",
			mutate: func(snapshot *ui.Snapshot) {},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := base
			snapshot.Members = append([]ui.MemberStatus(nil), base.Members...)
			snapshot.Consensus.LiveVoterDeviceIDs = append(
				[]string(nil),
				base.Consensus.LiveVoterDeviceIDs...,
			)
			snapshot.Consensus.TargetVoterDeviceIDs = append(
				[]string(nil),
				base.Consensus.TargetVoterDeviceIDs...,
			)
			snapshot.Consensus.ActivatedVoterDeviceIDs = append(
				[]string(nil),
				base.Consensus.ActivatedVoterDeviceIDs...,
			)
			test.mutate(&snapshot)
			expectedJoiner := joined
			if test.name == "unknown expected joiner" {
				expectedJoiner = third
			}
			operator := &voterPlacementOperatorStub{snapshot: snapshot}
			changed, _, err := runGuidedVoterPlacement(
				t.Context(),
				operator,
				expectedJoiner,
				strings.NewReader("joined\nyes\n"),
				&bytes.Buffer{},
			)
			if !errors.Is(err, errVoterPlacementUnavailable) ||
				changed ||
				len(operator.requests) != 0 {
				t.Fatalf(
					"runGuidedVoterPlacement() = (%t, %v), calls %d",
					changed,
					err,
					len(operator.requests),
				)
			}
		})
	}
}

func voterPlacementSnapshot(
	current, joined domain.DeviceID,
) ui.Snapshot {
	return ui.Snapshot{
		Session: ui.SessionStatus{
			LocalDeviceID: string(current),
			MemberRole:    string(device.RoleOwner),
			MemberStatus:  string(device.StatusActive),
		},
		Consensus: ui.ConsensusStatus{
			LiveConfigurationSource: string(
				coordstatus.LiveConfigurationLocal,
			),
			LiveVoterDeviceIDs:      []string{string(current)},
			TargetVoterDeviceIDs:    []string{string(current)},
			ActivatedVoterDeviceIDs: []string{string(current)},
			VoterSetVersion:         7,
			ConfigurationReconciled: true,
			ReconciliationState:     string(coordstatus.ReconciliationStable),
			ReconciliationStep:      string(coordstatus.ReconciliationStepComplete),
			ReconciliationBlocker:   string(coordstatus.ReconciliationBlockerNone),
		},
		Members: []ui.MemberStatus{
			{
				DeviceID:      string(current),
				Role:          string(device.RoleOwner),
				Status:        string(device.StatusActive),
				EntityVersion: 1,
			},
			{
				DeviceID:      string(joined),
				Role:          string(device.RoleEditor),
				Status:        string(device.StatusActive),
				EntityVersion: 1,
			},
		},
		MemberTotal: 2,
	}
}
