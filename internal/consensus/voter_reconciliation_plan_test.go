package consensus

import (
	"fmt"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

const voterPlanSessionID = domain.UUIDv7(
	"018f47de-89ab-7def-8123-7123456789ab",
)

func TestVoterReconciliationPlansProtocolOrder(t *testing.T) {
	a, b, c, d := voterPlanID(1), voterPlanID(2), voterPlanID(3), voterPlanID(4)
	tests := []struct {
		name       string
		input      voterReconciliationInput
		want       voterReconciliationActionKind
		wantID     domain.DeviceID
		wantReason voterReconciliationReason
	}{
		{
			name: "add lowest missing target before proving staged target",
			input: voterPlanWithTargetVersion(
				voterPlanInput(
					[]domain.DeviceID{a, b, c},
					[]raft.Server{
						voterPlanServer(a, raft.Voter),
						voterPlanServer(c, raft.Nonvoter),
					},
					a,
				),
				2,
			),
			want:   voterReconciliationAddNonvoter,
			wantID: b,
		},
		{
			name: "prove lowest reachable unproven nonvoter",
			input: voterPlanWithEligible(
				voterPlanWithTargetVersion(
					voterPlanInput(
						[]domain.DeviceID{a, b, c},
						[]raft.Server{
							voterPlanServer(a, raft.Voter),
							voterPlanServer(b, raft.Nonvoter),
							voterPlanServer(c, raft.Nonvoter),
						},
						a,
					),
					2,
				),
				c,
			),
			want:   voterReconciliationProveNonvoter,
			wantID: b,
		},
		{
			name: "promote lowest proven nonvoter",
			input: voterPlanWithEligible(
				voterPlanWithTargetVersion(
					voterPlanInput(
						[]domain.DeviceID{a, b, c},
						[]raft.Server{
							voterPlanServer(a, raft.Voter),
							voterPlanServer(b, raft.Nonvoter),
							voterPlanServer(c, raft.Nonvoter),
						},
						a,
					),
					2,
				),
				b, c,
			),
			want:   voterReconciliationPromoteVoter,
			wantID: b,
		},
		{
			name: "skip unreachable lower nonvoter and prove reachable target",
			input: voterPlanWithoutReachability(
				voterPlanWithEligible(
					voterPlanWithTargetVersion(
						voterPlanInput(
							[]domain.DeviceID{a, b, c},
							[]raft.Server{
								voterPlanServer(a, raft.Voter),
								voterPlanServer(b, raft.Nonvoter),
								voterPlanServer(c, raft.Nonvoter),
							},
							a,
						),
						2,
					),
					b,
				),
				b,
			),
			want:   voterReconciliationProveNonvoter,
			wantID: c,
		},
		{
			name: "stall on lowest target when no nonvoter is reachable",
			input: voterPlanWithoutReachability(
				voterPlanWithTargetVersion(
					voterPlanInput(
						[]domain.DeviceID{a, b, c},
						[]raft.Server{
							voterPlanServer(a, raft.Voter),
							voterPlanServer(b, raft.Nonvoter),
							voterPlanServer(c, raft.Nonvoter),
						},
						a,
					),
					2,
				),
				b,
				c,
			),
			want:       voterReconciliationStalled,
			wantID:     b,
			wantReason: voterReconciliationTargetUnavailable,
		},
		{
			name: "activate authority before transfer or removal",
			input: voterPlanWithTargetVersion(
				voterPlanInput(
					[]domain.DeviceID{b},
					[]raft.Server{
						voterPlanServer(a, raft.Voter),
						voterPlanServer(b, raft.Voter),
					},
					a,
				),
				2,
			),
			want: voterReconciliationActivateAuthority,
		},
		{
			name: "transfer to lowest reachable eligible target",
			input: voterPlanWithEligible(
				voterPlanInput(
					[]domain.DeviceID{b, c, d},
					[]raft.Server{
						voterPlanServer(a, raft.Voter),
						voterPlanServer(b, raft.Voter),
						voterPlanServer(c, raft.Voter),
						voterPlanServer(d, raft.Voter),
					},
					a,
				),
				b, c, d,
			),
			want:   voterReconciliationTransferLeadership,
			wantID: b,
		},
		{
			name: "skip unreachable lower transfer target",
			input: voterPlanWithoutReachability(
				voterPlanWithEligible(
					voterPlanInput(
						[]domain.DeviceID{b, c, d},
						[]raft.Server{
							voterPlanServer(a, raft.Voter),
							voterPlanServer(b, raft.Voter),
							voterPlanServer(c, raft.Voter),
							voterPlanServer(d, raft.Voter),
						},
						a,
					),
					b, c, d,
				),
				b,
			),
			want:   voterReconciliationTransferLeadership,
			wantID: c,
		},
		{
			name: "leader outside target stalls without transfer target",
			input: voterPlanWithEligible(
				voterPlanInput(
					[]domain.DeviceID{b},
					[]raft.Server{
						voterPlanServer(a, raft.Voter),
						voterPlanServer(b, raft.Voter),
					},
					a,
				),
			),
			want:       voterReconciliationStalled,
			wantReason: voterReconciliationNoTransferTarget,
		},
		{
			name: "remove revoked voter before unreachable voter",
			input: voterPlanWithStatus(
				voterPlanWithoutReachability(
					voterPlanInput(
						[]domain.DeviceID{a},
						[]raft.Server{
							voterPlanServer(a, raft.Voter),
							voterPlanServer(b, raft.Voter),
							voterPlanServer(c, raft.Voter),
							voterPlanServer(d, raft.Voter),
							voterPlanServer(voterPlanID(5), raft.Voter),
						},
						a,
					),
					b,
				),
				c, device.StatusRevoked,
			),
			want:   voterReconciliationRemoveVoter,
			wantID: c,
		},
		{
			name: "remove unreachable voter before reachable voter",
			input: voterPlanWithoutReachability(
				voterPlanInput(
					[]domain.DeviceID{a},
					[]raft.Server{
						voterPlanServer(a, raft.Voter),
						voterPlanServer(b, raft.Voter),
						voterPlanServer(c, raft.Voter),
					},
					a,
				),
				c,
			),
			want:   voterReconciliationRemoveVoter,
			wantID: c,
		},
		{
			name: "remove extra voter by device ID",
			input: voterPlanInput(
				[]domain.DeviceID{a},
				[]raft.Server{
					voterPlanServer(a, raft.Voter),
					voterPlanServer(b, raft.Voter),
					voterPlanServer(c, raft.Voter),
				},
				a,
			),
			want:   voterReconciliationRemoveVoter,
			wantID: b,
		},
		{
			name: "unsafe voter removal stalls",
			input: voterPlanWithoutReachability(
				voterPlanInput(
					[]domain.DeviceID{a},
					[]raft.Server{
						voterPlanServer(a, raft.Voter),
						voterPlanServer(b, raft.Voter),
						voterPlanServer(c, raft.Voter),
					},
					a,
				),
				b, c,
			),
			want:       voterReconciliationStalled,
			wantReason: voterReconciliationNoRemovableVoter,
		},
		{
			name: "remove lowest obsolete nonvoter after voters settle",
			input: voterPlanInput(
				[]domain.DeviceID{a},
				[]raft.Server{
					voterPlanServer(a, raft.Voter),
					voterPlanServer(c, raft.Nonvoter),
					voterPlanServer(b, raft.Nonvoter),
				},
				a,
			),
			want:   voterReconciliationRemoveNonvoter,
			wantID: b,
		},
		{
			name: "stable exact target and authority",
			input: voterPlanInput(
				[]domain.DeviceID{a, b, c},
				[]raft.Server{
					voterPlanServer(c, raft.Voter),
					voterPlanServer(a, raft.Voter),
					voterPlanServer(b, raft.Voter),
				},
				a,
			),
			want: voterReconciliationStable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := planVoterReconciliation(test.input)
			if got.action != test.want ||
				got.deviceID != test.wantID ||
				got.reason != test.wantReason {
				t.Fatalf("planVoterReconciliation() = %#v", got)
			}
			if got.configurationIndex != test.input.configuration.Index {
				t.Fatalf(
					"configuration index = %d, want %d",
					got.configurationIndex,
					test.input.configuration.Index,
				)
			}
			if repeated := planVoterReconciliation(test.input); repeated != got {
				t.Fatalf("repeated plan changed: %#v != %#v", repeated, got)
			}
		})
	}
}

func TestVoterReconciliationRejectsInvalidInputs(t *testing.T) {
	a, b := voterPlanID(1), voterPlanID(2)
	base := voterPlanInput(
		[]domain.DeviceID{a},
		[]raft.Server{
			voterPlanServer(a, raft.Voter),
			voterPlanServer(b, raft.Nonvoter),
		},
		a,
	)
	tests := []struct {
		name   string
		mutate func(*voterReconciliationInput)
		reason voterReconciliationReason
	}{
		{
			name: "target",
			mutate: func(input *voterReconciliationInput) {
				input.target = voterset.Set{}
			},
			reason: voterReconciliationInvalidTarget,
		},
		{
			name: "authority",
			mutate: func(input *voterReconciliationInput) {
				input.authority.VoterSetVersion = 2
			},
			reason: voterReconciliationInvalidAuthority,
		},
		{
			name: "configuration index",
			mutate: func(input *voterReconciliationInput) {
				input.configuration.Index = 0
			},
			reason: voterReconciliationInvalidConfiguration,
		},
		{
			name: "configuration address",
			mutate: func(input *voterReconciliationInput) {
				input.configuration.Configuration.Servers[0].Address = "wrong"
			},
			reason: voterReconciliationInvalidConfiguration,
		},
		{
			name: "leader is nonvoter",
			mutate: func(input *voterReconciliationInput) {
				input.localLeaderID = b
			},
			reason: voterReconciliationInvalidLeader,
		},
		{
			name: "leader is not reachable",
			mutate: func(input *voterReconciliationInput) {
				delete(input.reachable, a)
			},
			reason: voterReconciliationInvalidLeader,
		},
		{
			name: "missing member status",
			mutate: func(input *voterReconciliationInput) {
				delete(input.memberStatus, b)
			},
			reason: voterReconciliationInvalidMembers,
		},
		{
			name: "target member revoked",
			mutate: func(input *voterReconciliationInput) {
				input.memberStatus[a] = device.StatusRevoked
			},
			reason: voterReconciliationInvalidMembers,
		},
		{
			name: "unknown reachable member",
			mutate: func(input *voterReconciliationInput) {
				input.reachable[voterPlanID(9)] = struct{}{}
			},
			reason: voterReconciliationInvalidReachability,
		},
		{
			name: "eligible device outside target",
			mutate: func(input *voterReconciliationInput) {
				input.eligible[b] = struct{}{}
			},
			reason: voterReconciliationInvalidEligibility,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneVoterPlanInput(base)
			test.mutate(&input)
			got := planVoterReconciliation(input)
			if got.action != voterReconciliationInvalid ||
				got.reason != test.reason ||
				got.deviceID != "" ||
				got.configurationIndex != 0 {
				t.Fatalf("planVoterReconciliation() = %#v", got)
			}
		})
	}
}

func voterPlanInput(
	targetIDs []domain.DeviceID,
	servers []raft.Server,
	leaderID domain.DeviceID,
) voterReconciliationInput {
	target, err := voterset.New(voterPlanSessionID, targetIDs, 1)
	if err != nil {
		panic(err)
	}
	statuses := make(map[domain.DeviceID]device.Status)
	reachable := make(map[domain.DeviceID]struct{})
	for _, id := range targetIDs {
		statuses[id] = device.StatusActive
		reachable[id] = struct{}{}
	}
	for _, server := range servers {
		id := domain.DeviceID(server.ID)
		statuses[id] = device.StatusActive
		reachable[id] = struct{}{}
	}
	return voterReconciliationInput{
		target: target,
		authority: credentialauthority.Authority{
			SessionID:        voterPlanSessionID,
			VoterDeviceIDs:   append([]domain.DeviceID(nil), targetIDs...),
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		},
		configuration: committedRaftConfiguration{
			Index: 17,
			Configuration: raft.Configuration{
				Servers: append([]raft.Server(nil), servers...),
			},
		},
		localLeaderID: leaderID,
		memberStatus:  statuses,
		reachable:     reachable,
		eligible:      make(map[domain.DeviceID]struct{}),
	}
}

func voterPlanWithTargetVersion(
	input voterReconciliationInput,
	version uint64,
) voterReconciliationInput {
	target, err := voterset.New(
		input.target.SessionID,
		input.target.VoterDeviceIDs(),
		version,
	)
	if err != nil {
		panic(err)
	}
	input.target = target
	input.authority = credentialauthority.Authority{
		SessionID:        voterPlanSessionID,
		VoterDeviceIDs:   []domain.DeviceID{voterPlanID(1)},
		VoterSetVersion:  1,
		ActivationSource: credentialauthority.ActivationGenesis,
	}
	return input
}

func voterPlanWithEligible(
	input voterReconciliationInput,
	deviceIDs ...domain.DeviceID,
) voterReconciliationInput {
	for _, deviceID := range deviceIDs {
		input.eligible[deviceID] = struct{}{}
	}
	return input
}

func voterPlanWithoutReachability(
	input voterReconciliationInput,
	deviceIDs ...domain.DeviceID,
) voterReconciliationInput {
	for _, deviceID := range deviceIDs {
		delete(input.reachable, deviceID)
	}
	return input
}

func voterPlanWithStatus(
	input voterReconciliationInput,
	deviceID domain.DeviceID,
	status device.Status,
) voterReconciliationInput {
	input.memberStatus[deviceID] = status
	return input
}

func cloneVoterPlanInput(
	input voterReconciliationInput,
) voterReconciliationInput {
	result := input
	result.configuration = committedRaftConfiguration{
		Index:         input.configuration.Index,
		Configuration: input.configuration.Configuration.Clone(),
	}
	result.memberStatus = make(map[domain.DeviceID]device.Status)
	for id, status := range input.memberStatus {
		result.memberStatus[id] = status
	}
	result.reachable = make(map[domain.DeviceID]struct{})
	for id := range input.reachable {
		result.reachable[id] = struct{}{}
	}
	result.eligible = make(map[domain.DeviceID]struct{})
	for id := range input.eligible {
		result.eligible[id] = struct{}{}
	}
	return result
}

func voterPlanServer(
	deviceID domain.DeviceID,
	suffrage raft.ServerSuffrage,
) raft.Server {
	return raft.Server{
		ID:       raft.ServerID(deviceID),
		Address:  raft.ServerAddress(deviceID),
		Suffrage: suffrage,
	}
}

func voterPlanID(value int) domain.DeviceID {
	return domain.DeviceID(fmt.Sprintf("cc1%064x", value))
}
