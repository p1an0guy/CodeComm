package status

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

const (
	statusTestSessionID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-0123456789ab",
	)
	statusTestWorkspaceID = domain.UUIDv4(
		"550e8400-e29b-41d4-a716-446655440000",
	)
)

func TestSnapshotValidateSettledUnknownConfiguration(t *testing.T) {
	snapshot := settledUnknownSnapshot(t)
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*RuntimeSnapshot)
	}{
		{
			name: "unclosed source",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.LiveConfigurationSource = "cached"
			},
		},
		{
			name: "leader",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.LeaderDeviceID = runtime.LocalDeviceID
			},
		},
		{
			name: "live voter",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.LiveVoterDeviceIDs = []domain.DeviceID{
					runtime.LocalDeviceID,
				}
			},
		},
		{
			name: "live nonvoter",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.LiveNonvoterDeviceIDs = []domain.DeviceID{
					runtime.LocalDeviceID,
				}
			},
		},
		{
			name: "quorum",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.QuorumRequired = 1
			},
		},
		{
			name: "exactness claim",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.ConfigurationReconciled = true
			},
		},
		{
			name: "known reconciliation",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.ReconciliationState = ReconciliationStable
			},
		},
		{
			name: "reconciliation step",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.ReconciliationStep = ReconciliationStepComplete
			},
		},
		{
			name: "reconciliation blocker",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.ReconciliationBlocker = ReconciliationBlockerRetrying
			},
		},
		{
			name: "reconciliation device",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.ReconciliationDeviceID = runtime.LocalDeviceID
			},
		},
		{
			name: "raft role",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.Role = RoleFollower
			},
		},
		{
			name: "available writes",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.StrongWrites = StrongWritesAvailable
			},
		},
		{
			name: "Raft currency",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.ReplicaCurrency = ReplicaCurrencyRaft
			},
		},
		{
			name: "current without authority observations",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.ReplicaCurrency = ReplicaCurrencyCurrent
			},
		},
		{
			name: "behind without a higher watermark",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.ReplicaCurrency = ReplicaCurrencyBehind
			},
		},
		{
			name: "unknown with a higher watermark",
			mutate: func(runtime *RuntimeSnapshot) {
				runtime.ObservedResultIndex = 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := settledUnknownSnapshot(t)
			test.mutate(&candidate.Runtime)
			if err := candidate.Validate(); !errors.Is(
				err,
				ErrInvalidSnapshot,
			) {
				t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidSnapshot)
			}
		})
	}
}

func TestSnapshotValidateSettledCurrencyEvidence(t *testing.T) {
	current := settledUnknownSnapshot(t)
	current.Runtime.ReplicaCurrency = ReplicaCurrencyCurrent
	current.Runtime.ObservedAuthorityIDs = current.Durable.
		CredentialAuthority.VoterDeviceIDs()
	current.Runtime.ObservedResultIndex = current.Durable.Heads.ResultIndex
	if err := current.Validate(); err != nil {
		t.Fatalf("Validate(current): %v", err)
	}

	behind := settledUnknownSnapshot(t)
	behind.Runtime.ReplicaCurrency = ReplicaCurrencyBehind
	behind.Runtime.ObservedResultIndex =
		behind.Durable.Heads.ResultIndex + 1
	if err := behind.Validate(); err != nil {
		t.Fatalf("Validate(behind): %v", err)
	}
}

func TestSnapshotValidateVoterReportedConfigurationDoesNotInferReconciliation(
	t *testing.T,
) {
	snapshot := settledUnknownSnapshot(t)
	snapshot.Runtime.LiveConfigurationSource =
		LiveConfigurationVoterReported
	snapshot.Runtime.LeaderDeviceID = snapshot.Runtime.LocalDeviceID
	snapshot.Runtime.LiveVoterDeviceIDs = []domain.DeviceID{
		snapshot.Runtime.LocalDeviceID,
	}
	snapshot.Runtime.QuorumRequired = 1
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}

	snapshot.Runtime.ConfigurationReconciled = true
	if err := snapshot.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidSnapshot)
	}
}

func TestSnapshotValidateLocalConfigurationRetainsExactness(t *testing.T) {
	snapshot := localSnapshot(t)
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}

	snapshot.Runtime.ConfigurationReconciled = false
	if err := snapshot.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidSnapshot)
	}
}

func settledUnknownSnapshot(t *testing.T) Snapshot {
	t.Helper()
	snapshot := localSnapshot(t)
	snapshot.Runtime = RuntimeSnapshot{
		State:                   ConsensusSettled,
		Role:                    RoleNonvoter,
		LocalDeviceID:           snapshot.Durable.Member.ID,
		LiveConfigurationSource: LiveConfigurationUnknown,
		LiveVoterDeviceIDs:      []domain.DeviceID{},
		LiveNonvoterDeviceIDs:   []domain.DeviceID{},
		StrongWrites:            StrongWritesWaiting,
		ReplicaCurrency:         ReplicaCurrencyUnknown,
		ObservedAuthorityIDs:    []domain.DeviceID{},
		ReconciliationState:     ReconciliationUnknown,
		ReconciliationStep:      ReconciliationStepObserve,
		ReconciliationBlocker:   ReconciliationBlockerNone,
	}
	return snapshot
}

func localSnapshot(t *testing.T) Snapshot {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat(
		[]byte{0x42},
		ed25519.SeedSize,
	))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	member := device.Device{
		ID:                deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: publicKey,
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	target, err := voterset.New(
		statusTestSessionID,
		[]domain.DeviceID{deviceID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	term := uint64(1)
	applied := uint64(1)
	return Snapshot{
		Durable: DurableSnapshot{
			SessionID:          statusTestSessionID,
			WorkspaceID:        statusTestWorkspaceID,
			RecoveryGeneration: 0,
			Heads: AppliedHeads{
				CurrentTerm:             &term,
				LastRaftAppliedLogIndex: &applied,
				DigestVersion:           1,
				ProjectionSchemaVersion: 1,
			},
			Member: member,
			Members: []MemberSummary{{
				ID:            member.ID,
				Role:          member.Role,
				Status:        member.Status,
				EntityVersion: member.EntityVersion,
			}},
			MemberTotal:         1,
			VoterSet:            target,
			CredentialAuthority: target,
		},
		Runtime: RuntimeSnapshot{
			State:                   ConsensusReady,
			Role:                    RoleLeader,
			LocalDeviceID:           deviceID,
			LeaderDeviceID:          deviceID,
			LiveConfigurationSource: LiveConfigurationLocal,
			LiveVoterDeviceIDs:      []domain.DeviceID{deviceID},
			LiveNonvoterDeviceIDs:   []domain.DeviceID{},
			QuorumRequired:          1,
			StrongWrites:            StrongWritesAvailable,
			ReplicaCurrency:         ReplicaCurrencyRaft,
			ObservedAuthorityIDs:    []domain.DeviceID{},
			ConfigurationReconciled: true,
			ReconciliationState:     ReconciliationStable,
			ReconciliationStep:      ReconciliationStepComplete,
			ReconciliationBlocker:   ReconciliationBlockerNone,
		},
	}
}
