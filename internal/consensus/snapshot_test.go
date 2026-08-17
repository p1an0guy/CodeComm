package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestFSMSnapshotAnchorValidationAndRestoreRefusal(t *testing.T) {
	t.Parallel()

	fsm := newSnapshotTestFSM(t, true)
	snapshot, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	value, ok := snapshot.(*fsmSnapshot)
	if !ok {
		t.Fatalf("Snapshot() type = %T, want *fsmSnapshot", snapshot)
	}
	encoded := bytes.Clone(value.encoded)
	snapshot.Release()
	if len(value.encoded) != 0 {
		t.Fatal("Release() retained snapshot bytes")
	}

	if err := fsm.Restore(
		io.NopCloser(bytes.NewReader(encoded)),
	); !errors.Is(err, ErrSnapshotRestoreUnsupported) {
		t.Fatalf(
			"Restore(exact) error = %v, want ErrSnapshotRestoreUnsupported",
			err,
		)
	}

	var anchor snapshotAnchor
	if err := json.Unmarshal(encoded, &anchor); err != nil {
		t.Fatalf("json.Unmarshal(anchor): %v", err)
	}
	if anchor.Version != 2 {
		t.Fatalf("snapshot anchor version = %d, want 2", anchor.Version)
	}
	legacy := anchor
	legacy.Version = 1
	rawLegacy, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("json.Marshal(legacy anchor): %v", err)
	}
	encodedLegacy, err := codec.CanonicalizeSignedObject(rawLegacy)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(legacy anchor): %v", err)
	}
	if _, err := decodeSnapshotAnchor(encodedLegacy); !errors.Is(
		err,
		ErrInvalidSnapshotAnchor,
	) {
		t.Fatalf(
			"decodeSnapshotAnchor(version 1) error = %v, want ErrInvalidSnapshotAnchor",
			err,
		)
	}
	anchor.WorkspaceID = "550e8400-e29b-41d4-a716-446655440001"
	rawTampered, err := json.Marshal(anchor)
	if err != nil {
		t.Fatalf("json.Marshal(tampered anchor): %v", err)
	}
	tampered, err := codec.CanonicalizeSignedObject(rawTampered)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(tampered anchor): %v", err)
	}
	decoded, err := decodeSnapshotAnchor(tampered)
	if err != nil {
		t.Fatalf("decodeSnapshotAnchor(tampered): %v", err)
	}
	view, err := fsm.store.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if snapshotAnchorMatchesView(decoded, view) {
		t.Fatal("tampered snapshot anchor matches durable view")
	}
	if _, err := decodeSnapshotAnchor(
		append([]byte(" "), encoded...),
	); !errors.Is(err, ErrInvalidSnapshotAnchor) {
		t.Fatalf(
			"decodeSnapshotAnchor(noncanonical) error = %v, want ErrInvalidSnapshotAnchor",
			err,
		)
	}
	if _, err := decodeSnapshotAnchor(
		make([]byte, maxSnapshotAnchorBytes+1),
	); !errors.Is(err, ErrInvalidSnapshotAnchor) {
		t.Fatalf(
			"decodeSnapshotAnchor(oversized) error = %v, want ErrInvalidSnapshotAnchor",
			err,
		)
	}
	if err := fsm.Restore(nil); !errors.Is(err, ErrInvalidFSMOptions) {
		t.Fatalf(
			"Restore(nil) error = %v, want ErrInvalidFSMOptions",
			err,
		)
	}

	halted := fsm.halt(
		&raft.Log{Index: 3},
		ErrInvalidCommand,
	).Err
	select {
	case _, open := <-fsm.admissionChanged:
		if open {
			t.Fatal("FSM admission feed remained open after halt")
		}
	default:
		t.Fatal("FSM admission feed did not close synchronously on halt")
	}
	fsm.closePeerAdmissionChanges()
	fsm.publishPeerAdmission(nil, 1, true)
	if err := fsm.Restore(
		io.NopCloser(bytes.NewReader(encoded)),
	); !errors.Is(err, halted) {
		t.Fatalf("Restore(halted) error = %v, want %v", err, halted)
	}
}

func TestFSMSnapshotRequiresDurableRaftWatermark(t *testing.T) {
	t.Parallel()

	fsm := newSnapshotTestFSM(t, false)
	if _, err := fsm.Snapshot(); !errors.Is(
		err,
		raft.ErrNothingNewToSnapshot,
	) {
		t.Fatalf(
			"Snapshot() error = %v, want raft.ErrNothingNewToSnapshot",
			err,
		)
	}
}

func TestFSMSnapshotStopsTailAtLaterUnappliedCommand(t *testing.T) {
	t.Parallel()

	fsm := newSnapshotTestFSM(t, true)
	logs := raft.NewInmemStore()
	if err := logs.StoreLogs([]*raft.Log{
		{Index: 3, Term: 1, Type: raft.LogBarrier},
		{Index: 4, Term: 1, Type: raft.LogCommand, Data: []byte("later")},
	}); err != nil {
		t.Fatalf("StoreLogs(): %v", err)
	}
	fsm.logStore = logs

	snapshot, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	value := snapshot.(*fsmSnapshot)
	anchor, err := decodeSnapshotAnchor(value.encoded)
	if err != nil {
		t.Fatalf("decodeSnapshotAnchor(): %v", err)
	}
	if len(anchor.RaftTail) != 1 ||
		anchor.RaftTail[0].Index != 3 ||
		anchor.RaftTail[0].Type != "barrier" {
		t.Fatalf("RaftTail = %#v, want only barrier at index 3", anchor.RaftTail)
	}
}

func TestFSMSnapshotRefusesTruncatedNonCommandTail(t *testing.T) {
	t.Parallel()

	fsm := newSnapshotTestFSM(t, true)
	logs := raft.NewInmemStore()
	entries := make([]*raft.Log, 0, maxSnapshotRaftTail+1)
	for offset := range maxSnapshotRaftTail + 1 {
		entries = append(entries, &raft.Log{
			Index: uint64(offset + 3),
			Term:  1,
			Type:  raft.LogBarrier,
		})
	}
	if err := logs.StoreLogs(entries); err != nil {
		t.Fatalf("StoreLogs(): %v", err)
	}
	fsm.logStore = logs

	if _, err := fsm.Snapshot(); !errors.Is(
		err,
		ErrSnapshotRaftTailCoverage,
	) {
		t.Fatalf(
			"Snapshot() error = %v, want ErrSnapshotRaftTailCoverage",
			err,
		)
	}
	if err := fsm.HaltError(); err != nil {
		t.Fatalf("capacity refusal halted FSM: %v", err)
	}

	entries[len(entries)-1].Type = raft.LogCommand
	entries[len(entries)-1].Data = []byte("later")
	if err := logs.StoreLog(entries[len(entries)-1]); err != nil {
		t.Fatalf("StoreLog(command boundary): %v", err)
	}
	snapshot, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot(command boundary): %v", err)
	}
	anchor, err := decodeSnapshotAnchor(snapshot.(*fsmSnapshot).encoded)
	if err != nil {
		t.Fatalf("decodeSnapshotAnchor(): %v", err)
	}
	if len(anchor.RaftTail) != maxSnapshotRaftTail {
		t.Fatalf(
			"RaftTail length = %d, want %d",
			len(anchor.RaftTail),
			maxSnapshotRaftTail,
		)
	}
}

func TestSnapshotMetadataRequiresExactSingleLoopbackVoter(t *testing.T) {
	t.Parallel()

	_, _, deviceID := nodeTestInitialState(t)
	valid := raft.SnapshotMeta{
		Version: raft.SnapshotVersionMax,
		ID:      "snapshot",
		Index:   7,
		Term:    3,
		Configuration: raft.Configuration{Servers: []raft.Server{{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(deviceID),
			Address:  "127.0.0.1:12345",
		}}},
		ConfigurationIndex: 1,
		Size:               128,
	}
	if err := validateSingleVoterSnapshotMeta(
		&valid,
		deviceID,
	); err != nil {
		t.Fatalf("validateSingleVoterSnapshotMeta(valid): %v", err)
	}
	anchor := snapshotAnchor{
		CurrentTerm:             valid.Term,
		LastRaftAppliedLogIndex: valid.Index,
	}
	if err := validateSnapshotMetaAnchor(&valid, anchor); err != nil {
		t.Fatalf("validateSnapshotMetaAnchor(valid): %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*raft.SnapshotMeta)
	}{
		{
			name: "old version",
			mutate: func(meta *raft.SnapshotMeta) {
				meta.Version--
			},
		},
		{
			name: "zero index",
			mutate: func(meta *raft.SnapshotMeta) {
				meta.Index = 0
			},
		},
		{
			name: "zero term",
			mutate: func(meta *raft.SnapshotMeta) {
				meta.Term = 0
			},
		},
		{
			name: "configuration after snapshot",
			mutate: func(meta *raft.SnapshotMeta) {
				meta.ConfigurationIndex = meta.Index + 1
			},
		},
		{
			name: "wrong voter",
			mutate: func(meta *raft.SnapshotMeta) {
				meta.Configuration.Servers[0].ID = "other"
			},
		},
		{
			name: "nonvoter",
			mutate: func(meta *raft.SnapshotMeta) {
				meta.Configuration.Servers[0].Suffrage = raft.Nonvoter
			},
		},
		{
			name: "additional voter",
			mutate: func(meta *raft.SnapshotMeta) {
				meta.Configuration.Servers = append(
					meta.Configuration.Servers,
					meta.Configuration.Servers[0],
				)
			},
		},
		{
			name: "nonloopback address",
			mutate: func(meta *raft.SnapshotMeta) {
				meta.Configuration.Servers[0].Address = "192.0.2.1:12345"
			},
		},
		{
			name: "empty snapshot",
			mutate: func(meta *raft.SnapshotMeta) {
				meta.Size = 0
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			candidate.Configuration.Servers = append(
				[]raft.Server(nil),
				valid.Configuration.Servers...,
			)
			test.mutate(&candidate)
			if err := validateSingleVoterSnapshotMeta(
				&candidate,
				deviceID,
			); err == nil {
				t.Fatal("validateSingleVoterSnapshotMeta() accepted corruption")
			}
		})
	}

	for _, mutate := range []func(*snapshotAnchor){
		func(value *snapshotAnchor) { value.CurrentTerm++ },
		func(value *snapshotAnchor) { value.LastRaftAppliedLogIndex++ },
	} {
		candidate := anchor
		mutate(&candidate)
		if err := validateSnapshotMetaAnchor(
			&valid,
			candidate,
		); !errors.Is(err, ErrSnapshotAnchorCoverage) {
			t.Fatalf(
				"validateSnapshotMetaAnchor() error = %v, want ErrSnapshotAnchorCoverage",
				err,
			)
		}
	}
}

func newSnapshotTestFSM(t *testing.T, applyCommand bool) *FSM {
	t.Helper()

	initial, privateKey, deviceID := nodeTestInitialState(t)
	state, err := store.Open(context.Background(), store.Options{
		Path: filepath.Join(t.TempDir(), "state", "state.db"),
	})
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Errorf("store.Close(): %v", err)
		}
	})
	if _, err := state.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	fsm, err := NewFSM(FSMOptions{
		Store:                 state,
		OriginBootID:          nodeTestBootID1,
		ValidateConfiguration: validateDeviceAddressedSnapshotConfiguration,
		Clock: func() (domain.Timestamp, int64, error) {
			return "2026-08-11T13:00:00Z", 1, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFSM(): %v", err)
	}
	if !applyCommand {
		return fsm
	}

	signed := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"snapshot task",
	)
	response, ok := fsm.Apply(&raft.Log{
		Index: 2,
		Term:  1,
		Type:  raft.LogCommand,
		Data:  signed.CanonicalBytes(),
	}).(ApplyResponse)
	if !ok {
		t.Fatalf("Apply() response type is %T", response)
	}
	if response.Err != nil {
		t.Fatalf("Apply(): %v", response.Err)
	}
	return fsm
}
