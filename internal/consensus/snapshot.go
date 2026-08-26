package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	snapshotAnchorVersion  = 2
	maxSnapshotAnchorBytes = 8 << 10
	maxSnapshotRaftTail    = 64
)

var (
	ErrInvalidSnapshotAnchor      = errors.New("consensus: invalid snapshot anchor")
	ErrSnapshotStateMismatch      = errors.New("consensus: snapshot does not match durable state")
	ErrSnapshotRaftTailCoverage   = errors.New("consensus: snapshot Raft tail exceeds anchor capacity")
	ErrSnapshotRestoreUnsupported = errors.New(
		"consensus: snapshot restore is not implemented",
	)
)

type snapshotAnchor struct {
	Version                 uint64              `json:"version"`
	SessionID               string              `json:"session_id"`
	WorkspaceID             string              `json:"workspace_id"`
	RecoveryGeneration      uint64              `json:"recovery_generation"`
	CurrentTerm             uint64              `json:"current_term"`
	LastRaftAppliedLogIndex uint64              `json:"last_raft_applied_log_index"`
	ChainIndex              uint64              `json:"chain_index"`
	ChainHash               string              `json:"chain_hash"`
	ResultIndex             uint64              `json:"result_index"`
	ResultHash              string              `json:"result_hash"`
	ProjectionAccumulator   string              `json:"projection_accumulator"`
	ProjectionStateDigest   string              `json:"projection_state_digest"`
	DigestVersion           uint64              `json:"digest_version"`
	ProjectionSchemaVersion uint64              `json:"projection_schema_version"`
	RaftTail                []snapshotRaftEntry `json:"raft_tail"`
}

type snapshotRaftEntry struct {
	Index uint64 `json:"index"`
	Term  uint64 `json:"term"`
	Type  string `json:"type"`
}

func (fsm *FSM) Snapshot() (raft.FSMSnapshot, error) {
	if fsm == nil {
		return nil, ErrInvalidFSMOptions
	}
	if err := fsm.HaltError(); err != nil {
		return nil, err
	}
	if err := fsm.store.VerifyCommitmentHistory(
		context.Background(),
	); err != nil {
		return nil, fsm.haltSnapshot(fmt.Errorf(
			"consensus: verify history before snapshot: %w",
			err,
		))
	}
	view, err := fsm.store.View(context.Background())
	if err != nil {
		return nil, fsm.haltSnapshot(fmt.Errorf(
			"consensus: capture snapshot state: %w",
			err,
		))
	}
	if view.CurrentTerm == nil || view.LastRaftAppliedLogIndex == nil {
		return nil, raft.ErrNothingNewToSnapshot
	}
	tail, err := fsm.captureSnapshotRaftTail(view)
	if err != nil {
		if errors.Is(err, ErrSnapshotRaftTailCoverage) {
			return nil, err
		}
		return nil, fsm.haltSnapshot(err)
	}
	if fsm.snapshotSigner != nil {
		snapshot, err := fsm.captureLogicalRaftSnapshot(view, tail)
		if err != nil {
			if errors.Is(err, raft.ErrNothingNewToSnapshot) {
				return nil, err
			}
			return nil, fsm.haltSnapshot(err)
		}
		return snapshot, nil
	}
	encoded, err := encodeSnapshotAnchor(view, tail)
	if err != nil {
		return nil, fsm.haltSnapshot(err)
	}
	return &fsmSnapshot{encoded: encoded}, nil
}

func (fsm *FSM) haltSnapshot(cause error) error {
	return fsm.halt(nil, fmt.Errorf("snapshot integrity: %w", cause)).Err
}

func (fsm *FSM) Restore(reader io.ReadCloser) error {
	if fsm == nil || reader == nil {
		return ErrInvalidFSMOptions
	}
	if err := fsm.HaltError(); err != nil {
		return err
	}
	metadata, err := raftSnapshotMetadataFromReader(reader)
	if err != nil {
		return ErrSnapshotRestoreUnsupported
	}
	if fsm.snapshotDir == "" {
		return ErrSnapshotRestoreUnsupported
	}
	if err := fsm.restoreLogicalRaftSnapshot(reader, metadata); err != nil {
		closeErr := reader.Close()
		var rejectErr error
		if metadata.Reject != nil {
			rejectErr = metadata.Reject()
		}
		return fsm.haltSnapshot(errors.Join(err, closeErr, rejectErr))
	}
	return nil
}

type fsmSnapshot struct {
	encoded []byte
}

func (snapshot *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if snapshot == nil || sink == nil ||
		len(snapshot.encoded) == 0 ||
		len(snapshot.encoded) > maxSnapshotAnchorBytes {
		if sink != nil {
			_ = sink.Cancel()
		}
		return ErrInvalidSnapshotAnchor
	}
	if _, err := sink.Write(snapshot.encoded); err != nil {
		_ = sink.Cancel()
		return err
	}
	if err := sink.Close(); err != nil {
		_ = sink.Cancel()
		return err
	}
	return nil
}

func (snapshot *fsmSnapshot) Release() {
	if snapshot != nil {
		clear(snapshot.encoded)
		snapshot.encoded = nil
	}
}

func (fsm *FSM) captureSnapshotRaftTail(
	view store.StateView,
) ([]snapshotRaftEntry, error) {
	if view.LastRaftAppliedLogIndex == nil {
		return nil, ErrInvalidSnapshotAnchor
	}
	tail := make([]snapshotRaftEntry, 0)
	if fsm.logStore == nil {
		return tail, nil
	}
	lastIndex, err := fsm.logStore.LastIndex()
	if err != nil {
		return nil, fmt.Errorf(
			"consensus: inspect Raft log for snapshot: %w",
			err,
		)
	}
	appliedIndex := *view.LastRaftAppliedLogIndex
	if lastIndex < appliedIndex {
		if fsm.snapshotSigner == nil {
			return nil, ErrInvalidSnapshotAnchor
		}
		// Raft compaction can remove the command baseline after a verified
		// local or installed snapshot. Startup already proved that coverage;
		// captureLogicalRaftSnapshot will decline the repeated request until a
		// newer checkpoint command is retained.
		return tail, nil
	}
	if fsm.snapshotSigner != nil {
		var baseline raft.Log
		if err := fsm.logStore.GetLog(appliedIndex, &baseline); err != nil {
			if errors.Is(err, raft.ErrLogNotFound) {
				// A restored snapshot may have compacted the command baseline
				// while retaining newer entries after SnapshotMeta.Index.
				return tail, nil
			}
			return nil, fmt.Errorf(
				"consensus: read Raft snapshot baseline at %d: %w",
				appliedIndex,
				err,
			)
		}
	}
	for index := appliedIndex + 1; index <= lastIndex; index++ {
		var entry raft.Log
		if err := fsm.logStore.GetLog(index, &entry); err != nil {
			return nil, fmt.Errorf(
				"consensus: read Raft snapshot tail at %d: %w",
				index,
				err,
			)
		}
		if len(tail) == maxSnapshotRaftTail {
			if entry.Type == raft.LogCommand {
				break
			}
			return nil, ErrSnapshotRaftTailCoverage
		}
		entryType, ok := snapshotRaftEntryType(entry.Type)
		if !ok {
			// Raft may append a later command while its FSM is capturing an
			// earlier cut. Snapshot metadata cannot include that command
			// unless SQLite has applied it, so retain only the contiguous
			// non-command prefix and validate the actual metadata on reopen.
			if entry.Type == raft.LogCommand {
				break
			}
			return nil, ErrInvalidSnapshotAnchor
		}
		tail = append(tail, snapshotRaftEntry{
			Index: index,
			Term:  entry.Term,
			Type:  entryType,
		})
	}
	return tail, nil
}

func snapshotRaftEntryType(logType raft.LogType) (string, bool) {
	switch logType {
	case raft.LogBarrier:
		return "barrier", true
	case raft.LogConfiguration:
		return "configuration", true
	case raft.LogNoop:
		return "noop", true
	default:
		return "", false
	}
}

func encodeSnapshotAnchor(
	view store.StateView,
	tail []snapshotRaftEntry,
) ([]byte, error) {
	if view.CurrentTerm == nil || view.LastRaftAppliedLogIndex == nil {
		return nil, ErrInvalidSnapshotAnchor
	}
	anchor := snapshotAnchor{
		Version:                 snapshotAnchorVersion,
		SessionID:               string(view.SessionID),
		WorkspaceID:             string(view.WorkspaceID),
		RecoveryGeneration:      view.RecoveryGeneration,
		CurrentTerm:             *view.CurrentTerm,
		LastRaftAppliedLogIndex: *view.LastRaftAppliedLogIndex,
		ChainIndex:              view.Heads.ChainIndex,
		ChainHash: codec.EncodeBase64URL(
			view.Heads.ChainHash[:],
		),
		ResultIndex: view.Heads.ResultIndex,
		ResultHash:  codec.EncodeBase64URL(view.Heads.ResultHash[:]),
		ProjectionAccumulator: codec.EncodeBase64URL(
			view.Heads.ProjectionAccumulator[:],
		),
		ProjectionStateDigest: codec.EncodeBase64URL(
			view.ProjectionStateDigest[:],
		),
		DigestVersion:           view.Heads.DigestVersion,
		ProjectionSchemaVersion: view.Heads.ProjectionSchemaVersion,
		RaftTail: append(
			[]snapshotRaftEntry{},
			tail...,
		),
	}
	raw, err := json.Marshal(anchor)
	if err != nil {
		return nil, fmt.Errorf("consensus: encode snapshot anchor: %w", err)
	}
	encoded, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil, fmt.Errorf("consensus: canonicalize snapshot anchor: %w", err)
	}
	if len(encoded) > maxSnapshotAnchorBytes {
		return nil, ErrInvalidSnapshotAnchor
	}
	return encoded, nil
}

func decodeSnapshotAnchor(input []byte) (snapshotAnchor, error) {
	if len(input) == 0 || len(input) > maxSnapshotAnchorBytes {
		return snapshotAnchor{}, ErrInvalidSnapshotAnchor
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil || !bytes.Equal(input, canonical) {
		return snapshotAnchor{}, fmt.Errorf(
			"%w: noncanonical object",
			ErrInvalidSnapshotAnchor,
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var anchor snapshotAnchor
	if err := decoder.Decode(&anchor); err != nil {
		return snapshotAnchor{}, fmt.Errorf(
			"%w: %v",
			ErrInvalidSnapshotAnchor,
			err,
		)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return snapshotAnchor{}, ErrInvalidSnapshotAnchor
	}
	if err := validateSnapshotAnchor(anchor); err != nil {
		return snapshotAnchor{}, err
	}
	return anchor, nil
}

func validateSnapshotAnchor(anchor snapshotAnchor) error {
	if anchor.Version != snapshotAnchorVersion ||
		!domain.UUIDv7(anchor.SessionID).Valid() ||
		!domain.UUIDv4(anchor.WorkspaceID).Valid() ||
		!domain.ValidUnsignedInteger(anchor.RecoveryGeneration) ||
		anchor.CurrentTerm < 1 ||
		!domain.ValidUnsignedInteger(anchor.CurrentTerm) ||
		anchor.LastRaftAppliedLogIndex < 1 ||
		!domain.ValidUnsignedInteger(anchor.LastRaftAppliedLogIndex) ||
		!domain.ValidUnsignedInteger(anchor.ChainIndex) ||
		anchor.ResultIndex < 1 ||
		!domain.ValidUnsignedInteger(anchor.ResultIndex) ||
		anchor.ChainIndex > anchor.ResultIndex ||
		anchor.ResultIndex > anchor.LastRaftAppliedLogIndex ||
		anchor.DigestVersion < 1 ||
		!domain.ValidUnsignedInteger(anchor.DigestVersion) ||
		anchor.ProjectionSchemaVersion < 1 ||
		!domain.ValidUnsignedInteger(anchor.ProjectionSchemaVersion) ||
		anchor.RaftTail == nil ||
		len(anchor.RaftTail) > maxSnapshotRaftTail {
		return ErrInvalidSnapshotAnchor
	}
	previousIndex := anchor.LastRaftAppliedLogIndex
	previousTerm := anchor.CurrentTerm
	for _, entry := range anchor.RaftTail {
		if entry.Index != previousIndex+1 ||
			entry.Term < previousTerm ||
			!domain.ValidUnsignedInteger(entry.Index) ||
			entry.Term < 1 ||
			!domain.ValidUnsignedInteger(entry.Term) {
			return ErrInvalidSnapshotAnchor
		}
		switch entry.Type {
		case "barrier", "configuration", "noop":
		default:
			return ErrInvalidSnapshotAnchor
		}
		previousIndex = entry.Index
		previousTerm = entry.Term
	}
	for _, encoded := range []string{
		anchor.ChainHash,
		anchor.ResultHash,
		anchor.ProjectionAccumulator,
		anchor.ProjectionStateDigest,
	} {
		if _, err := codec.DecodeBase64URLExact(encoded, len(store.Digest{})); err != nil {
			return ErrInvalidSnapshotAnchor
		}
	}
	return nil
}

func snapshotAnchorMatchesView(
	anchor snapshotAnchor,
	view store.StateView,
) bool {
	if view.CurrentTerm == nil || view.LastRaftAppliedLogIndex == nil {
		return false
	}
	return anchor.Version == snapshotAnchorVersion &&
		anchor.SessionID == string(view.SessionID) &&
		anchor.WorkspaceID == string(view.WorkspaceID) &&
		anchor.RecoveryGeneration == view.RecoveryGeneration &&
		anchor.CurrentTerm == *view.CurrentTerm &&
		anchor.LastRaftAppliedLogIndex == *view.LastRaftAppliedLogIndex &&
		anchor.ChainIndex == view.Heads.ChainIndex &&
		anchor.ChainHash == codec.EncodeBase64URL(view.Heads.ChainHash[:]) &&
		anchor.ResultIndex == view.Heads.ResultIndex &&
		anchor.ResultHash == codec.EncodeBase64URL(view.Heads.ResultHash[:]) &&
		anchor.ProjectionAccumulator ==
			codec.EncodeBase64URL(view.Heads.ProjectionAccumulator[:]) &&
		anchor.ProjectionStateDigest ==
			codec.EncodeBase64URL(view.ProjectionStateDigest[:]) &&
		anchor.DigestVersion == view.Heads.DigestVersion &&
		anchor.ProjectionSchemaVersion ==
			view.Heads.ProjectionSchemaVersion
}
