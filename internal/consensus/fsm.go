package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	ErrInvalidFSMOptions = errors.New("consensus: invalid FSM options")
	ErrFSMHalted         = errors.New("consensus: FSM integrity halt")
	ErrInvalidCommand    = errors.New("consensus: invalid committed command")
)

// ApplyClock returns local apply provenance. The timestamp and monotonic value
// are never reducer inputs or replicated commitments.
type ApplyClock func() (domain.Timestamp, int64, error)

// NewSystemApplyClock returns a same-boot monotonic clock plus canonical UTC
// display timestamps.
func NewSystemApplyClock() ApplyClock {
	started := time.Now()
	return func() (domain.Timestamp, int64, error) {
		now := time.Now()
		monotonic := now.Sub(started).Nanoseconds()
		if monotonic < 0 {
			return "", 0, errors.New("consensus: monotonic clock regressed")
		}
		return domain.Timestamp(
			now.UTC().Format(time.RFC3339Nano),
		), monotonic, nil
	}
}

// FSMOptions binds one Raft state machine to its durable store and daemon boot.
type FSMOptions struct {
	Store        *store.Store
	OriginBootID domain.UUIDv7
	Clock        ApplyClock
	LogStore     raft.LogStore
}

// ApplyResponse is returned through raft.ApplyFuture.Response. Result is the
// already-durable command outcome whenever Err is nil.
type ApplyResponse struct {
	LogIndex uint64
	Result   store.ApplyResult
	Err      error
}

// FSM adapts committed Raft commands to the deterministic reducer and the
// atomic SQLite apply transaction.
type FSM struct {
	store            *store.Store
	originBootID     domain.UUIDv7
	clock            ApplyClock
	logStore         raft.LogStore
	admission        atomic.Pointer[peerAdmissionPublication]
	admissionChanged chan struct{}
	admissionMu      sync.Mutex
	admissionClosed  bool

	haltOnce sync.Once
	haltMu   sync.RWMutex
	haltErr  error
	halted   chan error
}

// NewFSM constructs a fail-closed state machine. Callers must continuously
// consume Halted and terminate the owning daemon when it yields an error.
func NewFSM(options FSMOptions) (*FSM, error) {
	if options.Store == nil ||
		!options.OriginBootID.Valid() ||
		options.Clock == nil {
		return nil, ErrInvalidFSMOptions
	}
	return &FSM{
		store:            options.Store,
		originBootID:     options.OriginBootID,
		clock:            options.Clock,
		logStore:         options.LogStore,
		admissionChanged: make(chan struct{}, 1),
		halted:           make(chan error, 1),
	}, nil
}

// Halted yields the first terminal FSM error. The channel remains open and
// emits at most one value.
func (fsm *FSM) Halted() <-chan error {
	if fsm == nil {
		return nil
	}
	return fsm.halted
}

// HaltError returns the latched terminal error, if any.
func (fsm *FSM) HaltError() error {
	if fsm == nil {
		return ErrInvalidFSMOptions
	}
	fsm.haltMu.RLock()
	defer fsm.haltMu.RUnlock()
	return fsm.haltErr
}

// Apply implements raft.FSM. Raft invokes it serially for committed command
// entries; any non-durable failure permanently halts this adapter.
func (fsm *FSM) Apply(log *raft.Log) interface{} {
	if fsm == nil {
		return ApplyResponse{Err: ErrInvalidFSMOptions}
	}
	if err := fsm.HaltError(); err != nil {
		return ApplyResponse{
			LogIndex: raftLogIndex(log),
			Err:      err,
		}
	}
	if log == nil ||
		log.Type != raft.LogCommand ||
		log.Term < 1 ||
		log.Index < 1 ||
		len(log.Data) == 0 ||
		len(log.Data) > event.MaxEventBytes {
		return fsm.halt(log, ErrInvalidCommand)
	}

	view, err := fsm.store.View(context.Background())
	if err != nil {
		return fsm.halt(log, fmt.Errorf("load committed state: %w", err))
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		return fsm.halt(log, fmt.Errorf(
			"decode committed state: %w",
			err,
		))
	}
	deviceID, err := commandOriginDeviceID(log.Data)
	if err != nil {
		return fsm.halt(log, err)
	}
	identityKey, exists := decoded.IdentityPublicKey(deviceID)
	if !exists {
		return fsm.halt(log, fmt.Errorf(
			"%w: origin device %q is absent from committed membership",
			ErrInvalidCommand,
			deviceID,
		))
	}
	signed, err := event.ParseAndVerify(log.Data, event.VerificationContext{
		SessionID:         view.SessionID,
		WorkspaceID:       view.WorkspaceID,
		IdentityPublicKey: identityKey,
	})
	if err != nil {
		return fsm.halt(log, fmt.Errorf(
			"%w: verify signed event: %v",
			ErrInvalidCommand,
			err,
		))
	}

	lookup, duplicate, err := fsm.store.LookupCommandResult(
		context.Background(),
		signed.Proposal().EventID,
	)
	if err != nil {
		return fsm.halt(log, fmt.Errorf(
			"lookup durable command result: %w",
			err,
		))
	}
	if duplicate && !bytes.Equal(lookup.CanonicalProposal, log.Data) {
		return fsm.halt(log, fmt.Errorf(
			"%w: committed event ID reuses different signed bytes",
			ErrInvalidCommand,
		))
	}
	if duplicate &&
		view.LastRaftAppliedLogIndex != nil &&
		log.Index <= *view.LastRaftAppliedLogIndex {
		if err := fsm.store.VerifyRaftCommand(
			context.Background(),
			log.Term,
			log.Index,
			signed,
		); err != nil {
			return fsm.halt(log, fmt.Errorf(
				"%w: covered Raft command binding differs: %v",
				ErrInvalidCommand,
				err,
			))
		}
		return ApplyResponse{
			LogIndex: log.Index,
			Result: store.ApplyResult{
				Heads:             view.Heads,
				Outcome:           lookup.Outcome,
				AdmissionRevision: view.AdmissionRevision,
				Duplicate:         true,
			},
		}
	}
	if duplicate && view.LastRaftAppliedLogIndex == nil {
		return fsm.halt(log, fmt.Errorf(
			"%w: durable result exists without an applied Raft watermark",
			ErrInvalidCommand,
		))
	}

	appliedAt, monotonicNow, err := fsm.clock()
	if err != nil {
		return fsm.halt(log, fmt.Errorf("read apply clock: %w", err))
	}
	if !appliedAt.Valid() || monotonicNow < 0 {
		return fsm.halt(log, fmt.Errorf(
			"read apply clock: invalid timestamp or monotonic value",
		))
	}
	applyContext := ApplyContext{
		Term:               log.Term,
		LogIndex:           log.Index,
		RecoveryGeneration: view.RecoveryGeneration,
		AppliedAt:          appliedAt,
		OriginBootID:       fsm.originBootID,
		MonotonicNowNS:     monotonicNow,
		PriorHeads:         view.Heads,
	}
	if duplicate {
		result, err := fsm.store.Apply(context.Background(), store.ApplyRequest{
			Term:               log.Term,
			LogIndex:           log.Index,
			AppliedAt:          appliedAt,
			RecoveryGeneration: view.RecoveryGeneration,
			Proposal:           signed,
		})
		if err != nil {
			if errors.Is(err, store.ErrIdempotencyConflict) {
				return fsm.halt(log, fmt.Errorf(
					"durable duplicate changed after verification: %w",
					err,
				))
			}
			return fsm.halt(log, fmt.Errorf(
				"advance duplicate Raft watermark: %w",
				err,
			))
		}
		return ApplyResponse{LogIndex: log.Index, Result: result}
	}
	outcome, err := reduceCommitted(
		decoded.Reducer,
		signed,
		log,
		view.Heads,
	)
	if err != nil {
		return fsm.halt(log, fmt.Errorf("reduce command: %w", err))
	}
	prospective := decoded.Reducer
	if err := prospective.Apply(outcome.Changes); err != nil {
		return fsm.halt(log, fmt.Errorf(
			"validate prospective reducer state: %w",
			err,
		))
	}
	nextAdmission, err := decoded.Admission.Advance(peerauth.Changes{
		AdvancesEventChain:       outcome.Changes.AdvancesEventChain,
		Devices:                  outcome.Changes.Devices,
		AuditCounters:            outcome.Changes.AuditCounters,
		CredentialAuthorizations: outcome.Changes.CredentialAuthorizations,
	})
	if err != nil {
		return fsm.halt(log, fmt.Errorf(
			"validate prospective peer admission: %w",
			err,
		))
	}
	request, err := BuildApplyRequest(signed, outcome, applyContext)
	if err != nil {
		return fsm.halt(log, err)
	}
	result, err := fsm.store.Apply(context.Background(), request)
	if err != nil {
		return fsm.halt(log, fmt.Errorf("commit command: %w", err))
	}
	fsm.publishPeerAdmission(
		nextAdmission,
		result.AdmissionRevision,
		admissionAccessChanged(outcome.Changes),
	)
	return ApplyResponse{LogIndex: log.Index, Result: result}
}

type peerAdmissionPublication struct {
	revision uint64
	snapshot *peerauth.Snapshot
}

func (fsm *FSM) publishPeerAdmission(
	snapshot *peerauth.Snapshot,
	revision uint64,
	notify bool,
) {
	fsm.admissionMu.Lock()
	defer fsm.admissionMu.Unlock()
	if fsm.admissionClosed {
		return
	}
	fsm.admission.Store(&peerAdmissionPublication{
		revision: revision,
		snapshot: snapshot,
	})
	if notify {
		select {
		case fsm.admissionChanged <- struct{}{}:
		default:
		}
	}
}

func (fsm *FSM) closePeerAdmissionChanges() {
	if fsm == nil {
		return
	}
	fsm.admissionMu.Lock()
	defer fsm.admissionMu.Unlock()
	if fsm.admissionClosed {
		return
	}
	fsm.admissionClosed = true
	close(fsm.admissionChanged)
}

func admissionAccessChanged(changes reducer.Changes) bool {
	return len(changes.Devices) != 0 ||
		len(changes.CredentialAuthorizations) != 0
}

func reduceCommitted(
	state reducer.State,
	signed event.SignedEvent,
	log *raft.Log,
	heads store.ApplyHeads,
) (reducer.Outcome, error) {
	if signed.Proposal().Kind != event.KindConsensusCheckpoint {
		return reducer.Reduce(state, signed)
	}
	return reducer.ReduceCheckpoint(
		state,
		signed,
		reducer.CheckpointApplyContext{
			Term:                    log.Term,
			LogIndex:                log.Index,
			ChainIndex:              heads.ChainIndex,
			ChainHash:               heads.ChainHash,
			ResultIndex:             heads.ResultIndex,
			ResultHash:              heads.ResultHash,
			ProjectionAccumulator:   heads.ProjectionAccumulator,
			DigestVersion:           heads.DigestVersion,
			ProjectionSchemaVersion: heads.ProjectionSchemaVersion,
		},
	)
}

type commandRoute struct {
	Origin struct {
		DeviceID string `json:"device_id"`
	} `json:"origin"`
}

func commandOriginDeviceID(input []byte) (domain.DeviceID, error) {
	if len(input) == 0 || len(input) > event.MaxEventBytes {
		return "", ErrInvalidCommand
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	var route commandRoute
	if err := decoder.Decode(&route); err != nil {
		return "", fmt.Errorf("%w: decode routing fields: %v", ErrInvalidCommand, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return "", err
	}
	deviceID := domain.DeviceID(route.Origin.DeviceID)
	if !deviceID.Valid() {
		return "", fmt.Errorf("%w: invalid origin device", ErrInvalidCommand)
	}
	return deviceID, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrInvalidCommand)
		}
		return fmt.Errorf("%w: trailing JSON: %v", ErrInvalidCommand, err)
	}
	return nil
}

func (fsm *FSM) halt(log *raft.Log, cause error) ApplyResponse {
	index := raftLogIndex(log)
	err := fmt.Errorf("%w at log index %d: %w", ErrFSMHalted, index, cause)
	fsm.haltOnce.Do(func() {
		fsm.haltMu.Lock()
		fsm.haltErr = err
		fsm.haltMu.Unlock()
		fsm.closePeerAdmissionChanges()
		fsm.halted <- err
	})
	return ApplyResponse{LogIndex: index, Err: fsm.HaltError()}
}

func raftLogIndex(log *raft.Log) uint64 {
	if log == nil {
		return 0
	}
	return log.Index
}
