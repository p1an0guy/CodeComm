package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	ErrLogicalSnapshotBoundaryUnavailable = errors.New(
		"consensus: logical snapshot boundary unavailable",
	)
	ErrLogicalSnapshotSuccessorBoundaryUnsupported = errors.New(
		"consensus: successor logical snapshot boundary is unsupported",
	)
	ErrLogicalSnapshotSuccessorBoundaryInvalid = errors.New(
		"consensus: invalid successor logical snapshot boundary",
	)
)

// GenerationZeroStateSource supplies a fully scrubbed reconstruction of the
// exact initial projection cut retained by an existing replica.
type GenerationZeroStateSource interface {
	VerifiedGenerationZeroView(context.Context) (store.StateView, error)
}

// GenerationZeroBoundaryVerifier verifies generation zero against a fully
// scrubbed local lineage and reconstructs signed successor generations from
// their verified predecessor cuts. The name is retained for API compatibility
// with the generation-zero-only implementation it replaced.
type GenerationZeroBoundaryVerifier struct {
	source GenerationZeroStateSource

	mu              sync.Mutex
	lineageStarted  bool
	workspaceID     domain.UUIDv4
	lastGeneration  uint64
	lastGenesis     chain.Digest
	recoveryKeySeen map[[ed25519.PublicKeySize]byte]struct{}
}

func NewGenerationZeroBoundaryVerifier(
	source GenerationZeroStateSource,
) (*GenerationZeroBoundaryVerifier, error) {
	if isNilSnapshotInterface(source) {
		return nil, ErrLogicalSnapshotBoundaryUnavailable
	}
	return &GenerationZeroBoundaryVerifier{source: source}, nil
}

func (verifier *GenerationZeroBoundaryVerifier) VerifyInitialBoundary(
	ctx context.Context,
	payload logicalsnapshot.GenesisPayload,
) (store.InitialState, error) {
	if verifier == nil ||
		isNilSnapshotInterface(verifier.source) ||
		ctx == nil {
		return store.InitialState{}, ErrLogicalSnapshotBoundaryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return store.InitialState{}, err
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if verifier.lineageStarted {
		return store.InitialState{}, fmt.Errorf(
			"%w: boundary verifier was already consumed",
			ErrLogicalSnapshotBoundaryUnavailable,
		)
	}
	metadata, err := logicalsnapshot.InspectGenesisPayload(payload)
	if err != nil {
		return store.InitialState{}, fmt.Errorf(
			"%w: inspect initial genesis: %v",
			ErrLogicalSnapshotBoundaryUnavailable,
			err,
		)
	}
	if metadata.RecoveryGeneration != 0 ||
		metadata.HasPredecessor ||
		len(payload.RecoveryAuthorizationJSON) != 0 {
		return store.InitialState{},
			ErrLogicalSnapshotSuccessorBoundaryUnsupported
	}
	view, err := verifier.source.VerifiedGenerationZeroView(ctx)
	if err != nil {
		return store.InitialState{}, fmt.Errorf(
			"%w: reconstruct local initial state: %w",
			ErrLogicalSnapshotBoundaryUnavailable,
			err,
		)
	}
	if view.SessionID != metadata.SessionID ||
		view.WorkspaceID != metadata.WorkspaceID ||
		view.RecoveryGeneration != 0 ||
		!bytes.Equal(view.GenesisJSON, payload.GenesisJSON) ||
		view.Heads.ChainIndex != 0 ||
		view.Heads.ResultIndex != 0 ||
		view.CurrentTerm != nil ||
		view.LastRaftAppliedLogIndex != nil ||
		chain.Digest(view.ProjectionStateDigest) !=
			metadata.BoundaryTransformDigest {
		return store.InitialState{}, fmt.Errorf(
			"%w: artifact and local initial boundaries differ",
			ErrLogicalSnapshotBoundaryUnavailable,
		)
	}
	snapshot, _, err := decodeReducerStateView(view)
	if err != nil {
		return store.InitialState{}, fmt.Errorf(
			"%w: decode local initial projections: %w",
			ErrLogicalSnapshotBoundaryUnavailable,
			err,
		)
	}
	var recoveryKey [ed25519.PublicKeySize]byte
	copy(recoveryKey[:], snapshot.RecoveryPublicKey)
	verifier.lineageStarted = true
	verifier.workspaceID = metadata.WorkspaceID
	verifier.lastGeneration = 0
	verifier.lastGenesis = metadata.GenesisDigest
	verifier.recoveryKeySeen =
		map[[ed25519.PublicKeySize]byte]struct{}{recoveryKey: {}}
	return store.InitialState{
		SessionID:               view.SessionID,
		WorkspaceID:             view.WorkspaceID,
		GenesisJSON:             bytes.Clone(view.GenesisJSON),
		Projections:             projectionWrites(snapshotProjectionChanges(snapshot)),
		DigestVersion:           view.Heads.DigestVersion,
		ProjectionSchemaVersion: view.Heads.ProjectionSchemaVersion,
	}, nil
}

func (verifier *GenerationZeroBoundaryVerifier) VerifySuccessorBoundary(
	ctx context.Context,
	predecessor store.StateView,
	payload logicalsnapshot.GenesisPayload,
) (store.SuccessorState, error) {
	if verifier == nil ||
		isNilSnapshotInterface(verifier.source) ||
		ctx == nil {
		return store.SuccessorState{}, ErrLogicalSnapshotBoundaryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return store.SuccessorState{}, err
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	predecessorDigest, err := chain.GenesisDigest(predecessor.GenesisJSON)
	if err != nil {
		return store.SuccessorState{}, fmt.Errorf(
			"%w: digest predecessor genesis: %v",
			ErrLogicalSnapshotBoundaryUnavailable,
			err,
		)
	}
	if !verifier.lineageStarted {
		if predecessor.RecoveryGeneration != 0 {
			return store.SuccessorState{}, fmt.Errorf(
				"%w: predecessor recovery-key history is unavailable",
				ErrLogicalSnapshotBoundaryUnavailable,
			)
		}
		snapshot, _, decodeErr := decodeReducerStateView(predecessor)
		if decodeErr != nil {
			return store.SuccessorState{}, fmt.Errorf(
				"%w: decode predecessor boundary: %v",
				ErrLogicalSnapshotBoundaryUnavailable,
				decodeErr,
			)
		}
		var recoveryKey [ed25519.PublicKeySize]byte
		copy(recoveryKey[:], snapshot.RecoveryPublicKey)
		verifier.lineageStarted = true
		verifier.workspaceID = predecessor.WorkspaceID
		verifier.lastGeneration = 0
		verifier.lastGenesis = predecessorDigest
		verifier.recoveryKeySeen =
			map[[ed25519.PublicKeySize]byte]struct{}{recoveryKey: {}}
	}
	if verifier.workspaceID != predecessor.WorkspaceID ||
		verifier.lastGeneration != predecessor.RecoveryGeneration ||
		verifier.lastGenesis != predecessorDigest {
		return store.SuccessorState{}, fmt.Errorf(
			"%w: predecessor does not continue the verified boundary sequence",
			ErrLogicalSnapshotBoundaryUnavailable,
		)
	}
	successor, err := verifyLogicalSnapshotSuccessorBoundary(
		ctx,
		predecessor,
		payload,
		verifier.recoveryKeySeen,
	)
	if err != nil {
		return store.SuccessorState{}, err
	}
	metadata, err := logicalsnapshot.InspectGenesisPayload(payload)
	if err != nil {
		return store.SuccessorState{}, err
	}
	binding, err := parseSuccessorRecoveryBinding(payload)
	if err != nil {
		return store.SuccessorState{}, err
	}
	var recoveryKey [ed25519.PublicKeySize]byte
	copy(recoveryKey[:], binding.recoveryPublicKey)
	verifier.recoveryKeySeen[recoveryKey] = struct{}{}
	verifier.lastGeneration = metadata.RecoveryGeneration
	verifier.lastGenesis = metadata.GenesisDigest
	return successor, nil
}

func snapshotProjectionChanges(snapshot reducer.Snapshot) reducer.Changes {
	changes := reducer.Changes{
		PlanCurrent:         []plan.Current{snapshot.PlanCurrent},
		VoterSet:            []voterset.Set{snapshot.VoterSet},
		CredentialAuthority: []credentialauthority.Authority{snapshot.CredentialAuthority},
		CanonicalRefs:       []publication.CanonicalRef{snapshot.CanonicalRef},
		SessionPolicy:       []policy.Policy{snapshot.SessionPolicy},
	}
	for _, value := range snapshot.OriginScopes {
		changes.OriginScopes = append(changes.OriginScopes, value)
	}
	for _, value := range snapshot.AuditCounters {
		changes.AuditCounters = append(changes.AuditCounters, value)
	}
	for _, value := range snapshot.Tasks {
		changes.Tasks = append(changes.Tasks, value)
	}
	for _, value := range snapshot.PlanRevisions {
		changes.PlanRevisions = append(changes.PlanRevisions, value)
	}
	for _, value := range snapshot.MemoryRecords {
		changes.MemoryRecords = append(changes.MemoryRecords, value)
	}
	for _, value := range snapshot.Leases {
		changes.Leases = append(changes.Leases, value)
	}
	for _, value := range snapshot.Devices {
		changes.Devices = append(changes.Devices, value)
	}
	for _, value := range snapshot.CredentialAuthorizations {
		changes.CredentialAuthorizations = append(
			changes.CredentialAuthorizations,
			value,
		)
	}
	for _, value := range snapshot.AgentSessions {
		changes.AgentSessions = append(changes.AgentSessions, value)
	}
	for _, value := range snapshot.Publications {
		changes.Publications = append(changes.Publications, value)
	}
	for _, value := range snapshot.ControlFileProposals {
		changes.ControlFileProposals = append(
			changes.ControlFileProposals,
			value,
		)
	}
	for _, value := range snapshot.MergeConflicts {
		changes.MergeConflicts = append(changes.MergeConflicts, value)
	}
	sortSnapshotProjectionChanges(&changes)
	return changes
}

func sortSnapshotProjectionChanges(changes *reducer.Changes) {
	sort.Slice(changes.OriginScopes, func(left, right int) bool {
		first := changes.OriginScopes[left]
		second := changes.OriginScopes[right]
		if first.DeviceID != second.DeviceID {
			return first.DeviceID < second.DeviceID
		}
		if first.Kind != second.Kind {
			return first.Kind < second.Kind
		}
		return first.ScopeID < second.ScopeID
	})
	sort.Slice(changes.AuditCounters, func(left, right int) bool {
		return changes.AuditCounters[left].DeviceID <
			changes.AuditCounters[right].DeviceID
	})
	sort.Slice(changes.Tasks, func(left, right int) bool {
		return changes.Tasks[left].ID < changes.Tasks[right].ID
	})
	sort.Slice(changes.PlanRevisions, func(left, right int) bool {
		return changes.PlanRevisions[left].ID() <
			changes.PlanRevisions[right].ID()
	})
	sort.Slice(changes.MemoryRecords, func(left, right int) bool {
		return changes.MemoryRecords[left].ID() <
			changes.MemoryRecords[right].ID()
	})
	sort.Slice(changes.Leases, func(left, right int) bool {
		return changes.Leases[left].ID < changes.Leases[right].ID
	})
	sort.Slice(changes.Devices, func(left, right int) bool {
		return changes.Devices[left].ID < changes.Devices[right].ID
	})
	sort.Slice(
		changes.CredentialAuthorizations,
		func(left, right int) bool {
			first := changes.CredentialAuthorizations[left]
			second := changes.CredentialAuthorizations[right]
			if first.DeviceID != second.DeviceID {
				return first.DeviceID < second.DeviceID
			}
			return first.Epoch < second.Epoch
		},
	)
	sort.Slice(changes.AgentSessions, func(left, right int) bool {
		return changes.AgentSessions[left].ID <
			changes.AgentSessions[right].ID
	})
	sort.Slice(changes.Publications, func(left, right int) bool {
		return changes.Publications[left].Metadata.PublicationID <
			changes.Publications[right].Metadata.PublicationID
	})
	sort.Slice(changes.ControlFileProposals, func(left, right int) bool {
		return changes.ControlFileProposals[left].ProposalEventID <
			changes.ControlFileProposals[right].ProposalEventID
	})
	sort.Slice(changes.MergeConflicts, func(left, right int) bool {
		return changes.MergeConflicts[left].ID <
			changes.MergeConflicts[right].ID
	})
}

var _ LogicalSnapshotBoundaryVerifier = (*GenerationZeroBoundaryVerifier)(nil)
