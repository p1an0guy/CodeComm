package consensus

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/store"
)

// FreshDeviceLogicalSnapshotBoundaryVerifier roots a fresh installation in an
// immutable generation-zero cut and bounds recovery replay at the active
// genesis pinned by the invite.
type FreshDeviceLogicalSnapshotBoundaryVerifier struct {
	mu sync.Mutex

	delegate                         *GenerationZeroBoundaryVerifier
	bootstrapGenesisJSON             []byte
	bootstrapGenesisDigest           chain.Digest
	bootstrapProjectionStateDigest   chain.Digest
	expectedActiveRecoveryGeneration uint64
	expectedActiveGenesisDigest      chain.Digest
	initialVerified                  bool
	lastVerifiedGeneration           uint64
}

var _ LogicalSnapshotBoundaryVerifier = (*FreshDeviceLogicalSnapshotBoundaryVerifier)(nil)

// NewFreshDeviceLogicalSnapshotBoundaryVerifier validates and freezes the
// bootstrap cut before any untrusted logical-snapshot payload is processed.
func NewFreshDeviceLogicalSnapshotBoundaryVerifier(
	bootstrap store.StateView,
	expectedActiveRecoveryGeneration uint64,
	expectedActiveGenesisDigest chain.Digest,
) (*FreshDeviceLogicalSnapshotBoundaryVerifier, error) {
	if !domain.ValidUnsignedInteger(expectedActiveRecoveryGeneration) {
		return nil, fmt.Errorf(
			"%w: invalid expected active recovery generation",
			ErrLogicalSnapshotBoundaryUnavailable,
		)
	}

	frozen := cloneFreshDeviceBootstrapView(bootstrap)
	genesisDigest, err := validateFreshDeviceBootstrapView(frozen)
	if err != nil {
		return nil, err
	}
	source := &freshDeviceBootstrapSource{view: frozen}
	delegate, err := NewGenerationZeroBoundaryVerifier(source)
	if err != nil {
		return nil, err
	}
	return &FreshDeviceLogicalSnapshotBoundaryVerifier{
		delegate:                         delegate,
		bootstrapGenesisJSON:             bytes.Clone(frozen.GenesisJSON),
		bootstrapGenesisDigest:           genesisDigest,
		bootstrapProjectionStateDigest:   chain.Digest(frozen.ProjectionStateDigest),
		expectedActiveRecoveryGeneration: expectedActiveRecoveryGeneration,
		expectedActiveGenesisDigest:      expectedActiveGenesisDigest,
	}, nil
}

// VerifyInitialBoundary verifies that the artifact's initial boundary exactly
// matches the frozen bootstrap cut.
func (verifier *FreshDeviceLogicalSnapshotBoundaryVerifier) VerifyInitialBoundary(
	ctx context.Context,
	payload logicalsnapshot.GenesisPayload,
) (store.InitialState, error) {
	if verifier == nil || verifier.delegate == nil || ctx == nil {
		return store.InitialState{}, ErrLogicalSnapshotBoundaryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return store.InitialState{}, err
	}

	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if verifier.initialVerified {
		return store.InitialState{}, fmt.Errorf(
			"%w: initial boundary was already verified",
			ErrLogicalSnapshotBoundaryUnavailable,
		)
	}
	metadata, err := logicalsnapshot.InspectGenesisPayload(payload)
	if err != nil {
		return store.InitialState{}, fmt.Errorf(
			"%w: inspect fresh-device initial genesis: %w",
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
	if metadata.GenesisDigest != verifier.bootstrapGenesisDigest ||
		!bytes.Equal(
			payload.GenesisJSON,
			verifier.bootstrapGenesisJSON,
		) ||
		metadata.BoundaryTransformDigest !=
			verifier.bootstrapProjectionStateDigest {
		return store.InitialState{}, fmt.Errorf(
			"%w: artifact and bootstrap initial boundaries differ",
			ErrLogicalSnapshotBoundaryUnavailable,
		)
	}
	if verifier.expectedActiveRecoveryGeneration == 0 &&
		metadata.GenesisDigest != verifier.expectedActiveGenesisDigest {
		return store.InitialState{}, fmt.Errorf(
			"%w: initial genesis differs from invite pin",
			ErrLogicalSnapshotBoundaryUnavailable,
		)
	}

	initial, err := verifier.delegate.VerifyInitialBoundary(ctx, payload)
	if err != nil {
		return store.InitialState{}, err
	}
	verifier.initialVerified = true
	verifier.lastVerifiedGeneration = 0
	return initial, nil
}

// VerifySuccessorBoundary verifies one contiguous recovery boundary. The
// invite pin is enforced at its declared active generation, after which all
// further successors are refused.
func (verifier *FreshDeviceLogicalSnapshotBoundaryVerifier) VerifySuccessorBoundary(
	ctx context.Context,
	predecessor store.StateView,
	payload logicalsnapshot.GenesisPayload,
) (store.SuccessorState, error) {
	if verifier == nil || verifier.delegate == nil || ctx == nil {
		return store.SuccessorState{}, ErrLogicalSnapshotBoundaryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return store.SuccessorState{}, err
	}

	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	if !verifier.initialVerified {
		return store.SuccessorState{}, fmt.Errorf(
			"%w: initial boundary has not been verified",
			ErrLogicalSnapshotBoundaryUnavailable,
		)
	}
	if verifier.lastVerifiedGeneration >=
		verifier.expectedActiveRecoveryGeneration {
		return store.SuccessorState{}, fmt.Errorf(
			"%w: invite-pinned active generation was already reached",
			ErrLogicalSnapshotSuccessorBoundaryUnsupported,
		)
	}

	metadata, err := logicalsnapshot.InspectGenesisPayload(payload)
	if err != nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"inspect fresh-device successor genesis",
			err,
		)
	}
	if metadata.RecoveryGeneration >
		verifier.expectedActiveRecoveryGeneration {
		return store.SuccessorState{}, fmt.Errorf(
			"%w: successor exceeds invite-pinned active generation",
			ErrLogicalSnapshotSuccessorBoundaryUnsupported,
		)
	}
	if metadata.RecoveryGeneration !=
		verifier.lastVerifiedGeneration+1 {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"successor is not the next verified recovery generation",
			nil,
		)
	}
	if metadata.RecoveryGeneration ==
		verifier.expectedActiveRecoveryGeneration &&
		metadata.GenesisDigest != verifier.expectedActiveGenesisDigest {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"active genesis differs from invite pin",
			nil,
		)
	}

	successor, err := verifier.delegate.VerifySuccessorBoundary(
		ctx,
		predecessor,
		payload,
	)
	if err != nil {
		return store.SuccessorState{}, err
	}
	verifier.lastVerifiedGeneration = metadata.RecoveryGeneration
	return successor, nil
}

type freshDeviceBootstrapSource struct {
	view store.StateView
}

func (source *freshDeviceBootstrapSource) VerifiedGenerationZeroView(
	ctx context.Context,
) (store.StateView, error) {
	if source == nil || ctx == nil {
		return store.StateView{}, ErrLogicalSnapshotBoundaryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return store.StateView{}, err
	}
	return cloneFreshDeviceBootstrapView(source.view), nil
}

func validateFreshDeviceBootstrapView(
	view store.StateView,
) (chain.Digest, error) {
	if view.RecoveryGeneration != 0 ||
		view.CurrentTerm != nil ||
		view.LastRaftAppliedLogIndex != nil ||
		view.Heads.ChainIndex != 0 ||
		view.Heads.ResultIndex != 0 ||
		view.Heads.PreviousResultHash != (store.Digest{}) {
		return chain.Digest{}, fmt.Errorf(
			"%w: bootstrap is not a provenance-free generation-zero cut",
			ErrLogicalSnapshotBoundaryUnavailable,
		)
	}
	if _, _, err := decodeReducerStateView(view); err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: validate bootstrap state: %w",
			ErrLogicalSnapshotBoundaryUnavailable,
			err,
		)
	}
	genesisDigest, err := chain.GenesisDigest(view.GenesisJSON)
	if err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: digest bootstrap genesis: %w",
			ErrLogicalSnapshotBoundaryUnavailable,
			err,
		)
	}
	boundary := chain.Boundary{Genesis: genesisDigest}
	eventSeed, err := chain.EventSeed(boundary)
	if err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: derive bootstrap event seed: %w",
			ErrLogicalSnapshotBoundaryUnavailable,
			err,
		)
	}
	resultSeed, err := chain.ResultSeed(boundary)
	if err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: derive bootstrap result seed: %w",
			ErrLogicalSnapshotBoundaryUnavailable,
			err,
		)
	}
	accumulator := chain.AccumulatorSeedInitial(
		genesisDigest,
		chain.Digest(view.ProjectionStateDigest),
	)
	if chain.Digest(view.Heads.ChainHash) != eventSeed ||
		chain.Digest(view.Heads.ResultHash) != resultSeed ||
		chain.Digest(view.Heads.ProjectionAccumulator) != accumulator {
		return chain.Digest{}, fmt.Errorf(
			"%w: bootstrap generation-zero commitment heads differ",
			ErrLogicalSnapshotBoundaryUnavailable,
		)
	}
	return genesisDigest, nil
}

func cloneFreshDeviceBootstrapView(view store.StateView) store.StateView {
	cloned := view
	cloned.GenesisJSON = bytes.Clone(view.GenesisJSON)
	if view.CurrentTerm != nil {
		value := *view.CurrentTerm
		cloned.CurrentTerm = &value
	}
	if view.LastRaftAppliedLogIndex != nil {
		value := *view.LastRaftAppliedLogIndex
		cloned.LastRaftAppliedLogIndex = &value
	}
	cloned.ProjectionRows = make(
		[]chain.LogicalRow,
		len(view.ProjectionRows),
	)
	for index, row := range view.ProjectionRows {
		cloned.ProjectionRows[index] = chain.LogicalRow{
			Table:      row.Table,
			PrimaryKey: bytes.Clone(row.PrimaryKey),
			Row:        bytes.Clone(row.Row),
		}
	}
	return cloned
}
