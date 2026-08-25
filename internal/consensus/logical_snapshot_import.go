package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	ErrInvalidLogicalSnapshotImport = errors.New(
		"consensus: invalid logical snapshot import",
	)
	ErrLogicalSnapshotSemanticMismatch = errors.New(
		"consensus: logical snapshot semantic mismatch",
	)
)

// LogicalSnapshotImportScratch is caller-owned file-backed artifact storage.
type LogicalSnapshotImportScratch = logicalsnapshot.ExpandedArtifact

// LogicalSnapshotReadWriteScratch is caller-owned file-backed scratch used
// for structural sequence validation or successor-boundary spooling.
type LogicalSnapshotReadWriteScratch = logicalsnapshot.VerificationScratch

// LogicalSnapshotRootPreflight authenticates and applies caller-specific
// operational policy to a root before any artifact source is opened.
type LogicalSnapshotRootPreflight func(
	context.Context,
	logicalsnapshot.Root,
) error

// LogicalSnapshotBoundaryVerifier owns identity/bootstrap and recovery policy.
// The importer independently checks that returned store inputs bind the exact
// artifact record, predecessor cut, commitment versions, and transform digest.
type LogicalSnapshotBoundaryVerifier interface {
	VerifyInitialBoundary(
		context.Context,
		logicalsnapshot.GenesisPayload,
	) (store.InitialState, error)
	VerifySuccessorBoundary(
		context.Context,
		store.StateView,
		logicalsnapshot.GenesisPayload,
	) (store.SuccessorState, error)
}

// LogicalSnapshotImportOptions binds complete descriptor/chunk sources to
// distinct expanded, sequence, boundary, and SQLite quarantine storage.
type LogicalSnapshotImportOptions struct {
	ExpandedArtifact LogicalSnapshotImportScratch
	SequenceScratch  LogicalSnapshotReadWriteScratch
	BoundaryScratch  LogicalSnapshotReadWriteScratch
	OpenPage         logicalsnapshot.DescriptorPageSource
	OpenChunk        logicalsnapshot.ArtifactChunkSource
	PreflightRoot    LogicalSnapshotRootPreflight
	StagePath        string
	OriginBootID     domain.UUIDv7
	Clock            ApplyClock
	Boundaries       LogicalSnapshotBoundaryVerifier
}

// VerifiedLogicalSnapshotStage owns a complete, frozen quarantine database.
// It becomes authoritative only through a later standalone or metadata-bound
// Raft installation transaction.
type VerifiedLogicalSnapshotStage struct {
	stage        *store.LogicalSnapshotStage
	root         logicalsnapshot.Root
	cut          store.LogicalSnapshotCut
	originBootID domain.UUIDv7
	clock        ApplyClock

	closeOnce sync.Once
	closeErr  error
}

// Path returns the quarantine database path.
func (verified *VerifiedLogicalSnapshotStage) Path() string {
	if verified == nil || verified.stage == nil {
		return ""
	}
	return verified.stage.Path()
}

// Root returns the verified signed snapshot root.
func (verified *VerifiedLogicalSnapshotStage) Root() logicalsnapshot.Root {
	if verified == nil {
		return logicalsnapshot.Root{}
	}
	return verified.root
}

// Cut returns the exact root-derived logical cut.
func (verified *VerifiedLogicalSnapshotStage) Cut() store.LogicalSnapshotCut {
	if verified == nil {
		return store.LogicalSnapshotCut{}
	}
	return verified.cut
}

// View returns the frozen staged state for diagnostics and installation
// preflight. It does not make the stage authoritative.
func (verified *VerifiedLogicalSnapshotStage) View(
	ctx context.Context,
) (store.StateView, error) {
	if verified == nil || verified.stage == nil {
		return store.StateView{}, ErrInvalidLogicalSnapshotImport
	}
	return verified.stage.View(ctx)
}

// Close releases the quarantine database. The caller retains ownership of the
// file for installation, evidence preservation, or secure cleanup.
func (verified *VerifiedLogicalSnapshotStage) Close() error {
	if verified == nil || verified.stage == nil {
		return ErrInvalidLogicalSnapshotImport
	}
	verified.closeOnce.Do(func() {
		verified.closeErr = verified.stage.Close()
	})
	return verified.closeErr
}

// VerifyAndStageLogicalSnapshot performs two complete passes over an expanded
// artifact spool. Pass one validates framing, order, commitments, and the
// exact root digest before invoking trusted recovery logic. Pass two verifies
// signatures and deterministic reducer semantics while rebuilding a new
// SQLite quarantine one bounded command transaction at a time.
func VerifyAndStageLogicalSnapshot(
	ctx context.Context,
	root logicalsnapshot.Root,
	options LogicalSnapshotImportOptions,
) (_ *VerifiedLogicalSnapshotStage, err error) {
	if err := validateLogicalSnapshotImportOptions(ctx, root, options); err != nil {
		return nil, err
	}
	if err := options.PreflightRoot(ctx, root); err != nil {
		return nil, snapshotSemanticError(
			"preflight signed root",
			err,
		)
	}
	artifactProof, err := logicalsnapshot.VerifyAndExpandArtifact(
		ctx,
		root,
		logicalsnapshot.ArtifactVerificationOptions{
			ExpandedArtifact: options.ExpandedArtifact,
			SequenceScratch:  options.SequenceScratch,
			OpenPage:         options.OpenPage,
			OpenChunk:        options.OpenChunk,
		},
	)
	if err != nil {
		return nil, err
	}
	if err := resetSnapshotScratch(options.BoundaryScratch); err != nil {
		return nil, fmt.Errorf(
			"%w: reset boundary scratch: %v",
			ErrInvalidLogicalSnapshotImport,
			err,
		)
	}

	stage, err := store.OpenLogicalSnapshotStage(ctx, options.StagePath)
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			closeErr := stage.Close()
			removeErr := removeLogicalSnapshotStageFiles(stage.Path())
			if closeErr != nil {
				err = errors.Join(err, closeErr)
			}
			if removeErr != nil {
				err = errors.Join(err, removeErr)
			}
		}
	}()

	replay := logicalSnapshotSemanticReplay{
		ctx:              ctx,
		root:             root,
		rootInput:        root.Unsigned().Input(),
		stage:            stage,
		boundaries:       options.Boundaries,
		boundaryScratch:  options.BoundaryScratch,
		originBootID:     options.OriginBootID,
		clock:            options.Clock,
		section:          snapshotSectionGenesis,
		expectedBoundary: 0,
	}
	if err := replay.consumeExpandedArtifact(options.ExpandedArtifact); err != nil {
		return nil, err
	}
	if err := replay.finish(); err != nil {
		return nil, snapshotSemanticError(
			"finish semantic replay",
			err,
		)
	}

	cut := logicalSnapshotCutFromRoot(replay.rootInput)
	if err := stage.VerifyArtifact(ctx, root, artifactProof); err != nil {
		return nil, snapshotSemanticError(
			"freeze staged SQLite state",
			err,
		)
	}
	succeeded = true
	return &VerifiedLogicalSnapshotStage{
		stage:        stage,
		root:         root,
		cut:          cut,
		originBootID: options.OriginBootID,
		clock:        options.Clock,
	}, nil
}

func removeLogicalSnapshotStageFiles(path string) error {
	if path == "" {
		return ErrInvalidLogicalSnapshotImport
	}
	var result error
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(candidate); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	return result
}

func validateLogicalSnapshotImportOptions(
	ctx context.Context,
	root logicalsnapshot.Root,
	options LogicalSnapshotImportOptions,
) error {
	if ctx == nil ||
		len(root.CanonicalBytes()) == 0 ||
		isNilSnapshotInterface(options.ExpandedArtifact) ||
		isNilSnapshotInterface(options.SequenceScratch) ||
		isNilSnapshotInterface(options.BoundaryScratch) ||
		options.OpenPage == nil ||
		options.OpenChunk == nil ||
		options.PreflightRoot == nil ||
		options.StagePath == "" ||
		!options.OriginBootID.Valid() ||
		options.Clock == nil ||
		isNilSnapshotInterface(options.Boundaries) {
		return ErrInvalidLogicalSnapshotImport
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if sameSnapshotScratch(
		options.ExpandedArtifact,
		options.SequenceScratch,
	) ||
		sameSnapshotScratch(
			options.ExpandedArtifact,
			options.BoundaryScratch,
		) ||
		sameSnapshotScratch(
			options.SequenceScratch,
			options.BoundaryScratch,
		) {
		return fmt.Errorf(
			"%w: scratch storage aliases",
			ErrInvalidLogicalSnapshotImport,
		)
	}
	return nil
}

type logicalSnapshotSection uint8

const (
	snapshotSectionGenesis logicalSnapshotSection = iota
	snapshotSectionResult
	snapshotSectionEvent
	snapshotSectionProjection
	snapshotSectionCheckpoint
	snapshotSectionDone
)

type pendingSnapshotResult struct {
	payload       logicalsnapshot.ResultPayload
	mutationBytes []byte
	nextChunk     uint64
}

type snapshotGenesisMetadata struct {
	sessionID               domain.UUIDv7
	workspaceID             domain.UUIDv4
	generation              uint64
	predecessorChainIndex   uint64
	predecessorChainHash    chain.Digest
	predecessorResultIndex  uint64
	predecessorResultHash   chain.Digest
	predecessorAccumulator  chain.Digest
	boundaryTransformDigest chain.Digest
	digestVersion           uint64
	projectionVersion       uint64
	hasPredecessor          bool
}

type logicalSnapshotSemanticReplay struct {
	ctx       context.Context
	root      logicalsnapshot.Root
	rootInput logicalsnapshot.RootInput
	stage     *store.LogicalSnapshotStage

	boundaries      LogicalSnapshotBoundaryVerifier
	boundaryScratch LogicalSnapshotReadWriteScratch
	originBootID    domain.UUIDv7
	clock           ApplyClock

	section          logicalSnapshotSection
	expectedBoundary uint64
	pendingBoundary  *logicalsnapshot.GenesisPayload
	pendingMetadata  snapshotGenesisMetadata
	pendingResult    pendingSnapshotResult

	heads      store.ApplyHeads
	activeView store.StateView

	checkpointSeen bool
	recordCount    uint64
}

func (replay *logicalSnapshotSemanticReplay) consumeExpandedArtifact(
	artifact LogicalSnapshotImportScratch,
) error {
	if _, err := artifact.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf(
			"%w: rewind expanded artifact: %v",
			ErrInvalidLogicalSnapshotImport,
			err,
		)
	}
	limited := &io.LimitedReader{
		R: artifact,
		N: int64(replay.rootInput.ExpandedBytes),
	}
	hasher := sha256.New()
	reader := logicalsnapshot.NewRecordReader(io.TeeReader(limited, hasher))
	for {
		if err := replay.ctx.Err(); err != nil {
			return err
		}
		record, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return snapshotSemanticError(
				fmt.Sprintf("decode semantic record %d", replay.recordCount),
				err,
			)
		}
		if replay.recordCount >= replay.rootInput.RecordCount {
			return snapshotSemanticError(
				"semantic record count exceeds root",
				nil,
			)
		}
		if err := replay.consume(record); err != nil {
			return snapshotSemanticError(
				fmt.Sprintf("replay semantic record %d", replay.recordCount),
				err,
			)
		}
		replay.recordCount++
	}
	return verifyExpandedSnapshotEnd(
		artifact,
		limited,
		hasher.Sum(nil),
		replay.recordCount,
		replay.rootInput,
	)
}

func (replay *logicalSnapshotSemanticReplay) consume(
	record logicalsnapshot.Record,
) error {
	switch record.Type {
	case logicalsnapshot.RecordGenesis:
		return replay.consumeGenesis(record.Payload)
	case logicalsnapshot.RecordResult:
		return replay.consumeResult(record.Payload)
	case logicalsnapshot.RecordMutation:
		return replay.consumeMutation(record.Payload)
	case logicalsnapshot.RecordEvent:
		return replay.consumeEvent(record.Payload)
	case logicalsnapshot.RecordProjection:
		return replay.consumeProjection(record.Payload)
	case logicalsnapshot.RecordCheckpoint:
		return replay.consumeCheckpoint(record.Payload)
	default:
		return ErrLogicalSnapshotSemanticMismatch
	}
}

func (replay *logicalSnapshotSemanticReplay) consumeGenesis(
	encoded []byte,
) error {
	if replay.section != snapshotSectionGenesis {
		return errors.New("genesis appears after the genesis section")
	}
	payload, err := logicalsnapshot.DecodeGenesisPayload(encoded)
	if err != nil {
		return fmt.Errorf("decode genesis: %w", err)
	}
	metadata, err := inspectSnapshotGenesis(payload)
	if err != nil {
		return err
	}
	if metadata.generation != replay.expectedBoundary ||
		metadata.workspaceID != replay.rootInput.WorkspaceID {
		return errors.New("genesis lineage differs from root")
	}
	if replay.expectedBoundary == 0 {
		if err := replay.installInitial(payload, metadata); err != nil {
			return err
		}
	} else if err := writeSnapshotBoundary(
		replay.boundaryScratch,
		encoded,
	); err != nil {
		return err
	}
	replay.expectedBoundary++
	return nil
}

func (replay *logicalSnapshotSemanticReplay) installInitial(
	payload logicalsnapshot.GenesisPayload,
	metadata snapshotGenesisMetadata,
) error {
	initial, err := replay.boundaries.VerifyInitialBoundary(
		replay.ctx,
		payload,
	)
	if err != nil {
		return fmt.Errorf("verify generation-zero boundary: %w", err)
	}
	if metadata.generation != 0 ||
		metadata.hasPredecessor ||
		initial.SessionID != metadata.sessionID ||
		initial.WorkspaceID != metadata.workspaceID ||
		!bytes.Equal(initial.GenesisJSON, payload.GenesisJSON) ||
		initial.DigestVersion != replay.rootInput.DigestVersion ||
		initial.ProjectionSchemaVersion !=
			replay.rootInput.ProjectionSchemaVersion {
		return errors.New(
			"verified generation-zero state differs from artifact",
		)
	}
	heads, err := replay.stage.Initialize(replay.ctx, initial)
	if err != nil {
		return fmt.Errorf("initialize staged generation zero: %w", err)
	}
	view, err := replay.stage.View(replay.ctx)
	if err != nil {
		return fmt.Errorf("read staged generation zero: %w", err)
	}
	if view.SessionID != metadata.sessionID ||
		view.WorkspaceID != metadata.workspaceID ||
		view.RecoveryGeneration != 0 ||
		view.Heads != heads ||
		chain.Digest(view.ProjectionStateDigest) !=
			metadata.boundaryTransformDigest {
		return errors.New(
			"staged generation-zero transform differs from artifact",
		)
	}
	return replay.loadActiveView(view)
}

func (replay *logicalSnapshotSemanticReplay) finishGenesis() error {
	if replay.section != snapshotSectionGenesis {
		return nil
	}
	if replay.expectedBoundary != replay.rootInput.RecoveryGeneration+1 {
		return errors.New("genesis lineage is incomplete")
	}
	if _, err := replay.boundaryScratch.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind boundary scratch: %w", err)
	}
	replay.section = snapshotSectionResult
	return replay.readNextBoundary()
}

func (replay *logicalSnapshotSemanticReplay) readNextBoundary() error {
	if replay.pendingBoundary != nil {
		return errors.New("next boundary requested while one is pending")
	}
	if replay.activeView.RecoveryGeneration ==
		replay.rootInput.RecoveryGeneration {
		return nil
	}
	encoded, err := readSnapshotBoundary(replay.boundaryScratch)
	if err != nil {
		return err
	}
	payload, err := logicalsnapshot.DecodeGenesisPayload(encoded)
	if err != nil {
		return fmt.Errorf("decode staged successor genesis: %w", err)
	}
	metadata, err := inspectSnapshotGenesis(payload)
	if err != nil {
		return err
	}
	replay.pendingBoundary = &payload
	replay.pendingMetadata = metadata
	return nil
}

func (replay *logicalSnapshotSemanticReplay) applyReadyBoundaries() error {
	for replay.pendingBoundary != nil {
		metadata := replay.pendingMetadata
		if metadata.predecessorResultIndex < replay.heads.ResultIndex {
			return errors.New("successor boundary was skipped")
		}
		if metadata.predecessorResultIndex > replay.heads.ResultIndex {
			return nil
		}
		if !metadata.hasPredecessor ||
			metadata.generation !=
				replay.activeView.RecoveryGeneration+1 ||
			metadata.sessionID == replay.activeView.SessionID ||
			metadata.workspaceID != replay.activeView.WorkspaceID ||
			metadata.predecessorChainIndex != replay.heads.ChainIndex ||
			metadata.predecessorChainHash !=
				chain.Digest(replay.heads.ChainHash) ||
			metadata.predecessorResultHash !=
				chain.Digest(replay.heads.ResultHash) ||
			metadata.predecessorAccumulator !=
				chain.Digest(replay.heads.ProjectionAccumulator) ||
			metadata.digestVersion != replay.heads.DigestVersion ||
			metadata.projectionVersion !=
				replay.heads.ProjectionSchemaVersion {
			return errors.New(
				"successor predecessor commitments differ from replay",
			)
		}
		payload := *replay.pendingBoundary
		predecessorView, err := replay.stage.View(replay.ctx)
		if err != nil {
			return fmt.Errorf(
				"read predecessor cut for generation %d: %w",
				metadata.generation,
				err,
			)
		}
		if predecessorView.SessionID != replay.activeView.SessionID ||
			predecessorView.WorkspaceID != replay.activeView.WorkspaceID ||
			predecessorView.RecoveryGeneration !=
				replay.activeView.RecoveryGeneration ||
			!sameLogicalSnapshotHeads(
				predecessorView.Heads,
				replay.heads,
			) {
			return errors.New(
				"durable predecessor cut differs from semantic replay",
			)
		}
		successor, err := replay.boundaries.VerifySuccessorBoundary(
			replay.ctx,
			predecessorView,
			payload,
		)
		if err != nil {
			return fmt.Errorf(
				"verify successor generation %d: %w",
				metadata.generation,
				err,
			)
		}
		if successor.SessionID != metadata.sessionID ||
			successor.WorkspaceID != metadata.workspaceID ||
			successor.RecoveryGeneration != metadata.generation ||
			!bytes.Equal(successor.GenesisJSON, payload.GenesisJSON) ||
			!bytes.Equal(
				successor.RecoveryAuthorizationJSON,
				payload.RecoveryAuthorizationJSON,
			) ||
			!sameLogicalSnapshotHeads(
				successor.Predecessor,
				replay.heads,
			) ||
			successor.DigestVersion != metadata.digestVersion ||
			successor.ProjectionSchemaVersion !=
				metadata.projectionVersion {
			return errors.New(
				"verified successor state differs from artifact",
			)
		}
		heads, err := replay.stage.InstallSuccessor(
			replay.ctx,
			successor,
		)
		if err != nil {
			return fmt.Errorf(
				"install staged successor generation %d: %w",
				metadata.generation,
				err,
			)
		}
		view, err := replay.stage.View(replay.ctx)
		if err != nil {
			return fmt.Errorf(
				"read staged successor generation %d: %w",
				metadata.generation,
				err,
			)
		}
		if view.SessionID != metadata.sessionID ||
			view.WorkspaceID != metadata.workspaceID ||
			view.RecoveryGeneration != metadata.generation ||
			view.Heads != heads ||
			chain.Digest(view.ProjectionStateDigest) !=
				metadata.boundaryTransformDigest {
			return errors.New(
				"staged successor transform differs from artifact",
			)
		}
		if err := replay.loadActiveView(view); err != nil {
			return err
		}
		replay.pendingBoundary = nil
		replay.pendingMetadata = snapshotGenesisMetadata{}
		if err := replay.readNextBoundary(); err != nil {
			return err
		}
	}
	return nil
}

func (replay *logicalSnapshotSemanticReplay) consumeResult(
	encoded []byte,
) error {
	if err := replay.finishGenesis(); err != nil {
		return err
	}
	if replay.section != snapshotSectionResult ||
		replay.pendingResult.payload.Result.ResultIndex != 0 {
		return errors.New("result record interrupts semantic replay")
	}
	if err := replay.applyReadyBoundaries(); err != nil {
		return err
	}
	payload, err := logicalsnapshot.DecodeResultPayload(encoded)
	if err != nil {
		return fmt.Errorf("decode result: %w", err)
	}
	if replay.heads.ResultIndex == domain.MaxSafeInteger ||
		payload.Result.ResultIndex != replay.heads.ResultIndex+1 {
		return errors.New("result is not the next dense position")
	}
	replay.pendingResult = pendingSnapshotResult{
		payload: payload,
		mutationBytes: make(
			[]byte,
			0,
			int(payload.MutationBytes),
		),
	}
	return nil
}

func (replay *logicalSnapshotSemanticReplay) consumeMutation(
	encoded []byte,
) error {
	pending := &replay.pendingResult
	if replay.section != snapshotSectionResult ||
		pending.payload.Result.ResultIndex == 0 {
		return errors.New("mutation chunk has no pending result")
	}
	payload, err := logicalsnapshot.DecodeMutationChunkPayload(encoded)
	if err != nil {
		return fmt.Errorf("decode result mutation chunk: %w", err)
	}
	expected := pending.payload
	if payload.ResultIndex != expected.Result.ResultIndex ||
		payload.ChunkIndex != pending.nextChunk ||
		payload.ChunkIndex >= expected.MutationChunkCount {
		return errors.New("mutation chunk identity or order differs")
	}
	offset := payload.ChunkIndex * logicalsnapshot.MaxMutationChunkBytes
	remaining := expected.MutationBytes - offset
	expectedLength := uint64(logicalsnapshot.MaxMutationChunkBytes)
	if remaining < expectedLength {
		expectedLength = remaining
	}
	if expectedLength == 0 || uint64(len(payload.Data)) != expectedLength {
		return errors.New("mutation chunk length differs")
	}
	pending.mutationBytes = append(
		pending.mutationBytes,
		payload.Data...,
	)
	pending.nextChunk++
	if pending.nextChunk != expected.MutationChunkCount {
		return nil
	}
	if uint64(len(pending.mutationBytes)) != expected.MutationBytes ||
		sha256.Sum256(pending.mutationBytes) != expected.MutationDigest {
		return errors.New("mutation stream commitment differs")
	}
	result := pending.payload.Result
	encodedMutations := bytes.Clone(pending.mutationBytes)
	replay.pendingResult = pendingSnapshotResult{}
	return replay.importCommand(result, encodedMutations)
}

func (replay *logicalSnapshotSemanticReplay) importCommand(
	result chain.Result,
	artifactMutationBytes []byte,
) error {
	appliedAt, monotonicNow, err := replay.clock()
	if err != nil {
		return fmt.Errorf("read snapshot import clock: %w", err)
	}
	encodedResult, err := chain.EncodeResult(result)
	if err != nil {
		return fmt.Errorf("encode snapshot result: %w", err)
	}
	imported, err := replay.stage.ReplayCommand(
		replay.ctx,
		encodedResult,
		artifactMutationBytes,
		appliedAt,
		replay.originBootID,
		monotonicNow,
	)
	if err != nil {
		return fmt.Errorf("persist staged snapshot command: %w", err)
	}
	if imported.ResultIndex != result.ResultIndex {
		return errors.New("staged command returned a different result position")
	}
	replay.heads = imported
	replay.activeView.Heads = imported
	return nil
}

func (replay *logicalSnapshotSemanticReplay) finishResults() error {
	if replay.section != snapshotSectionResult {
		return nil
	}
	if replay.pendingResult.payload.Result.ResultIndex != 0 {
		return errors.New("result mutation stream is incomplete")
	}
	if err := replay.applyReadyBoundaries(); err != nil {
		return err
	}
	if replay.pendingBoundary != nil ||
		replay.activeView.SessionID != replay.rootInput.SessionID ||
		replay.activeView.RecoveryGeneration !=
			replay.rootInput.RecoveryGeneration ||
		replay.heads.ChainIndex != replay.rootInput.ChainIndex ||
		replay.heads.ChainHash !=
			store.Digest(replay.rootInput.ChainHash) ||
		replay.heads.ResultIndex != replay.rootInput.ResultIndex ||
		replay.heads.ResultHash !=
			store.Digest(replay.rootInput.ResultHash) ||
		replay.heads.ProjectionAccumulator !=
			store.Digest(replay.rootInput.ProjectionAccumulator) {
		return errors.New("semantic result heads differ from root")
	}
	replay.section = snapshotSectionEvent
	return nil
}

func (replay *logicalSnapshotSemanticReplay) consumeEvent(
	encoded []byte,
) error {
	if err := replay.finishGenesis(); err != nil {
		return err
	}
	if err := replay.finishResults(); err != nil {
		return err
	}
	if replay.section != snapshotSectionEvent {
		return errors.New("event appears outside event section")
	}
	if _, err := logicalsnapshot.DecodeEventPayload(encoded); err != nil {
		return fmt.Errorf("decode accepted event: %w", err)
	}
	return nil
}

func (replay *logicalSnapshotSemanticReplay) startProjections() error {
	if err := replay.finishGenesis(); err != nil {
		return err
	}
	if err := replay.finishResults(); err != nil {
		return err
	}
	switch replay.section {
	case snapshotSectionEvent:
		if err := resetSnapshotScratch(replay.boundaryScratch); err != nil {
			return fmt.Errorf("reset projection scratch: %w", err)
		}
		if err := replay.stage.StreamProjectionRows(
			replay.ctx,
			func(row chain.LogicalRow) error {
				encoded, err := logicalsnapshot.EncodeProjectionPayload(
					logicalsnapshot.ProjectionPayload{Row: row},
				)
				if err != nil {
					return err
				}
				return writeSnapshotBoundary(
					replay.boundaryScratch,
					encoded,
				)
			},
		); err != nil {
			return fmt.Errorf("stream staged projection rows: %w", err)
		}
		if _, err := replay.boundaryScratch.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind projection scratch: %w", err)
		}
		replay.section = snapshotSectionProjection
	case snapshotSectionProjection:
		return nil
	default:
		return errors.New("projection section is out of order")
	}
	return nil
}

func (replay *logicalSnapshotSemanticReplay) consumeProjection(
	encoded []byte,
) error {
	if err := replay.startProjections(); err != nil {
		return err
	}
	payload, err := logicalsnapshot.DecodeProjectionPayload(encoded)
	if err != nil {
		return fmt.Errorf("decode projection row: %w", err)
	}
	expected, err := readSnapshotBoundary(replay.boundaryScratch)
	if err != nil {
		return fmt.Errorf(
			"artifact has more projection rows than staged state: %w",
			err,
		)
	}
	expectedPayload, err := logicalsnapshot.DecodeProjectionPayload(expected)
	if err != nil {
		return fmt.Errorf("decode staged projection row: %w", err)
	}
	if !equalLogicalRow(expectedPayload.Row, payload.Row) {
		return errors.New(
			"artifact projection row differs from staged reducer state",
		)
	}
	return nil
}

func (replay *logicalSnapshotSemanticReplay) consumeCheckpoint(
	encoded []byte,
) error {
	if err := replay.startProjections(); err != nil {
		return err
	}
	if _, err := readSnapshotBoundary(replay.boundaryScratch); err == nil {
		return errors.New("artifact projection rows are incomplete")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("read final staged projection row: %w", err)
	}
	if replay.checkpointSeen {
		return errors.New("artifact contains multiple terminal checkpoints")
	}
	payload, err := logicalsnapshot.DecodeCheckpointPayload(encoded)
	if err != nil {
		return fmt.Errorf("decode terminal checkpoint: %w", err)
	}
	if payload.CheckpointEventID != replay.rootInput.CheckpointEventID {
		return errors.New("terminal checkpoint differs from root")
	}
	replay.checkpointSeen = true
	replay.section = snapshotSectionDone
	return nil
}

func (replay *logicalSnapshotSemanticReplay) finish() error {
	if replay.section != snapshotSectionDone ||
		!replay.checkpointSeen ||
		replay.recordCount != replay.rootInput.RecordCount {
		return errors.New("semantic artifact replay is incomplete")
	}
	return nil
}

func (replay *logicalSnapshotSemanticReplay) loadActiveView(
	view store.StateView,
) error {
	replay.heads = view.Heads
	view.ProjectionRows = nil
	replay.activeView = view
	return nil
}

func verifyExpandedSnapshotEnd(
	artifact LogicalSnapshotImportScratch,
	limited *io.LimitedReader,
	digestBytes []byte,
	recordCount uint64,
	input logicalsnapshot.RootInput,
) error {
	if limited == nil ||
		limited.N != 0 ||
		recordCount != input.RecordCount {
		return snapshotSemanticError(
			"expanded byte or record count differs from root",
			nil,
		)
	}
	var trailing [1]byte
	count, err := artifact.Read(trailing[:])
	if count != 0 || !errors.Is(err, io.EOF) {
		return snapshotSemanticError(
			"expanded artifact has trailing bytes",
			err,
		)
	}
	var digest chain.Digest
	copy(digest[:], digestBytes)
	if digest != input.ArtifactDigest {
		return snapshotSemanticError(
			"expanded artifact digest differs from root",
			nil,
		)
	}
	return nil
}

func logicalSnapshotCutFromRoot(
	input logicalsnapshot.RootInput,
) store.LogicalSnapshotCut {
	return store.LogicalSnapshotCut{
		SessionID:               input.SessionID,
		WorkspaceID:             input.WorkspaceID,
		RecoveryGeneration:      input.RecoveryGeneration,
		CheckpointEventID:       input.CheckpointEventID,
		ChainIndex:              input.ChainIndex,
		ChainHash:               store.Digest(input.ChainHash),
		ResultIndex:             input.ResultIndex,
		ResultHash:              store.Digest(input.ResultHash),
		ProjectionAccumulator:   store.Digest(input.ProjectionAccumulator),
		ProjectionStateDigest:   store.Digest(input.ProjectionStateDigest),
		AuthorityVersion:        input.AuthorityVersion,
		SignerDeviceID:          input.SignerDeviceID,
		DigestVersion:           input.DigestVersion,
		ProjectionSchemaVersion: input.ProjectionSchemaVersion,
		RecordCount:             input.RecordCount,
	}
}

func writeSnapshotBoundary(
	scratch io.Writer,
	encoded []byte,
) error {
	if scratch == nil ||
		len(encoded) < 2 ||
		len(encoded) > logicalsnapshot.MaxRecordPayloadBytes {
		return ErrInvalidLogicalSnapshotImport
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
	for _, value := range [][]byte{length[:], encoded} {
		if err := writeSnapshotBytes(scratch, value); err != nil {
			return fmt.Errorf("write boundary scratch: %w", err)
		}
	}
	return nil
}

func readSnapshotBoundary(
	scratch io.Reader,
) ([]byte, error) {
	if scratch == nil {
		return nil, ErrInvalidLogicalSnapshotImport
	}
	var length [8]byte
	if _, err := io.ReadFull(scratch, length[:]); err != nil {
		return nil, fmt.Errorf("read boundary scratch length: %w", err)
	}
	size := binary.BigEndian.Uint64(length[:])
	if size < 2 || size > logicalsnapshot.MaxRecordPayloadBytes {
		return nil, errors.New("boundary scratch length is invalid")
	}
	encoded := make([]byte, int(size))
	if _, err := io.ReadFull(scratch, encoded); err != nil {
		return nil, fmt.Errorf("read boundary scratch payload: %w", err)
	}
	return encoded, nil
}

func writeSnapshotBytes(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written < 1 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func resetSnapshotScratch(
	scratch LogicalSnapshotReadWriteScratch,
) error {
	if scratch == nil {
		return ErrInvalidLogicalSnapshotImport
	}
	if err := scratch.Truncate(0); err != nil {
		return err
	}
	_, err := scratch.Seek(0, io.SeekStart)
	return err
}

func sameSnapshotScratch(left, right any) bool {
	if isNilSnapshotInterface(left) || isNilSnapshotInterface(right) {
		return false
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if leftValue.Type() == rightValue.Type() {
		switch leftValue.Kind() {
		case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer,
			reflect.Slice, reflect.UnsafePointer:
			if leftValue.Pointer() == rightValue.Pointer() {
				return true
			}
		default:
			if leftValue.Type().Comparable() &&
				leftValue.Interface() == rightValue.Interface() {
				return true
			}
		}
	}
	leftFile, leftOK := left.(interface {
		Stat() (os.FileInfo, error)
	})
	rightFile, rightOK := right.(interface {
		Stat() (os.FileInfo, error)
	})
	if !leftOK || !rightOK {
		return false
	}
	leftInfo, leftErr := leftFile.Stat()
	rightInfo, rightErr := rightFile.Stat()
	return leftErr == nil &&
		rightErr == nil &&
		os.SameFile(leftInfo, rightInfo)
}

func isNilSnapshotInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func equalLogicalRow(left, right chain.LogicalRow) bool {
	return left.Table == right.Table &&
		bytes.Equal(left.PrimaryKey, right.PrimaryKey) &&
		bytes.Equal(left.Row, right.Row)
}

func sameLogicalSnapshotHeads(
	left store.ApplyHeads,
	right store.ApplyHeads,
) bool {
	return left.ChainIndex == right.ChainIndex &&
		left.ChainHash == right.ChainHash &&
		left.ResultIndex == right.ResultIndex &&
		left.ResultHash == right.ResultHash &&
		left.ProjectionAccumulator == right.ProjectionAccumulator &&
		left.DigestVersion == right.DigestVersion &&
		left.ProjectionSchemaVersion == right.ProjectionSchemaVersion
}

func snapshotSemanticError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf(
			"%w: %w: %s",
			ErrInvalidLogicalSnapshotImport,
			ErrLogicalSnapshotSemanticMismatch,
			detail,
		)
	}
	return fmt.Errorf(
		"%w: %w: %s: %w",
		ErrInvalidLogicalSnapshotImport,
		ErrLogicalSnapshotSemanticMismatch,
		detail,
		cause,
	)
}

func inspectSnapshotGenesis(
	payload logicalsnapshot.GenesisPayload,
) (snapshotGenesisMetadata, error) {
	metadata, err := logicalsnapshot.InspectGenesisPayload(payload)
	if err != nil {
		return snapshotGenesisMetadata{}, fmt.Errorf(
			"inspect genesis metadata: %w",
			err,
		)
	}
	return snapshotGenesisMetadata{
		sessionID:              metadata.SessionID,
		workspaceID:            metadata.WorkspaceID,
		generation:             metadata.RecoveryGeneration,
		predecessorChainIndex:  metadata.PredecessorChainIndex,
		predecessorChainHash:   metadata.PredecessorChainHash,
		predecessorResultIndex: metadata.PredecessorResultIndex,
		predecessorResultHash:  metadata.PredecessorResultHash,
		predecessorAccumulator: metadata.
			PredecessorProjectionAccumulator,
		boundaryTransformDigest: metadata.BoundaryTransformDigest,
		digestVersion:           metadata.DigestVersion,
		projectionVersion:       metadata.ProjectionSchemaVersion,
		hasPredecessor:          metadata.HasPredecessor,
	}, nil
}
