package logicalsnapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
)

var (
	ErrInvalidRecordSequence = errors.New(
		"logicalsnapshot: invalid semantic record sequence",
	)
	ErrSequenceFinished = errors.New(
		"logicalsnapshot: semantic sequence is already finished",
	)
)

type sequenceSection uint8

const (
	sectionGenesis sequenceSection = iota
	sectionResult
	sectionEvent
	sectionProjection
	sectionDone
)

const (
	boundaryScratchBytes       = 220
	acceptedDigestScratchBytes = sha256.Size
	maxScratchOffset           = uint64(1<<63 - 1)
)

// SequenceValidator incrementally verifies one expanded artifact's record
// order and hash commitments. Scratch is caller-owned and may be a bounded
// temporary file; only fixed-size generation metadata and projection row
// digests are written to it. Authority signatures, origin signatures, and
// reducer replay are verified by the import layer after this structural pass
// and before state becomes visible.
//
// SequenceValidator is not safe for concurrent use.
type SequenceValidator struct {
	root    RootInput
	scratch io.ReadWriteSeeker

	section     sequenceSection
	recordCount uint64
	failed      error
	finished    bool

	genesisCount         uint64
	lastGenesisDigest    chain.Digest
	lastGenesisSessionID domain.UUIDv7

	replayReadCount uint64
	activeBoundary  sequenceBoundary
	nextBoundary    sequenceBoundary
	hasNextBoundary bool

	resultIndex       uint64
	resultHash        chain.Digest
	resultChainIndex  uint64
	resultChainHash   chain.Digest
	resultAccumulator chain.Digest
	pendingResult     ResultPayload
	pendingMutations  []byte
	pendingChunkIndex uint64

	checkpointCaptured      bool
	checkpointProposal      []byte
	checkpointSignedPayload []byte
	checkpointPre           checkpointPreCut

	eventIndex          uint64
	eventHash           chain.Digest
	checkpointEventSeen bool

	coveredTables          []string
	tableIndexes           map[string]int
	projectionState        hash.Hash
	projectionCurrentTable int
	projectionNextTable    int
	projectionRowCount     uint64
	projectionLastKey      []byte
}

type sequenceBoundary struct {
	generation              uint64
	sessionID               domain.UUIDv7
	genesisDigest           chain.Digest
	predecessorChainIndex   uint64
	predecessorChainHash    chain.Digest
	predecessorResultIndex  uint64
	predecessorResultHash   chain.Digest
	predecessorAccumulator  chain.Digest
	boundaryTransformDigest chain.Digest
}

type checkpointPreCut struct {
	chainIndex  uint64
	chainHash   chain.Digest
	resultIndex uint64
	resultHash  chain.Digest
	accumulator chain.Digest
}

// NewSequenceValidator constructs a fail-closed validator for one signed
// root. Root signature and authority validation remain the caller's job.
func NewSequenceValidator(
	root Root,
	scratch io.ReadWriteSeeker,
) (*SequenceValidator, error) {
	if err := root.validate(); err != nil {
		return nil, err
	}
	if scratch == nil {
		return nil, fmt.Errorf(
			"%w: nil scratch",
			ErrInvalidRecordSequence,
		)
	}
	input := root.Unsigned().Input()
	if input.ChainIndex < 1 {
		return nil, fmt.Errorf(
			"%w: a post-checkpoint root has no accepted checkpoint event",
			ErrInvalidRecordSequence,
		)
	}
	minimum, ok := sequenceMinimumRecordCount(input)
	if !ok || input.RecordCount < minimum {
		return nil, fmt.Errorf(
			"%w: record count is below the deterministic minimum",
			ErrInvalidRecordSequence,
		)
	}
	if _, err := scratch.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf(
			"%w: initialize scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	tables := chain.CoveredTables()
	indexes := make(map[string]int, len(tables))
	for index, table := range tables {
		indexes[table] = index
	}
	return &SequenceValidator{
		root:                   input,
		scratch:                scratch,
		section:                sectionGenesis,
		coveredTables:          tables,
		tableIndexes:           indexes,
		projectionCurrentTable: -1,
	}, nil
}

// Consume validates one record. Any failure is latched and makes all later
// operations return the same error.
func (validator *SequenceValidator) Consume(record Record) error {
	if validator == nil {
		return ErrInvalidRecordSequence
	}
	if validator.failed != nil {
		return validator.failed
	}
	if validator.finished {
		return ErrSequenceFinished
	}
	if !record.Type.valid() {
		return validator.fail(fmt.Errorf(
			"%w: unknown record type",
			ErrInvalidRecordSequence,
		))
	}
	if validator.recordCount >= validator.root.RecordCount {
		return validator.fail(fmt.Errorf(
			"%w: record count exceeds signed root",
			ErrInvalidRecordSequence,
		))
	}
	validator.recordCount++

	var err error
	switch record.Type {
	case RecordGenesis:
		err = validator.consumeGenesis(record.Payload)
	case RecordResult:
		err = validator.consumeResult(record.Payload)
	case RecordMutation:
		err = validator.consumeMutation(record.Payload)
	case RecordEvent:
		err = validator.consumeEvent(record.Payload)
	case RecordProjection:
		err = validator.consumeProjection(record.Payload)
	case RecordCheckpoint:
		err = validator.consumeCheckpoint(record.Payload)
	default:
		err = ErrInvalidRecordSequence
	}
	if err != nil {
		return validator.fail(err)
	}
	return nil
}

// Finish succeeds only after exactly one terminal checkpoint record and the
// root's exact record count.
func (validator *SequenceValidator) Finish() error {
	if validator == nil {
		return ErrInvalidRecordSequence
	}
	if validator.failed != nil {
		return validator.failed
	}
	if validator.finished {
		return nil
	}
	return validator.fail(fmt.Errorf(
		"%w: terminal checkpoint is missing",
		ErrInvalidRecordSequence,
	))
}

func (validator *SequenceValidator) consumeGenesis(encoded []byte) error {
	if validator.section != sectionGenesis {
		return fmt.Errorf(
			"%w: genesis record after genesis section",
			ErrInvalidRecordSequence,
		)
	}
	payload, err := DecodeGenesisPayload(encoded)
	if err != nil {
		return fmt.Errorf(
			"%w: decode genesis: %w",
			ErrInvalidRecordSequence,
			err,
		)
	}
	metadata, err := inspectGenesis(payload.GenesisJSON)
	if err != nil {
		return fmt.Errorf(
			"%w: inspect genesis: %w",
			ErrInvalidRecordSequence,
			err,
		)
	}
	if metadata.generation != validator.genesisCount ||
		metadata.generation > validator.root.RecoveryGeneration ||
		metadata.workspaceID != validator.root.WorkspaceID {
		return fmt.Errorf(
			"%w: genesis lineage identity or generation differs",
			ErrInvalidRecordSequence,
		)
	}
	if metadata.generation == validator.root.RecoveryGeneration {
		if metadata.sessionID != validator.root.SessionID {
			return fmt.Errorf(
				"%w: terminal genesis session differs from root",
				ErrInvalidRecordSequence,
			)
		}
	} else if metadata.sessionID == validator.root.SessionID {
		return fmt.Errorf(
			"%w: root session appears before terminal generation",
			ErrInvalidRecordSequence,
		)
	}
	if metadata.generation > 0 {
		if metadata.predecessorGenesisDigest !=
			validator.lastGenesisDigest ||
			metadata.digestVersion != validator.root.DigestVersion ||
			metadata.projectionSchemaVersion !=
				validator.root.ProjectionSchemaVersion {
			return fmt.Errorf(
				"%w: successor genesis does not continue prior boundary",
				ErrInvalidRecordSequence,
			)
		}
	}
	seen, err := validator.priorGenesisSessionID(metadata.sessionID)
	if err != nil {
		return err
	}
	if seen {
		return fmt.Errorf(
			"%w: genesis session ID is reused",
			ErrInvalidRecordSequence,
		)
	}
	metadata.boundaryTransformDigest = payload.BoundaryTransformDigest
	boundary := sequenceBoundary{
		generation:              metadata.generation,
		sessionID:               metadata.sessionID,
		genesisDigest:           metadata.genesisDigest,
		predecessorChainIndex:   metadata.predecessorChainIndex,
		predecessorChainHash:    metadata.predecessorChainHash,
		predecessorResultIndex:  metadata.predecessorResultIndex,
		predecessorResultHash:   metadata.predecessorResultHash,
		predecessorAccumulator:  metadata.predecessorAccumulator,
		boundaryTransformDigest: metadata.boundaryTransformDigest,
	}
	if err := writeSequenceBoundary(validator.scratch, boundary); err != nil {
		return fmt.Errorf(
			"%w: write generation scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	validator.genesisCount++
	validator.lastGenesisDigest = metadata.genesisDigest
	validator.lastGenesisSessionID = metadata.sessionID
	return nil
}

func (validator *SequenceValidator) priorGenesisSessionID(
	sessionID domain.UUIDv7,
) (bool, error) {
	appendOffset, ok := scratchProductOffset(
		validator.genesisCount,
		boundaryScratchBytes,
	)
	if !ok {
		return false, fmt.Errorf(
			"%w: generation scratch offset exceeds range",
			ErrInvalidRecordSequence,
		)
	}
	for index := uint64(0); index < validator.genesisCount; index++ {
		offset, ok := scratchProductOffset(index, boundaryScratchBytes)
		if !ok {
			return false, fmt.Errorf(
				"%w: generation scratch offset exceeds range",
				ErrInvalidRecordSequence,
			)
		}
		if _, err := validator.scratch.Seek(offset, io.SeekStart); err != nil {
			return false, fmt.Errorf(
				"%w: seek generation scratch: %v",
				ErrInvalidRecordSequence,
				err,
			)
		}
		var encoded [boundaryScratchBytes]byte
		if _, err := io.ReadFull(validator.scratch, encoded[:]); err != nil {
			return false, fmt.Errorf(
				"%w: read generation scratch: %v",
				ErrInvalidRecordSequence,
				err,
			)
		}
		boundary, err := decodeSequenceBoundary(encoded)
		if err != nil {
			return false, fmt.Errorf(
				"%w: decode generation scratch: %v",
				ErrInvalidRecordSequence,
				err,
			)
		}
		if boundary.sessionID == sessionID {
			return true, nil
		}
	}
	if _, err := validator.scratch.Seek(appendOffset, io.SeekStart); err != nil {
		return false, fmt.Errorf(
			"%w: restore generation scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	return false, nil
}

func (validator *SequenceValidator) consumeResult(encoded []byte) error {
	if validator.section == sectionGenesis {
		if err := validator.finishGenesis(); err != nil {
			return err
		}
	}
	if validator.section != sectionResult {
		return fmt.Errorf(
			"%w: result record outside result section",
			ErrInvalidRecordSequence,
		)
	}
	if validator.pendingResult.Result.ResultIndex != 0 {
		return fmt.Errorf(
			"%w: result record interrupted its mutation chunks",
			ErrInvalidRecordSequence,
		)
	}
	payload, err := DecodeResultPayload(encoded)
	if err != nil {
		return fmt.Errorf(
			"%w: decode result: %w",
			ErrInvalidRecordSequence,
			err,
		)
	}
	if validator.resultIndex >= domain.MaxSafeInteger ||
		payload.Result.ResultIndex != validator.resultIndex+1 ||
		payload.Result.ResultIndex > validator.root.ResultIndex {
		return fmt.Errorf(
			"%w: result indexes are not the signed dense prefix",
			ErrInvalidRecordSequence,
		)
	}
	validator.pendingResult = payload
	validator.pendingMutations = make(
		[]byte,
		0,
		int(payload.MutationBytes),
	)
	validator.pendingChunkIndex = 0
	return nil
}

func (validator *SequenceValidator) consumeMutation(encoded []byte) error {
	if validator.section != sectionResult ||
		validator.pendingResult.Result.ResultIndex == 0 {
		return fmt.Errorf(
			"%w: mutation chunk outside its result",
			ErrInvalidRecordSequence,
		)
	}
	payload, err := DecodeMutationChunkPayload(encoded)
	if err != nil {
		return fmt.Errorf(
			"%w: decode mutation chunk: %w",
			ErrInvalidRecordSequence,
			err,
		)
	}
	pending := validator.pendingResult
	if payload.ResultIndex != pending.Result.ResultIndex ||
		payload.ChunkIndex != validator.pendingChunkIndex ||
		payload.ChunkIndex >= pending.MutationChunkCount {
		return fmt.Errorf(
			"%w: mutation chunk identity or order differs",
			ErrInvalidRecordSequence,
		)
	}
	offset := payload.ChunkIndex * MaxMutationChunkBytes
	remaining := pending.MutationBytes - offset
	expectedBytes := uint64(MaxMutationChunkBytes)
	if remaining < expectedBytes {
		expectedBytes = remaining
	}
	if expectedBytes < 1 || uint64(len(payload.Data)) != expectedBytes {
		return fmt.Errorf(
			"%w: mutation chunk length differs",
			ErrInvalidRecordSequence,
		)
	}
	validator.pendingMutations = append(
		validator.pendingMutations,
		payload.Data...,
	)
	validator.pendingChunkIndex++
	if validator.pendingChunkIndex < pending.MutationChunkCount {
		return nil
	}
	if uint64(len(validator.pendingMutations)) != pending.MutationBytes ||
		sha256.Sum256(validator.pendingMutations) != pending.MutationDigest {
		return fmt.Errorf(
			"%w: mutation stream commitment differs",
			ErrInvalidRecordSequence,
		)
	}
	mutations, err := chain.DecodeMutations(validator.pendingMutations)
	if err != nil {
		return fmt.Errorf(
			"%w: decode mutation stream: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	validator.pendingResult = ResultPayload{}
	validator.pendingMutations = nil
	validator.pendingChunkIndex = 0
	return validator.finishResult(pending.Result, mutations)
}

func (validator *SequenceValidator) finishResult(
	result chain.Result,
	mutations []chain.Mutation,
) error {
	if err := validator.applyResultBoundaries(); err != nil {
		return err
	}
	proposal, err := event.InspectUnverifiedProposal(result.Proposal)
	if err != nil ||
		proposal.SessionID != validator.activeBoundary.sessionID ||
		proposal.WorkspaceID != validator.root.WorkspaceID {
		return fmt.Errorf(
			"%w: result proposal lineage differs: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}

	pre := checkpointPreCut{
		chainIndex:  validator.resultChainIndex,
		chainHash:   validator.resultChainHash,
		resultIndex: validator.resultIndex,
		resultHash:  validator.resultHash,
		accumulator: validator.resultAccumulator,
	}
	if err := validator.extendResultEventHead(result); err != nil {
		return err
	}
	if result.ChainIndex != nil {
		if err := validator.writeAcceptedProposalDigest(
			*result.ChainIndex,
			result.ProposalDigest,
		); err != nil {
			return err
		}
	}
	nextResultHash, _, err := chain.AppendResult(
		validator.resultHash,
		result,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: append result chain: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	nextAccumulator, _, err := chain.AppendAccumulator(
		validator.resultAccumulator,
		result.ResultIndex,
		nextResultHash,
		mutations,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: append projection accumulator: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}

	if proposal.EventID == validator.root.CheckpointEventID {
		if validator.checkpointCaptured ||
			proposal.Kind != event.KindConsensusCheckpoint ||
			result.ChainIndex == nil ||
			result.ResultIndex != validator.root.ResultIndex ||
			*result.ChainIndex != validator.root.ChainIndex {
			return fmt.Errorf(
				"%w: root checkpoint is not the terminal accepted result",
				ErrInvalidRecordSequence,
			)
		}
		checkpoint, _, err := event.DecodeCheckpointPayload(proposal.Payload)
		if err != nil {
			return fmt.Errorf(
				"%w: decode checkpoint proposal: %v",
				ErrInvalidRecordSequence,
				err,
			)
		}
		if err := validator.validateCheckpointPreCut(
			checkpoint,
			pre,
		); err != nil {
			return err
		}
		validator.checkpointCaptured = true
		validator.checkpointProposal = bytes.Clone(result.Proposal)
		validator.checkpointSignedPayload = bytes.Clone(proposal.Payload)
		validator.checkpointPre = pre
	}

	validator.resultIndex = result.ResultIndex
	validator.resultHash = nextResultHash
	validator.resultAccumulator = nextAccumulator
	return nil
}

func (validator *SequenceValidator) extendResultEventHead(
	result chain.Result,
) error {
	if result.ChainIndex == nil {
		return nil
	}
	if validator.resultChainIndex >= domain.MaxSafeInteger ||
		*result.ChainIndex != validator.resultChainIndex+1 {
		return fmt.Errorf(
			"%w: accepted result chain index is not dense",
			ErrInvalidRecordSequence,
		)
	}
	computed, err := chain.AppendEvent(
		validator.resultChainHash,
		result.Proposal,
	)
	if err != nil ||
		result.ChainHash == nil ||
		computed != *result.ChainHash {
		return fmt.Errorf(
			"%w: accepted result event link differs: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	validator.resultChainIndex = *result.ChainIndex
	validator.resultChainHash = computed
	return nil
}

func (validator *SequenceValidator) consumeEvent(encoded []byte) error {
	if validator.section == sectionGenesis {
		if err := validator.finishGenesis(); err != nil {
			return err
		}
	}
	if validator.section == sectionResult {
		if err := validator.finishResults(); err != nil {
			return err
		}
	}
	if validator.section != sectionEvent {
		return fmt.Errorf(
			"%w: event record outside event section",
			ErrInvalidRecordSequence,
		)
	}
	payload, err := DecodeEventPayload(encoded)
	if err != nil {
		return fmt.Errorf(
			"%w: decode event: %w",
			ErrInvalidRecordSequence,
			err,
		)
	}
	if validator.eventIndex >= domain.MaxSafeInteger ||
		payload.ChainIndex != validator.eventIndex+1 ||
		payload.ChainIndex > validator.root.ChainIndex {
		return fmt.Errorf(
			"%w: event indexes are not the signed dense prefix",
			ErrInvalidRecordSequence,
		)
	}
	if err := validator.applyEventBoundaries(); err != nil {
		return err
	}
	proposal, err := event.InspectUnverifiedProposal(payload.Proposal)
	if err != nil ||
		proposal.SessionID != validator.activeBoundary.sessionID ||
		proposal.WorkspaceID != validator.root.WorkspaceID {
		return fmt.Errorf(
			"%w: event proposal lineage differs: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	expectedProposalDigest, err := validator.readAcceptedProposalDigest(
		payload.ChainIndex,
	)
	if err != nil {
		return err
	}
	if sha256.Sum256(payload.Proposal) != expectedProposalDigest {
		return fmt.Errorf(
			"%w: event proposal differs from its accepted result",
			ErrInvalidRecordSequence,
		)
	}
	computed, err := chain.AppendEvent(validator.eventHash, payload.Proposal)
	if err != nil || computed != payload.ChainHash {
		return fmt.Errorf(
			"%w: event link differs: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	if proposal.EventID == validator.root.CheckpointEventID {
		if validator.checkpointEventSeen ||
			payload.ChainIndex != validator.root.ChainIndex ||
			!bytes.Equal(payload.Proposal, validator.checkpointProposal) {
			return fmt.Errorf(
				"%w: terminal checkpoint event differs from result",
				ErrInvalidRecordSequence,
			)
		}
		validator.checkpointEventSeen = true
	}
	validator.eventIndex = payload.ChainIndex
	validator.eventHash = computed
	return nil
}

func (validator *SequenceValidator) consumeProjection(encoded []byte) error {
	if err := validator.startProjectionSection(); err != nil {
		return err
	}
	payload, err := DecodeProjectionPayload(encoded)
	if err != nil {
		return fmt.Errorf(
			"%w: decode projection: %w",
			ErrInvalidRecordSequence,
			err,
		)
	}
	tableIndex, exists := validator.tableIndexes[payload.Row.Table]
	if !exists {
		return fmt.Errorf(
			"%w: projection table is not covered",
			ErrInvalidRecordSequence,
		)
	}
	if validator.projectionCurrentTable >= 0 &&
		tableIndex < validator.projectionCurrentTable {
		return fmt.Errorf(
			"%w: projection table order regressed",
			ErrInvalidRecordSequence,
		)
	}
	if tableIndex != validator.projectionCurrentTable {
		if err := validator.advanceProjectionTable(tableIndex); err != nil {
			return err
		}
	}
	if validator.projectionRowCount > 0 &&
		bytes.Compare(
			validator.projectionLastKey,
			payload.Row.PrimaryKey,
		) >= 0 {
		return fmt.Errorf(
			"%w: projection keys are duplicate or out of order",
			ErrInvalidRecordSequence,
		)
	}
	if validator.projectionRowCount >= domain.MaxSafeInteger {
		return fmt.Errorf(
			"%w: projection table row count exceeds exact range",
			ErrInvalidRecordSequence,
		)
	}
	digest := projectionRowDigest(payload.Row)
	if err := writeAll(validator.scratch, digest[:]); err != nil {
		return fmt.Errorf(
			"%w: write projection scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	validator.projectionRowCount++
	validator.projectionLastKey = bytes.Clone(payload.Row.PrimaryKey)
	return nil
}

func (validator *SequenceValidator) consumeCheckpoint(encoded []byte) error {
	if err := validator.startProjectionSection(); err != nil {
		return err
	}
	if err := validator.finishProjectionState(); err != nil {
		return err
	}
	payload, err := DecodeCheckpointPayload(encoded)
	if err != nil {
		return fmt.Errorf(
			"%w: decode checkpoint: %w",
			ErrInvalidRecordSequence,
			err,
		)
	}
	checkpoint, _, err := decodeSignedCheckpoint(payload)
	if err != nil {
		return fmt.Errorf(
			"%w: decode terminal checkpoint: %w",
			ErrInvalidRecordSequence,
			err,
		)
	}
	if payload.CheckpointEventID != validator.root.CheckpointEventID ||
		!bytes.Equal(
			payload.SignedPayload,
			validator.checkpointSignedPayload,
		) ||
		validator.validateCheckpointPreCut(
			checkpoint,
			validator.checkpointPre,
		) != nil {
		return fmt.Errorf(
			"%w: terminal checkpoint differs from accepted command",
			ErrInvalidRecordSequence,
		)
	}
	if validator.recordCount != validator.root.RecordCount {
		return fmt.Errorf(
			"%w: record count differs from signed root",
			ErrInvalidRecordSequence,
		)
	}
	validator.section = sectionDone
	validator.finished = true
	validator.checkpointProposal = nil
	validator.checkpointSignedPayload = nil
	return nil
}

func (validator *SequenceValidator) finishGenesis() error {
	if validator.section != sectionGenesis {
		return nil
	}
	if validator.genesisCount != validator.root.RecoveryGeneration+1 ||
		validator.lastGenesisSessionID != validator.root.SessionID {
		return fmt.Errorf(
			"%w: genesis records are not the complete dense lineage",
			ErrInvalidRecordSequence,
		)
	}
	if err := validator.prepareBoundaryReplay(); err != nil {
		return err
	}
	initial := chain.Boundary{
		Genesis: validator.activeBoundary.genesisDigest,
	}
	var err error
	validator.resultChainHash, err = chain.EventSeed(initial)
	if err != nil {
		return fmt.Errorf(
			"%w: seed event chain: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	validator.resultHash, err = chain.ResultSeed(initial)
	if err != nil {
		return fmt.Errorf(
			"%w: seed result chain: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	validator.resultAccumulator = chain.AccumulatorSeedInitial(
		validator.activeBoundary.genesisDigest,
		validator.activeBoundary.boundaryTransformDigest,
	)
	validator.section = sectionResult
	return nil
}

func (validator *SequenceValidator) finishResults() error {
	if validator.section != sectionResult {
		return nil
	}
	if validator.pendingResult.Result.ResultIndex != 0 {
		return fmt.Errorf(
			"%w: result mutation stream is incomplete",
			ErrInvalidRecordSequence,
		)
	}
	if err := validator.applyResultBoundaries(); err != nil {
		return err
	}
	if validator.hasNextBoundary ||
		validator.activeBoundary.generation !=
			validator.root.RecoveryGeneration ||
		validator.activeBoundary.sessionID != validator.root.SessionID ||
		validator.resultIndex != validator.root.ResultIndex ||
		validator.resultHash != validator.root.ResultHash ||
		validator.resultChainIndex != validator.root.ChainIndex ||
		validator.resultChainHash != validator.root.ChainHash ||
		validator.resultAccumulator != validator.root.ProjectionAccumulator ||
		!validator.checkpointCaptured {
		return fmt.Errorf(
			"%w: result-derived heads differ from signed root",
			ErrInvalidRecordSequence,
		)
	}
	if err := validator.prepareBoundaryReplay(); err != nil {
		return err
	}
	initial := chain.Boundary{
		Genesis: validator.activeBoundary.genesisDigest,
	}
	var err error
	validator.eventHash, err = chain.EventSeed(initial)
	if err != nil {
		return fmt.Errorf(
			"%w: seed event replay: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	validator.section = sectionEvent
	return nil
}

func (validator *SequenceValidator) finishEvents() error {
	if validator.section == sectionResult {
		if err := validator.finishResults(); err != nil {
			return err
		}
	}
	if validator.section != sectionEvent {
		return nil
	}
	if err := validator.applyEventBoundaries(); err != nil {
		return err
	}
	if validator.hasNextBoundary ||
		validator.activeBoundary.generation !=
			validator.root.RecoveryGeneration ||
		validator.activeBoundary.sessionID != validator.root.SessionID ||
		validator.eventIndex != validator.root.ChainIndex ||
		validator.eventHash != validator.root.ChainHash ||
		!validator.checkpointEventSeen {
		return fmt.Errorf(
			"%w: event-derived head differs from signed root",
			ErrInvalidRecordSequence,
		)
	}
	return nil
}

func (validator *SequenceValidator) startProjectionSection() error {
	switch validator.section {
	case sectionGenesis:
		if err := validator.finishGenesis(); err != nil {
			return err
		}
		fallthrough
	case sectionResult:
		if err := validator.finishResults(); err != nil {
			return err
		}
		fallthrough
	case sectionEvent:
		if err := validator.finishEvents(); err != nil {
			return err
		}
		if _, err := validator.scratch.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf(
				"%w: reset projection scratch: %v",
				ErrInvalidRecordSequence,
				err,
			)
		}
		validator.projectionState = sha256.New()
		writeHash(
			validator.projectionState,
			[]byte("codecomm/v1/projection-state"),
		)
		writeHash(validator.projectionState, []byte{0})
		writeHashUint64(
			validator.projectionState,
			validator.root.DigestVersion,
		)
		writeHashUint64(
			validator.projectionState,
			validator.root.ProjectionSchemaVersion,
		)
		validator.section = sectionProjection
	case sectionProjection:
		return nil
	default:
		return fmt.Errorf(
			"%w: records follow terminal checkpoint",
			ErrInvalidRecordSequence,
		)
	}
	return nil
}

func (validator *SequenceValidator) finishProjectionState() error {
	if validator.section != sectionProjection ||
		validator.projectionState == nil {
		return fmt.Errorf(
			"%w: projection section was not initialized",
			ErrInvalidRecordSequence,
		)
	}
	if validator.projectionCurrentTable >= 0 {
		if err := validator.finishProjectionTable(); err != nil {
			return err
		}
	}
	for validator.projectionNextTable < len(validator.coveredTables) {
		digest := emptyProjectionTableDigest(
			validator.coveredTables[validator.projectionNextTable],
		)
		writeHash(validator.projectionState, digest[:])
		validator.projectionNextTable++
	}
	var digest chain.Digest
	copy(digest[:], validator.projectionState.Sum(nil))
	if digest != validator.root.ProjectionStateDigest {
		return fmt.Errorf(
			"%w: projection-state digest differs from signed root",
			ErrInvalidRecordSequence,
		)
	}
	validator.projectionState = nil
	return nil
}

func (validator *SequenceValidator) prepareBoundaryReplay() error {
	if _, err := validator.scratch.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf(
			"%w: rewind generation scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	validator.replayReadCount = 0
	initial, exists, err := validator.readBoundary()
	if err != nil {
		return err
	}
	if !exists || initial.generation != 0 {
		return fmt.Errorf(
			"%w: generation zero is missing",
			ErrInvalidRecordSequence,
		)
	}
	validator.activeBoundary = initial
	next, exists, err := validator.readBoundary()
	if err != nil {
		return err
	}
	validator.nextBoundary = next
	validator.hasNextBoundary = exists
	return nil
}

func (validator *SequenceValidator) readBoundary() (
	sequenceBoundary,
	bool,
	error,
) {
	if validator.replayReadCount >= validator.genesisCount {
		return sequenceBoundary{}, false, nil
	}
	offset, ok := scratchProductOffset(
		validator.replayReadCount,
		boundaryScratchBytes,
	)
	if !ok {
		return sequenceBoundary{}, false, fmt.Errorf(
			"%w: generation scratch offset exceeds platform range",
			ErrInvalidRecordSequence,
		)
	}
	if _, err := validator.scratch.Seek(offset, io.SeekStart); err != nil {
		return sequenceBoundary{}, false, fmt.Errorf(
			"%w: seek generation scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	var encoded [boundaryScratchBytes]byte
	if _, err := io.ReadFull(validator.scratch, encoded[:]); err != nil {
		return sequenceBoundary{}, false, fmt.Errorf(
			"%w: read generation scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	boundary, err := decodeSequenceBoundary(encoded)
	if err != nil {
		return sequenceBoundary{}, false, fmt.Errorf(
			"%w: decode generation scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	validator.replayReadCount++
	return boundary, true, nil
}

func (validator *SequenceValidator) writeAcceptedProposalDigest(
	chainIndex uint64,
	digest chain.Digest,
) error {
	offset, ok := validator.acceptedProposalDigestOffset(chainIndex)
	if !ok {
		return fmt.Errorf(
			"%w: accepted-proposal scratch offset is invalid",
			ErrInvalidRecordSequence,
		)
	}
	if _, err := validator.scratch.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf(
			"%w: seek accepted-proposal scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	if err := writeAll(validator.scratch, digest[:]); err != nil {
		return fmt.Errorf(
			"%w: write accepted-proposal scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	return nil
}

func (validator *SequenceValidator) readAcceptedProposalDigest(
	chainIndex uint64,
) (chain.Digest, error) {
	offset, ok := validator.acceptedProposalDigestOffset(chainIndex)
	if !ok {
		return chain.Digest{}, fmt.Errorf(
			"%w: accepted-proposal scratch offset is invalid",
			ErrInvalidRecordSequence,
		)
	}
	if _, err := validator.scratch.Seek(offset, io.SeekStart); err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: seek accepted-proposal scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	var digest chain.Digest
	if _, err := io.ReadFull(validator.scratch, digest[:]); err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: read accepted-proposal scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	return digest, nil
}

func (validator *SequenceValidator) acceptedProposalDigestOffset(
	chainIndex uint64,
) (int64, bool) {
	if chainIndex < 1 ||
		!domain.ValidUnsignedInteger(chainIndex) {
		return 0, false
	}
	boundaryBytes, ok := scratchProductOffsetUint64(
		validator.genesisCount,
		boundaryScratchBytes,
	)
	if !ok {
		return 0, false
	}
	digestBytes, ok := scratchProductOffsetUint64(
		chainIndex-1,
		acceptedDigestScratchBytes,
	)
	if !ok || boundaryBytes > maxScratchOffset-digestBytes {
		return 0, false
	}
	return int64(boundaryBytes + digestBytes), true
}

func (validator *SequenceValidator) advanceBoundaryReplay() error {
	validator.activeBoundary = validator.nextBoundary
	next, exists, err := validator.readBoundary()
	if err != nil {
		return err
	}
	validator.nextBoundary = next
	validator.hasNextBoundary = exists
	return nil
}

func (validator *SequenceValidator) applyResultBoundaries() error {
	for validator.hasNextBoundary {
		next := validator.nextBoundary
		if next.predecessorResultIndex < validator.resultIndex {
			return fmt.Errorf(
				"%w: successor result boundary was skipped",
				ErrInvalidRecordSequence,
			)
		}
		if next.predecessorResultIndex > validator.resultIndex {
			return nil
		}
		if next.generation != validator.activeBoundary.generation+1 ||
			next.predecessorChainIndex != validator.resultChainIndex ||
			next.predecessorChainHash != validator.resultChainHash ||
			next.predecessorResultHash != validator.resultHash ||
			next.predecessorAccumulator != validator.resultAccumulator {
			return fmt.Errorf(
				"%w: successor predecessor commitments differ",
				ErrInvalidRecordSequence,
			)
		}
		boundary := chain.Boundary{
			Genesis:     next.genesisDigest,
			Generation:  next.generation,
			ChainIndex:  next.predecessorChainIndex,
			ResultIndex: next.predecessorResultIndex,
			ChainHash:   next.predecessorChainHash,
			ResultHash:  next.predecessorResultHash,
		}
		eventSeed, err := chain.EventSeed(boundary)
		if err != nil {
			return fmt.Errorf(
				"%w: seed successor event chain: %v",
				ErrInvalidRecordSequence,
				err,
			)
		}
		resultSeed, err := chain.ResultSeed(boundary)
		if err != nil {
			return fmt.Errorf(
				"%w: seed successor result chain: %v",
				ErrInvalidRecordSequence,
				err,
			)
		}
		validator.resultChainHash = eventSeed
		validator.resultHash = resultSeed
		validator.resultAccumulator = chain.AccumulatorSeedSuccessor(
			validator.resultAccumulator,
			next.genesisDigest,
			next.boundaryTransformDigest,
		)
		if err := validator.advanceBoundaryReplay(); err != nil {
			return err
		}
	}
	return nil
}

func (validator *SequenceValidator) applyEventBoundaries() error {
	for validator.hasNextBoundary {
		next := validator.nextBoundary
		if next.predecessorChainIndex < validator.eventIndex {
			return fmt.Errorf(
				"%w: successor event boundary was skipped",
				ErrInvalidRecordSequence,
			)
		}
		if next.predecessorChainIndex > validator.eventIndex {
			return nil
		}
		if next.generation != validator.activeBoundary.generation+1 ||
			next.predecessorChainHash != validator.eventHash {
			return fmt.Errorf(
				"%w: successor event predecessor differs",
				ErrInvalidRecordSequence,
			)
		}
		seed, err := chain.EventSeed(chain.Boundary{
			Genesis:     next.genesisDigest,
			Generation:  next.generation,
			ChainIndex:  next.predecessorChainIndex,
			ResultIndex: next.predecessorResultIndex,
			ChainHash:   next.predecessorChainHash,
			ResultHash:  next.predecessorResultHash,
		})
		if err != nil {
			return fmt.Errorf(
				"%w: seed successor event replay: %v",
				ErrInvalidRecordSequence,
				err,
			)
		}
		validator.eventHash = seed
		if err := validator.advanceBoundaryReplay(); err != nil {
			return err
		}
	}
	return nil
}

func (validator *SequenceValidator) validateCheckpointPreCut(
	checkpoint domain.Checkpoint,
	pre checkpointPreCut,
) error {
	if checkpoint.SessionID != validator.root.SessionID ||
		checkpoint.WorkspaceID != validator.root.WorkspaceID ||
		checkpoint.RecoveryGeneration != validator.root.RecoveryGeneration ||
		checkpoint.AuthorityVoterSetVersion != validator.root.AuthorityVersion ||
		checkpoint.CoveredChainIndex != pre.chainIndex ||
		chain.Digest(checkpoint.CoveredChainHash) != pre.chainHash ||
		checkpoint.CoveredResultIndex != pre.resultIndex ||
		chain.Digest(checkpoint.CoveredResultHash) != pre.resultHash ||
		chain.Digest(checkpoint.ProjectionAccumulator) != pre.accumulator ||
		checkpoint.DigestVersion != validator.root.DigestVersion ||
		checkpoint.ProjectionSchemaVersion !=
			validator.root.ProjectionSchemaVersion ||
		pre.chainIndex >= domain.MaxSafeInteger ||
		pre.resultIndex >= domain.MaxSafeInteger ||
		pre.chainIndex+1 != validator.root.ChainIndex ||
		pre.resultIndex+1 != validator.root.ResultIndex {
		return fmt.Errorf(
			"%w: checkpoint does not attest the immediate pre-root cut",
			ErrInvalidRecordSequence,
		)
	}
	return nil
}

func (validator *SequenceValidator) advanceProjectionTable(
	tableIndex int,
) error {
	if validator.projectionCurrentTable >= 0 {
		if err := validator.finishProjectionTable(); err != nil {
			return err
		}
	}
	if tableIndex < validator.projectionNextTable {
		return fmt.Errorf(
			"%w: projection table order differs",
			ErrInvalidRecordSequence,
		)
	}
	for validator.projectionNextTable < tableIndex {
		digest := emptyProjectionTableDigest(
			validator.coveredTables[validator.projectionNextTable],
		)
		writeHash(validator.projectionState, digest[:])
		validator.projectionNextTable++
	}
	if _, err := validator.scratch.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf(
			"%w: reset table scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	validator.projectionCurrentTable = tableIndex
	validator.projectionRowCount = 0
	validator.projectionLastKey = nil
	return nil
}

func (validator *SequenceValidator) finishProjectionTable() error {
	if validator.projectionCurrentTable < 0 ||
		validator.projectionCurrentTable != validator.projectionNextTable {
		return fmt.Errorf(
			"%w: projection table state is inconsistent",
			ErrInvalidRecordSequence,
		)
	}
	table := validator.coveredTables[validator.projectionCurrentTable]
	digester := sha256.New()
	writeHash(digester, []byte("codecomm/v1/projection-table"))
	writeHash(digester, []byte{0})
	writeHashUint64(digester, uint64(len(table)))
	writeHash(digester, []byte(table))
	writeHashUint64(digester, validator.projectionRowCount)
	if _, err := validator.scratch.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf(
			"%w: rewind table scratch: %v",
			ErrInvalidRecordSequence,
			err,
		)
	}
	var rowDigest [sha256.Size]byte
	for index := uint64(0); index < validator.projectionRowCount; index++ {
		if _, err := io.ReadFull(
			validator.scratch,
			rowDigest[:],
		); err != nil {
			return fmt.Errorf(
				"%w: read table scratch: %v",
				ErrInvalidRecordSequence,
				err,
			)
		}
		writeHash(digester, rowDigest[:])
	}
	writeHash(validator.projectionState, digester.Sum(nil))
	validator.projectionNextTable++
	validator.projectionCurrentTable = -1
	validator.projectionRowCount = 0
	validator.projectionLastKey = nil
	return nil
}

func (validator *SequenceValidator) fail(err error) error {
	if validator.failed == nil {
		if !errors.Is(err, ErrInvalidRecordSequence) {
			err = fmt.Errorf("%w: %w", ErrInvalidRecordSequence, err)
		}
		validator.failed = err
	}
	return validator.failed
}

func sequenceMinimumRecordCount(input RootInput) (uint64, bool) {
	total := input.RecoveryGeneration
	for _, value := range []uint64{
		1,
		input.ResultIndex,
		input.ResultIndex,
		input.ChainIndex,
		1,
	} {
		if total > domain.MaxSafeInteger-value {
			return 0, false
		}
		total += value
	}
	return total, true
}

func scratchProductOffset(count uint64, width uint64) (int64, bool) {
	value, ok := scratchProductOffsetUint64(count, width)
	return int64(value), ok
}

func scratchProductOffsetUint64(count uint64, width uint64) (uint64, bool) {
	if width == 0 || count > maxScratchOffset/width {
		return 0, false
	}
	return count * width, true
}

func writeSequenceBoundary(
	writer io.Writer,
	boundary sequenceBoundary,
) error {
	var encoded [boundaryScratchBytes]byte
	offset := 0
	putUint64 := func(value uint64) {
		binary.BigEndian.PutUint64(encoded[offset:offset+8], value)
		offset += 8
	}
	putBytes := func(value []byte) {
		copy(encoded[offset:offset+len(value)], value)
		offset += len(value)
	}
	putUint64(boundary.generation)
	putBytes([]byte(boundary.sessionID))
	putBytes(boundary.genesisDigest[:])
	putUint64(boundary.predecessorChainIndex)
	putBytes(boundary.predecessorChainHash[:])
	putUint64(boundary.predecessorResultIndex)
	putBytes(boundary.predecessorResultHash[:])
	putBytes(boundary.predecessorAccumulator[:])
	putBytes(boundary.boundaryTransformDigest[:])
	if offset != len(encoded) {
		return errors.New("logicalsnapshot: internal boundary size mismatch")
	}
	return writeAll(writer, encoded[:])
}

func decodeSequenceBoundary(
	encoded [boundaryScratchBytes]byte,
) (sequenceBoundary, error) {
	offset := 0
	readUint64 := func() uint64 {
		value := binary.BigEndian.Uint64(encoded[offset : offset+8])
		offset += 8
		return value
	}
	readBytes := func(target []byte) {
		copy(target, encoded[offset:offset+len(target)])
		offset += len(target)
	}
	boundary := sequenceBoundary{generation: readUint64()}
	boundary.sessionID = domain.UUIDv7(
		string(encoded[offset : offset+36]),
	)
	offset += 36
	readBytes(boundary.genesisDigest[:])
	boundary.predecessorChainIndex = readUint64()
	readBytes(boundary.predecessorChainHash[:])
	boundary.predecessorResultIndex = readUint64()
	readBytes(boundary.predecessorResultHash[:])
	readBytes(boundary.predecessorAccumulator[:])
	readBytes(boundary.boundaryTransformDigest[:])
	if offset != len(encoded) ||
		!boundary.sessionID.Valid() ||
		!domain.ValidUnsignedInteger(boundary.generation) ||
		!domain.ValidUnsignedInteger(boundary.predecessorChainIndex) ||
		!domain.ValidUnsignedInteger(boundary.predecessorResultIndex) {
		return sequenceBoundary{}, errors.New(
			"logicalsnapshot: invalid boundary scratch record",
		)
	}
	return boundary, nil
}

func projectionRowDigest(row chain.LogicalRow) chain.Digest {
	digester := sha256.New()
	writeHash(digester, []byte("codecomm/v1/projection-row"))
	writeHash(digester, []byte{0})
	writeHashUint64(digester, uint64(len(row.Table)))
	writeHash(digester, []byte(row.Table))
	writeHashUint64(digester, uint64(len(row.PrimaryKey)))
	writeHash(digester, row.PrimaryKey)
	writeHashUint64(digester, uint64(len(row.Row)))
	writeHash(digester, row.Row)
	var digest chain.Digest
	copy(digest[:], digester.Sum(nil))
	return digest
}

func emptyProjectionTableDigest(table string) chain.Digest {
	digester := sha256.New()
	writeHash(digester, []byte("codecomm/v1/projection-table"))
	writeHash(digester, []byte{0})
	writeHashUint64(digester, uint64(len(table)))
	writeHash(digester, []byte(table))
	writeHashUint64(digester, 0)
	var digest chain.Digest
	copy(digest[:], digester.Sum(nil))
	return digest
}

func writeHash(digester hash.Hash, value []byte) {
	_, _ = digester.Write(value)
}

func writeHashUint64(digester hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeHash(digester, encoded[:])
}
