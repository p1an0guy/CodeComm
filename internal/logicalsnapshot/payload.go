package logicalsnapshot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
)

var (
	ErrInvalidGenesisPayload = errors.New(
		"logicalsnapshot: invalid genesis payload",
	)
	ErrInvalidResultPayload = errors.New(
		"logicalsnapshot: invalid result payload",
	)
	ErrInvalidMutationPayload = errors.New(
		"logicalsnapshot: invalid result mutation chunk payload",
	)
	ErrInvalidEventPayload = errors.New(
		"logicalsnapshot: invalid event payload",
	)
	ErrInvalidProjectionPayload = errors.New(
		"logicalsnapshot: invalid projection payload",
	)
	ErrInvalidCheckpointPayload = errors.New(
		"logicalsnapshot: invalid checkpoint payload",
	)
)

// MaxMutationChunkBytes keeps each base64url-wrapped continuation record
// below MaxRecordPayloadBytes while covering the full V1 mutation ceiling.
const MaxMutationChunkBytes = 2 << 20

// GenesisPayload retains one complete signed genesis record and the
// store-level boundary values not contained by every genesis schema.
type GenesisPayload struct {
	GenesisJSON               []byte
	RecoveryAuthorizationJSON []byte
	BoundaryTransformDigest   chain.Digest
}

// ResultPayload retains one exact result-chain preimage and commitments to its
// following deterministic mutation-chunk sequence.
type ResultPayload struct {
	Result             chain.Result
	MutationBytes      uint64
	MutationChunkCount uint64
	MutationDigest     chain.Digest
}

// MutationChunkPayload carries one deterministic slice of a result's exact
// canonical projection-mutation encoding.
type MutationChunkPayload struct {
	ResultIndex uint64
	ChunkIndex  uint64
	Data        []byte
}

// EventPayload is one accepted event at its committed event-chain position.
type EventPayload struct {
	ChainIndex uint64
	ChainHash  chain.Digest
	Proposal   []byte
}

// ProjectionPayload is one current covered logical row.
type ProjectionPayload struct {
	Row chain.LogicalRow
}

// CheckpointPayload retains the exact authority-signed checkpoint payload and
// the event ID of its accepted consensus.checkpoint command.
type CheckpointPayload struct {
	CheckpointEventID domain.UUIDv7
	SignedPayload     []byte
}

type genesisPayloadWire struct {
	BoundaryTransformDigest string          `json:"boundary_transform_digest"`
	Genesis                 json.RawMessage `json:"genesis"`
	RecoveryAuthorization   json.RawMessage `json:"recovery_authorization"`
}

type resultPayloadWire struct {
	MutationBytes      uint64          `json:"mutation_bytes"`
	MutationChunkCount uint64          `json:"mutation_chunk_count"`
	MutationSHA256     string          `json:"mutation_sha256"`
	Result             json.RawMessage `json:"result"`
}

type mutationChunkPayloadWire struct {
	ChunkIndex  uint64 `json:"chunk_index"`
	Data        string `json:"data"`
	ResultIndex uint64 `json:"result_index"`
}

type eventPayloadWire struct {
	ChainHash  string          `json:"chain_hash"`
	ChainIndex uint64          `json:"chain_index"`
	Proposal   json.RawMessage `json:"proposal"`
}

type projectionPayloadWire struct {
	PrimaryKey json.RawMessage `json:"primary_key"`
	Row        json.RawMessage `json:"row"`
	Table      string          `json:"table"`
}

type checkpointPayloadWire struct {
	CheckpointEventID string          `json:"checkpoint_event_id"`
	Payload           json.RawMessage `json:"payload"`
}

// EncodeGenesisPayload returns the closed canonical genesis payload object.
func EncodeGenesisPayload(payload GenesisPayload) ([]byte, error) {
	genesis, err := requireCanonicalPayloadObject(
		payload.GenesisJSON,
		ErrInvalidGenesisPayload,
		"genesis",
	)
	if err != nil {
		return nil, err
	}
	metadata, err := inspectGenesis(genesis)
	if err != nil {
		return nil, err
	}

	var recovery json.RawMessage = json.RawMessage("null")
	if payload.RecoveryAuthorizationJSON != nil {
		canonical, err := requireCanonicalPayloadObject(
			payload.RecoveryAuthorizationJSON,
			ErrInvalidGenesisPayload,
			"recovery authorization",
		)
		if err != nil {
			return nil, err
		}
		recovery = canonical
	}
	if (metadata.generation == 0) !=
		(payload.RecoveryAuthorizationJSON == nil) {
		return nil, fmt.Errorf(
			"%w: recovery authorization shape disagrees with generation",
			ErrInvalidGenesisPayload,
		)
	}
	if metadata.hasPredecessor &&
		metadata.boundaryTransformDigest != payload.BoundaryTransformDigest {
		return nil, fmt.Errorf(
			"%w: successor transform digest differs",
			ErrInvalidGenesisPayload,
		)
	}

	return encodeSemanticPayload(genesisPayloadWire{
		BoundaryTransformDigest: codec.EncodeBase64URL(
			payload.BoundaryTransformDigest[:],
		),
		Genesis:               genesis,
		RecoveryAuthorization: recovery,
	}, ErrInvalidGenesisPayload)
}

// DecodeGenesisPayload accepts only an exact EncodeGenesisPayload value.
func DecodeGenesisPayload(encoded []byte) (GenesisPayload, error) {
	if err := requireCanonicalSemanticPayload(
		encoded,
		ErrInvalidGenesisPayload,
	); err != nil {
		return GenesisPayload{}, err
	}
	var wire genesisPayloadWire
	if err := decodeSemanticPayload(encoded, &wire); err != nil {
		return GenesisPayload{}, fmt.Errorf(
			"%w: decode: %v",
			ErrInvalidGenesisPayload,
			err,
		)
	}
	if wire.Genesis == nil ||
		wire.RecoveryAuthorization == nil ||
		wire.BoundaryTransformDigest == "" {
		return GenesisPayload{}, fmt.Errorf(
			"%w: missing member",
			ErrInvalidGenesisPayload,
		)
	}
	transform, err := decodeSemanticDigest(
		wire.BoundaryTransformDigest,
		ErrInvalidGenesisPayload,
		"boundary_transform_digest",
	)
	if err != nil {
		return GenesisPayload{}, err
	}
	var recovery []byte
	if !bytes.Equal(wire.RecoveryAuthorization, []byte("null")) {
		recovery, err = requireCanonicalPayloadObject(
			wire.RecoveryAuthorization,
			ErrInvalidGenesisPayload,
			"recovery authorization",
		)
		if err != nil {
			return GenesisPayload{}, err
		}
	}
	payload := GenesisPayload{
		GenesisJSON:               bytes.Clone(wire.Genesis),
		RecoveryAuthorizationJSON: bytes.Clone(recovery),
		BoundaryTransformDigest:   transform,
	}
	reencoded, err := EncodeGenesisPayload(payload)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return GenesisPayload{}, fmt.Errorf(
			"%w: fields do not round trip",
			ErrInvalidGenesisPayload,
		)
	}
	return payload, nil
}

// EncodeResultPayload returns a bounded wrapper around the immutable
// six-field result-chain preimage and its mutation-stream commitments.
func EncodeResultPayload(payload ResultPayload) ([]byte, error) {
	if _, err := requireCanonicalProposal(
		payload.Result.Proposal,
		ErrInvalidResultPayload,
	); err != nil {
		return nil, err
	}
	result, err := chain.EncodeResult(payload.Result)
	if err != nil {
		return nil, fmt.Errorf("%w: result: %v", ErrInvalidResultPayload, err)
	}
	expectedChunks, valid := mutationChunkCount(payload.MutationBytes)
	if !valid || payload.MutationChunkCount != expectedChunks {
		return nil, fmt.Errorf(
			"%w: invalid mutation stream bounds",
			ErrInvalidResultPayload,
		)
	}
	return encodeSemanticPayload(resultPayloadWire{
		MutationBytes:      payload.MutationBytes,
		MutationChunkCount: payload.MutationChunkCount,
		MutationSHA256: codec.EncodeBase64URL(
			payload.MutationDigest[:],
		),
		Result: result,
	}, ErrInvalidResultPayload)
}

// DecodeResultPayload accepts only an exact EncodeResultPayload value.
func DecodeResultPayload(encoded []byte) (ResultPayload, error) {
	if err := requireCanonicalSemanticPayload(
		encoded,
		ErrInvalidResultPayload,
	); err != nil {
		return ResultPayload{}, err
	}
	var wire resultPayloadWire
	if err := decodeSemanticPayload(encoded, &wire); err != nil {
		return ResultPayload{}, fmt.Errorf(
			"%w: decode: %v",
			ErrInvalidResultPayload,
			err,
		)
	}
	if wire.Result == nil || wire.MutationSHA256 == "" {
		return ResultPayload{}, fmt.Errorf(
			"%w: missing member",
			ErrInvalidResultPayload,
		)
	}
	result, err := chain.DecodeResult(wire.Result)
	if err != nil {
		return ResultPayload{}, fmt.Errorf(
			"%w: result: %v",
			ErrInvalidResultPayload,
			err,
		)
	}
	digest, err := decodeSemanticDigest(
		wire.MutationSHA256,
		ErrInvalidResultPayload,
		"mutation_sha256",
	)
	if err != nil {
		return ResultPayload{}, err
	}
	payload := ResultPayload{
		Result:             cloneResult(result),
		MutationBytes:      wire.MutationBytes,
		MutationChunkCount: wire.MutationChunkCount,
		MutationDigest:     digest,
	}
	reencoded, err := EncodeResultPayload(payload)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return ResultPayload{}, fmt.Errorf(
			"%w: fields do not round trip",
			ErrInvalidResultPayload,
		)
	}
	return payload, nil
}

// EncodeMutationChunkPayload returns one canonical bounded mutation
// continuation payload.
func EncodeMutationChunkPayload(
	payload MutationChunkPayload,
) ([]byte, error) {
	if payload.ResultIndex < 1 ||
		!domain.ValidUnsignedInteger(payload.ResultIndex) ||
		!domain.ValidUnsignedInteger(payload.ChunkIndex) ||
		len(payload.Data) < 1 ||
		len(payload.Data) > MaxMutationChunkBytes {
		return nil, ErrInvalidMutationPayload
	}
	return encodeSemanticPayload(mutationChunkPayloadWire{
		ChunkIndex:  payload.ChunkIndex,
		Data:        codec.EncodeBase64URL(payload.Data),
		ResultIndex: payload.ResultIndex,
	}, ErrInvalidMutationPayload)
}

// DecodeMutationChunkPayload accepts only an exact
// EncodeMutationChunkPayload value.
func DecodeMutationChunkPayload(
	encoded []byte,
) (MutationChunkPayload, error) {
	if err := requireCanonicalSemanticPayload(
		encoded,
		ErrInvalidMutationPayload,
	); err != nil {
		return MutationChunkPayload{}, err
	}
	var wire mutationChunkPayloadWire
	if err := decodeSemanticPayload(encoded, &wire); err != nil {
		return MutationChunkPayload{}, fmt.Errorf(
			"%w: decode: %v",
			ErrInvalidMutationPayload,
			err,
		)
	}
	data, err := codec.DecodeBase64URL(wire.Data)
	if err != nil {
		return MutationChunkPayload{}, fmt.Errorf(
			"%w: data: %v",
			ErrInvalidMutationPayload,
			err,
		)
	}
	payload := MutationChunkPayload{
		ResultIndex: wire.ResultIndex,
		ChunkIndex:  wire.ChunkIndex,
		Data:        data,
	}
	reencoded, err := EncodeMutationChunkPayload(payload)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return MutationChunkPayload{}, fmt.Errorf(
			"%w: fields do not round trip",
			ErrInvalidMutationPayload,
		)
	}
	return payload, nil
}

// NewResultPayload encodes and commits one exact mutation set for a result.
func NewResultPayload(
	result chain.Result,
	mutations []chain.Mutation,
) (ResultPayload, []byte, error) {
	if _, err := requireCanonicalProposal(
		result.Proposal,
		ErrInvalidResultPayload,
	); err != nil {
		return ResultPayload{}, nil, err
	}
	if _, err := chain.EncodeResult(result); err != nil {
		return ResultPayload{}, nil, fmt.Errorf(
			"%w: result: %v",
			ErrInvalidResultPayload,
			err,
		)
	}
	encoded, err := chain.EncodeMutations(mutations)
	if err != nil {
		return ResultPayload{}, nil, fmt.Errorf(
			"%w: projection mutations: %v",
			ErrInvalidResultPayload,
			err,
		)
	}
	chunks, valid := mutationChunkCount(uint64(len(encoded)))
	if !valid {
		return ResultPayload{}, nil, ErrInvalidResultPayload
	}
	return ResultPayload{
		Result:             cloneResult(result),
		MutationBytes:      uint64(len(encoded)),
		MutationChunkCount: chunks,
		MutationDigest:     sha256.Sum256(encoded),
	}, encoded, nil
}

func mutationChunkCount(encodedBytes uint64) (uint64, bool) {
	if encodedBytes < 2 ||
		encodedBytes > chain.MaxEncodedMutationBytes {
		return 0, false
	}
	return (encodedBytes + MaxMutationChunkBytes - 1) /
		MaxMutationChunkBytes, true
}

// EncodeEventPayload returns the closed canonical accepted-event payload.
func EncodeEventPayload(payload EventPayload) ([]byte, error) {
	if payload.ChainIndex < 1 ||
		!domain.ValidUnsignedInteger(payload.ChainIndex) {
		return nil, fmt.Errorf(
			"%w: invalid chain index",
			ErrInvalidEventPayload,
		)
	}
	proposal, err := requireCanonicalProposal(
		payload.Proposal,
		ErrInvalidEventPayload,
	)
	if err != nil {
		return nil, err
	}
	return encodeSemanticPayload(eventPayloadWire{
		ChainHash:  codec.EncodeBase64URL(payload.ChainHash[:]),
		ChainIndex: payload.ChainIndex,
		Proposal:   proposal,
	}, ErrInvalidEventPayload)
}

// DecodeEventPayload accepts only an exact EncodeEventPayload value.
func DecodeEventPayload(encoded []byte) (EventPayload, error) {
	if err := requireCanonicalSemanticPayload(
		encoded,
		ErrInvalidEventPayload,
	); err != nil {
		return EventPayload{}, err
	}
	var wire eventPayloadWire
	if err := decodeSemanticPayload(encoded, &wire); err != nil {
		return EventPayload{}, fmt.Errorf(
			"%w: decode: %v",
			ErrInvalidEventPayload,
			err,
		)
	}
	if wire.Proposal == nil || wire.ChainHash == "" {
		return EventPayload{}, fmt.Errorf(
			"%w: missing member",
			ErrInvalidEventPayload,
		)
	}
	digest, err := decodeSemanticDigest(
		wire.ChainHash,
		ErrInvalidEventPayload,
		"chain_hash",
	)
	if err != nil {
		return EventPayload{}, err
	}
	payload := EventPayload{
		ChainIndex: wire.ChainIndex,
		ChainHash:  digest,
		Proposal:   bytes.Clone(wire.Proposal),
	}
	reencoded, err := EncodeEventPayload(payload)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return EventPayload{}, fmt.Errorf(
			"%w: fields do not round trip",
			ErrInvalidEventPayload,
		)
	}
	return payload, nil
}

// EncodeProjectionPayload returns one closed canonical logical-row payload.
func EncodeProjectionPayload(payload ProjectionPayload) ([]byte, error) {
	row := cloneLogicalRow(payload.Row)
	if err := validateLogicalRowPayload(row); err != nil {
		return nil, err
	}
	return encodeSemanticPayload(projectionPayloadWire{
		PrimaryKey: row.PrimaryKey,
		Row:        row.Row,
		Table:      row.Table,
	}, ErrInvalidProjectionPayload)
}

// DecodeProjectionPayload accepts only an exact EncodeProjectionPayload value.
func DecodeProjectionPayload(encoded []byte) (ProjectionPayload, error) {
	if err := requireCanonicalSemanticPayload(
		encoded,
		ErrInvalidProjectionPayload,
	); err != nil {
		return ProjectionPayload{}, err
	}
	var wire projectionPayloadWire
	if err := decodeSemanticPayload(encoded, &wire); err != nil {
		return ProjectionPayload{}, fmt.Errorf(
			"%w: decode: %v",
			ErrInvalidProjectionPayload,
			err,
		)
	}
	if wire.Table == "" || wire.PrimaryKey == nil || wire.Row == nil {
		return ProjectionPayload{}, fmt.Errorf(
			"%w: missing member",
			ErrInvalidProjectionPayload,
		)
	}
	payload := ProjectionPayload{Row: chain.LogicalRow{
		Table:      wire.Table,
		PrimaryKey: bytes.Clone(wire.PrimaryKey),
		Row:        bytes.Clone(wire.Row),
	}}
	reencoded, err := EncodeProjectionPayload(payload)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return ProjectionPayload{}, fmt.Errorf(
			"%w: fields do not round trip",
			ErrInvalidProjectionPayload,
		)
	}
	return payload, nil
}

// EncodeCheckpointPayload returns the closed canonical terminal checkpoint
// payload. SignedPayload is the exact consensus.checkpoint event payload.
func EncodeCheckpointPayload(payload CheckpointPayload) ([]byte, error) {
	if !payload.CheckpointEventID.Valid() {
		return nil, fmt.Errorf(
			"%w: invalid checkpoint event ID",
			ErrInvalidCheckpointPayload,
		)
	}
	signed, err := requireCanonicalCheckpointPayload(payload.SignedPayload)
	if err != nil {
		return nil, err
	}
	return encodeSemanticPayload(checkpointPayloadWire{
		CheckpointEventID: string(payload.CheckpointEventID),
		Payload:           signed,
	}, ErrInvalidCheckpointPayload)
}

// DecodeCheckpointPayload accepts only an exact EncodeCheckpointPayload
// value.
func DecodeCheckpointPayload(encoded []byte) (CheckpointPayload, error) {
	if err := requireCanonicalSemanticPayload(
		encoded,
		ErrInvalidCheckpointPayload,
	); err != nil {
		return CheckpointPayload{}, err
	}
	var wire checkpointPayloadWire
	if err := decodeSemanticPayload(encoded, &wire); err != nil {
		return CheckpointPayload{}, fmt.Errorf(
			"%w: decode: %v",
			ErrInvalidCheckpointPayload,
			err,
		)
	}
	payload := CheckpointPayload{
		CheckpointEventID: domain.UUIDv7(wire.CheckpointEventID),
		SignedPayload:     bytes.Clone(wire.Payload),
	}
	reencoded, err := EncodeCheckpointPayload(payload)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return CheckpointPayload{}, fmt.Errorf(
			"%w: fields do not round trip",
			ErrInvalidCheckpointPayload,
		)
	}
	return payload, nil
}

func requireCanonicalSemanticPayload(encoded []byte, sentinel error) error {
	if len(encoded) == 0 {
		return sentinel
	}
	if len(encoded) > MaxRecordPayloadBytes {
		return fmt.Errorf("%w: %w", sentinel, ErrRecordTooLarge)
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil ||
		!bytes.Equal(canonical, encoded) ||
		encoded[0] != '{' ||
		encoded[len(encoded)-1] != '}' {
		return fmt.Errorf("%w: noncanonical object", sentinel)
	}
	return nil
}

func encodeSemanticPayload(value any, sentinel error) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", sentinel, err)
	}
	if len(raw) > MaxRecordPayloadBytes {
		return nil, fmt.Errorf("%w: %w", sentinel, ErrRecordTooLarge)
	}
	canonical, err := codec.Canonicalize(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %v", sentinel, err)
	}
	if len(canonical) > MaxRecordPayloadBytes {
		return nil, fmt.Errorf("%w: %w", sentinel, ErrRecordTooLarge)
	}
	return canonical, nil
}

func decodeSemanticPayload(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireCanonicalPayloadObject(
	encoded []byte,
	sentinel error,
	name string,
) ([]byte, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("%w: missing %s", sentinel, name)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, fmt.Errorf("%w: noncanonical %s", sentinel, name)
	}
	return canonical, nil
}

func requireCanonicalProposal(
	encoded []byte,
	sentinel error,
) ([]byte, error) {
	if _, err := event.InspectUnverifiedProposal(encoded); err != nil {
		return nil, fmt.Errorf("%w: proposal: %v", sentinel, err)
	}
	return bytes.Clone(encoded), nil
}

func requireCanonicalCheckpointPayload(encoded []byte) ([]byte, error) {
	if _, _, err := event.DecodeCheckpointPayload(encoded); err != nil {
		return nil, fmt.Errorf(
			"%w: signed payload: %v",
			ErrInvalidCheckpointPayload,
			err,
		)
	}
	return bytes.Clone(encoded), nil
}

func decodeSemanticDigest(
	encoded string,
	sentinel error,
	name string,
) (chain.Digest, error) {
	raw, err := codec.DecodeBase64URLExact(encoded, len(chain.Digest{}))
	if err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: %s: %v",
			sentinel,
			name,
			err,
		)
	}
	var digest chain.Digest
	copy(digest[:], raw)
	return digest, nil
}

func validateLogicalRowPayload(row chain.LogicalRow) error {
	if _, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		[]chain.LogicalRow{row},
	); err != nil {
		return fmt.Errorf(
			"%w: logical row: %v",
			ErrInvalidProjectionPayload,
			err,
		)
	}
	return nil
}

func cloneResult(value chain.Result) chain.Result {
	result := value
	result.Proposal = bytes.Clone(value.Proposal)
	result.Outcome = bytes.Clone(value.Outcome)
	if value.ChainIndex != nil {
		index := *value.ChainIndex
		result.ChainIndex = &index
	}
	if value.ChainHash != nil {
		digest := *value.ChainHash
		result.ChainHash = &digest
	}
	return result
}

func cloneLogicalRow(value chain.LogicalRow) chain.LogicalRow {
	return chain.LogicalRow{
		Table:      value.Table,
		PrimaryKey: bytes.Clone(value.PrimaryKey),
		Row:        bytes.Clone(value.Row),
	}
}

type genesisMetadata struct {
	sessionID                domain.UUIDv7
	workspaceID              domain.UUIDv4
	generation               uint64
	genesisDigest            chain.Digest
	predecessorGenesisDigest chain.Digest
	predecessorChainIndex    uint64
	predecessorChainHash     chain.Digest
	predecessorResultIndex   uint64
	predecessorResultHash    chain.Digest
	predecessorAccumulator   chain.Digest
	boundaryTransformDigest  chain.Digest
	digestVersion            uint64
	projectionSchemaVersion  uint64
	hasPredecessor           bool
}

func inspectGenesis(encoded []byte) (genesisMetadata, error) {
	canonical, err := requireCanonicalPayloadObject(
		encoded,
		ErrInvalidGenesisPayload,
		"genesis",
	)
	if err != nil {
		return genesisMetadata{}, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil {
		return genesisMetadata{}, fmt.Errorf(
			"%w: decode genesis",
			ErrInvalidGenesisPayload,
		)
	}
	session, err := requiredGenesisString(members, "session_id")
	if err != nil {
		return genesisMetadata{}, err
	}
	workspace, err := requiredGenesisString(members, "workspace_id")
	if err != nil {
		return genesisMetadata{}, err
	}
	generation, err := requiredGenesisUint(
		members,
		"recovery_generation",
	)
	if err != nil {
		return genesisMetadata{}, err
	}
	metadata := genesisMetadata{
		sessionID:   domain.UUIDv7(session),
		workspaceID: domain.UUIDv4(workspace),
		generation:  generation,
	}
	if !metadata.sessionID.Valid() || !metadata.workspaceID.Valid() {
		return genesisMetadata{}, fmt.Errorf(
			"%w: invalid genesis identity",
			ErrInvalidGenesisPayload,
		)
	}
	metadata.genesisDigest, err = chain.GenesisDigest(canonical)
	if err != nil {
		return genesisMetadata{}, fmt.Errorf(
			"%w: digest genesis: %v",
			ErrInvalidGenesisPayload,
			err,
		)
	}
	if generation == 0 {
		return metadata, nil
	}

	metadata.hasPredecessor = true
	if metadata.predecessorGenesisDigest, err = requiredGenesisDigest(
		members,
		"predecessor_genesis_digest",
	); err != nil {
		return genesisMetadata{}, err
	}
	if metadata.predecessorChainIndex, err = requiredGenesisUint(
		members,
		"predecessor_chain_index",
	); err != nil {
		return genesisMetadata{}, err
	}
	if metadata.predecessorChainHash, err = requiredGenesisDigest(
		members,
		"predecessor_chain_hash",
	); err != nil {
		return genesisMetadata{}, err
	}
	if metadata.predecessorResultIndex, err = requiredGenesisUint(
		members,
		"predecessor_result_index",
	); err != nil {
		return genesisMetadata{}, err
	}
	if metadata.predecessorResultHash, err = requiredGenesisDigest(
		members,
		"predecessor_result_hash",
	); err != nil {
		return genesisMetadata{}, err
	}
	if metadata.predecessorAccumulator, err = requiredGenesisDigest(
		members,
		"predecessor_projection_accumulator",
	); err != nil {
		return genesisMetadata{}, err
	}
	if metadata.boundaryTransformDigest, err = requiredGenesisDigest(
		members,
		"post_transform_state_digest",
	); err != nil {
		return genesisMetadata{}, err
	}
	if metadata.digestVersion, err = requiredPositiveGenesisUint(
		members,
		"digest_version",
	); err != nil {
		return genesisMetadata{}, err
	}
	if metadata.projectionSchemaVersion, err = requiredPositiveGenesisUint(
		members,
		"projection_schema_version",
	); err != nil {
		return genesisMetadata{}, err
	}
	if metadata.predecessorChainIndex > metadata.predecessorResultIndex {
		return genesisMetadata{}, fmt.Errorf(
			"%w: predecessor chain index exceeds result index",
			ErrInvalidGenesisPayload,
		)
	}
	return metadata, nil
}

func requiredGenesisString(
	members map[string]json.RawMessage,
	name string,
) (string, error) {
	raw, exists := members[name]
	var value string
	if !exists || json.Unmarshal(raw, &value) != nil || value == "" {
		return "", fmt.Errorf(
			"%w: genesis %s",
			ErrInvalidGenesisPayload,
			name,
		)
	}
	return value, nil
}

func requiredGenesisUint(
	members map[string]json.RawMessage,
	name string,
) (uint64, error) {
	raw, exists := members[name]
	var value uint64
	if !exists ||
		json.Unmarshal(raw, &value) != nil ||
		!domain.ValidUnsignedInteger(value) {
		return 0, fmt.Errorf(
			"%w: genesis %s",
			ErrInvalidGenesisPayload,
			name,
		)
	}
	return value, nil
}

func requiredPositiveGenesisUint(
	members map[string]json.RawMessage,
	name string,
) (uint64, error) {
	value, err := requiredGenesisUint(members, name)
	if err != nil {
		return 0, err
	}
	if value == 0 {
		return 0, fmt.Errorf(
			"%w: genesis %s is zero",
			ErrInvalidGenesisPayload,
			name,
		)
	}
	return value, nil
}

func requiredGenesisDigest(
	members map[string]json.RawMessage,
	name string,
) (chain.Digest, error) {
	raw, exists := members[name]
	var value string
	if !exists || json.Unmarshal(raw, &value) != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: genesis %s",
			ErrInvalidGenesisPayload,
			name,
		)
	}
	return decodeSemanticDigest(value, ErrInvalidGenesisPayload, name)
}

func decodeSignedCheckpoint(
	payload CheckpointPayload,
) (domain.Checkpoint, [ed25519.SignatureSize]byte, error) {
	checkpoint, signature, err := event.DecodeCheckpointPayload(
		payload.SignedPayload,
	)
	if err != nil {
		return domain.Checkpoint{}, signature, fmt.Errorf(
			"%w: signed payload: %v",
			ErrInvalidCheckpointPayload,
			err,
		)
	}
	return checkpoint, signature, nil
}
