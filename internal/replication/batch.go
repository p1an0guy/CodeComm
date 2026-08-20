// Package replication implements CodeComm's signed result-batch protocol.
package replication

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const (
	MaxBatchResults         = 256
	MaxBatchCompressedBytes = 4 << 20
	MaxBatchExpandedBytes   = 64 << 20
	MaxBatchResultsBytes    = MaxBatchExpandedBytes - (4 << 10)
	batchSignatureTextBytes = 86
)

var (
	ErrInvalidBatch      = errors.New("replication: invalid result batch")
	ErrBatchTooLarge     = errors.New("replication: result batch exceeds size limit")
	ErrNoncanonicalBatch = errors.New("replication: result batch is not canonical")
	ErrSignerMismatch    = errors.New("replication: signer key does not match server device")
	ErrSignatureInvalid  = errors.New("replication: result batch signature is invalid")
)

// BatchInput is the complete tuple covered by a result-batch signature.
// Results contains exact canonical command-result objects.
type BatchInput struct {
	FromResultIndex            uint64
	ToResultIndex              uint64
	StartResultHash            chain.Digest
	EndResultHash              chain.Digest
	StartChainIndex            uint64
	StartChainHash             chain.Digest
	EndChainIndex              uint64
	EndChainHash               chain.Digest
	StartProjectionAccumulator chain.Digest
	EndProjectionAccumulator   chain.Digest
	StartProjectionStateDigest chain.Digest
	EndProjectionStateDigest   chain.Digest
	Results                    [][]byte
	SessionID                  domain.UUIDv7
	WorkspaceID                domain.UUIDv4
	RecoveryGeneration         uint64
	ServerDeviceID             domain.DeviceID
	ServerAppliedResultIndex   uint64
	ServerAuthorityVersion     uint64
}

// BatchMetadata is the signed envelope without the potentially large result
// array.
type BatchMetadata struct {
	FromResultIndex            uint64
	ToResultIndex              uint64
	StartResultHash            chain.Digest
	EndResultHash              chain.Digest
	StartChainIndex            uint64
	StartChainHash             chain.Digest
	EndChainIndex              uint64
	EndChainHash               chain.Digest
	StartProjectionAccumulator chain.Digest
	EndProjectionAccumulator   chain.Digest
	StartProjectionStateDigest chain.Digest
	EndProjectionStateDigest   chain.Digest
	SessionID                  domain.UUIDv7
	WorkspaceID                domain.UUIDv4
	RecoveryGeneration         uint64
	ServerDeviceID             domain.DeviceID
	ServerAppliedResultIndex   uint64
	ServerAuthorityVersion     uint64
}

// UnsignedBatch is an immutable, validated batch signature preimage.
type UnsignedBatch struct {
	input       BatchInput
	canonical   []byte
	resultSpans []resultSpan
	valid       bool
}

// Batch is an immutable identity-signed result batch.
type Batch struct {
	unsigned  UnsignedBatch
	signature [ed25519.SignatureSize]byte
	valid     bool
}

type resultSpan struct {
	start int
	end   int
}

type batchWire struct {
	BatchSignature             string            `json:"batch_signature"`
	EndChainHash               string            `json:"end_chain_hash"`
	EndChainIndex              uint64            `json:"end_chain_index"`
	EndProjectionAccumulator   string            `json:"end_projection_accumulator"`
	EndProjectionStateDigest   string            `json:"end_projection_state_digest"`
	EndResultHash              string            `json:"end_result_hash"`
	FromResultIndex            uint64            `json:"from_result_index"`
	RecoveryGeneration         uint64            `json:"recovery_generation"`
	Results                    []json.RawMessage `json:"results"`
	ServerAppliedResultIndex   uint64            `json:"server_applied_result_index"`
	ServerAuthorityVersion     uint64            `json:"server_authority_version"`
	ServerDeviceID             string            `json:"server_device_id"`
	SessionID                  string            `json:"session_id"`
	StartChainHash             string            `json:"start_chain_hash"`
	StartChainIndex            uint64            `json:"start_chain_index"`
	StartProjectionAccumulator string            `json:"start_projection_accumulator"`
	StartProjectionStateDigest string            `json:"start_projection_state_digest"`
	StartResultHash            string            `json:"start_result_hash"`
	ToResultIndex              uint64            `json:"to_result_index"`
	WorkspaceID                string            `json:"workspace_id"`
}

// NewUnsignedBatch validates and copies the complete signed tuple.
func NewUnsignedBatch(input BatchInput) (UnsignedBatch, error) {
	if err := validateBatchShape(input); err != nil {
		return UnsignedBatch{}, err
	}
	if err := validateBatchEncodedSize(input); err != nil {
		return UnsignedBatch{}, err
	}
	if err := validateBatchLinks(input); err != nil {
		return UnsignedBatch{}, err
	}
	canonical, spans := encodeUnsignedBatch(input)
	input.Results = nil
	return UnsignedBatch{
		input:       input,
		canonical:   canonical,
		resultSpans: spans,
		valid:       true,
	}, nil
}

// NewBatch attaches a fixed-size signature to a validated batch preimage.
func NewBatch(
	unsigned UnsignedBatch,
	signature [ed25519.SignatureSize]byte,
) (Batch, error) {
	if err := unsigned.validate(); err != nil {
		return Batch{}, err
	}
	if completeBatchSize(len(unsigned.canonical)) > MaxBatchExpandedBytes {
		return Batch{}, ErrBatchTooLarge
	}
	return Batch{
		unsigned:  unsigned,
		signature: signature,
		valid:     true,
	}, nil
}

// SignBatch signs a validated batch with its named server identity.
func SignBatch(unsigned UnsignedBatch, privateKey []byte) (Batch, error) {
	if err := unsigned.validate(); err != nil {
		return Batch{}, err
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return Batch{}, fmt.Errorf("%w: %v", ErrSignerMismatch, err)
	}
	derived, err := device.DeriveID(ed25519.PublicKey(publicKey))
	if err != nil || derived != unsigned.input.ServerDeviceID {
		return Batch{}, ErrSignerMismatch
	}
	signatureBytes, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureBatch,
		unsigned.canonical,
	)
	if err != nil {
		return Batch{}, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	defer clear(signatureBytes)
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	return NewBatch(unsigned, signature)
}

// ParseBatch accepts only the exact canonical closed V1 batch object.
// Signature authorization is intentionally deferred to VerifyBatch and
// scratch replay of the authority handoff chain.
func ParseBatch(encoded []byte) (Batch, error) {
	if len(encoded) == 0 {
		return Batch{}, ErrInvalidBatch
	}
	if len(encoded) > MaxBatchExpandedBytes {
		return Batch{}, fmt.Errorf(
			"%w: got %d bytes, limit %d",
			ErrBatchTooLarge,
			len(encoded),
			MaxBatchExpandedBytes,
		)
	}
	wire, err := decodeBatchWire(encoded)
	if err != nil {
		return Batch{}, err
	}

	input, err := inputFromWire(wire)
	if err != nil {
		return Batch{}, err
	}
	unsigned, err := NewUnsignedBatch(input)
	if err != nil {
		return Batch{}, err
	}
	signatureBytes, err := codec.DecodeBase64URLExact(
		wire.BatchSignature,
		ed25519.SignatureSize,
	)
	if err != nil {
		return Batch{}, fmt.Errorf(
			"%w: batch signature: %v",
			ErrInvalidBatch,
			err,
		)
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	batch, err := NewBatch(unsigned, signature)
	if err != nil {
		return Batch{}, err
	}
	if !matchesCompleteBatch(encoded, unsigned.canonical, signature) {
		return Batch{}, ErrNoncanonicalBatch
	}
	return batch, nil
}

// VerifyBatch verifies the named server's identity signature. Whether that
// identity belongs to the authority at the batch end is established by
// scratch replay, not by this cryptographic check alone.
func VerifyBatch(batch Batch, publicKey []byte) error {
	if err := batch.validate(); err != nil {
		return err
	}
	derived, err := device.DeriveID(ed25519.PublicKey(publicKey))
	if err != nil || derived != batch.unsigned.input.ServerDeviceID {
		return ErrSignerMismatch
	}
	if err := codecommcrypto.VerifyEd25519(
		publicKey,
		codec.SignatureBatch,
		batch.unsigned.canonical,
		batch.signature[:],
	); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

// Input returns an independent copy of every signed field.
func (batch UnsignedBatch) Input() BatchInput {
	result := batch.input
	result.Results = make([][]byte, len(batch.resultSpans))
	for index, span := range batch.resultSpans {
		result.Results[index] = bytes.Clone(
			batch.canonical[span.start:span.end],
		)
	}
	return result
}

// Metadata returns the signed envelope without copying results.
func (batch UnsignedBatch) Metadata() BatchMetadata {
	if !batch.valid {
		return BatchMetadata{}
	}
	return BatchMetadata{
		FromResultIndex:            batch.input.FromResultIndex,
		ToResultIndex:              batch.input.ToResultIndex,
		StartResultHash:            batch.input.StartResultHash,
		EndResultHash:              batch.input.EndResultHash,
		StartChainIndex:            batch.input.StartChainIndex,
		StartChainHash:             batch.input.StartChainHash,
		EndChainIndex:              batch.input.EndChainIndex,
		EndChainHash:               batch.input.EndChainHash,
		StartProjectionAccumulator: batch.input.StartProjectionAccumulator,
		EndProjectionAccumulator:   batch.input.EndProjectionAccumulator,
		StartProjectionStateDigest: batch.input.StartProjectionStateDigest,
		EndProjectionStateDigest:   batch.input.EndProjectionStateDigest,
		SessionID:                  batch.input.SessionID,
		WorkspaceID:                batch.input.WorkspaceID,
		RecoveryGeneration:         batch.input.RecoveryGeneration,
		ServerDeviceID:             batch.input.ServerDeviceID,
		ServerAppliedResultIndex:   batch.input.ServerAppliedResultIndex,
		ServerAuthorityVersion:     batch.input.ServerAuthorityVersion,
	}
}

// CanonicalBytes returns an independent copy of the signature preimage.
func (batch UnsignedBatch) CanonicalBytes() []byte {
	return bytes.Clone(batch.canonical)
}

// Unsigned returns an independent copy of the batch signature preimage.
func (batch Batch) Unsigned() UnsignedBatch {
	return batch.unsigned
}

// CanonicalBytes returns an independent copy of the complete signed batch.
func (batch Batch) CanonicalBytes() []byte {
	if !batch.valid {
		return nil
	}
	return encodeCompleteBatch(batch.unsigned.canonical, batch.signature)
}

// EncodedLen returns the complete canonical batch size without encoding it.
func (batch Batch) EncodedLen() int {
	if err := batch.validate(); err != nil {
		return 0
	}
	return completeBatchSize(len(batch.unsigned.canonical))
}

// WriteCanonical streams the complete canonical batch without allocating a
// second result-sized buffer.
func (batch Batch) WriteCanonical(writer io.Writer) error {
	if writer == nil {
		return ErrInvalidBatch
	}
	if err := batch.validate(); err != nil {
		return err
	}
	if err := writeAll(
		writer,
		completeBatchPrefix(batch.signature),
	); err != nil {
		return err
	}
	return writeAll(writer, batch.unsigned.canonical[1:])
}

// MatchesUnsigned reports whether the signed batch contains the exact
// validated preimage without copying it.
func (batch Batch) MatchesUnsigned(unsigned UnsignedBatch) bool {
	return batch.validate() == nil &&
		unsigned.validate() == nil &&
		bytes.Equal(batch.unsigned.canonical, unsigned.canonical)
}

// Signature returns the complete identity signature by value.
func (batch Batch) Signature() [ed25519.SignatureSize]byte {
	return batch.signature
}

// AttestationID deterministically identifies the complete signed batch.
func (batch Batch) AttestationID() string {
	if err := batch.validate(); err != nil {
		return ""
	}
	digest := sha256.Sum256(batch.CanonicalBytes())
	return "batch:" + codec.EncodeBase64URL(digest[:])
}

// AttestationEnvelope returns the canonical signed metadata retained beside
// immutable command results. Recombining it with those results reproduces the
// exact signature preimage.
func (batch Batch) AttestationEnvelope() []byte {
	if err := batch.validate(); err != nil {
		return nil
	}
	return encodeAttestationEnvelope(batch.unsigned.input)
}

func (batch UnsignedBatch) validate() error {
	if !batch.valid ||
		len(batch.canonical) == 0 ||
		len(batch.resultSpans) == 0 {
		return fmt.Errorf("%w: invalid unsigned value", ErrInvalidBatch)
	}
	return nil
}

func (batch Batch) validate() error {
	if !batch.valid {
		return fmt.Errorf("%w: invalid complete value", ErrInvalidBatch)
	}
	if err := batch.unsigned.validate(); err != nil {
		return err
	}
	return nil
}

func validateBatchShape(input BatchInput) error {
	resultCount := len(input.Results)
	if !input.SessionID.Valid() ||
		!input.WorkspaceID.Valid() ||
		!input.ServerDeviceID.Valid() ||
		!domain.ValidUnsignedInteger(input.RecoveryGeneration) ||
		input.FromResultIndex < 1 ||
		!domain.ValidUnsignedInteger(input.FromResultIndex) ||
		input.ToResultIndex < input.FromResultIndex ||
		!domain.ValidUnsignedInteger(input.ToResultIndex) ||
		input.StartChainIndex > input.EndChainIndex ||
		!domain.ValidUnsignedInteger(input.StartChainIndex) ||
		!domain.ValidUnsignedInteger(input.EndChainIndex) ||
		input.ServerAppliedResultIndex < input.ToResultIndex ||
		!domain.ValidUnsignedInteger(input.ServerAppliedResultIndex) ||
		input.ServerAuthorityVersion < 1 ||
		!domain.ValidUnsignedInteger(input.ServerAuthorityVersion) ||
		resultCount < 1 ||
		resultCount > MaxBatchResults ||
		input.ToResultIndex-input.FromResultIndex+1 != uint64(resultCount) ||
		input.StartChainIndex >= input.FromResultIndex ||
		input.EndChainIndex > input.ToResultIndex {
		return ErrInvalidBatch
	}
	return nil
}

func validateBatchEncodedSize(input BatchInput) error {
	metadata := input
	metadata.Results = nil
	metadataBytes, _ := encodeUnsignedBatch(metadata)
	unsignedBytes := len(metadataBytes)
	for index, result := range input.Results {
		added := len(result)
		if index != 0 {
			added++
		}
		if added > MaxBatchExpandedBytes-unsignedBytes {
			return fmt.Errorf(
				"%w: complete batch exceeds %d bytes",
				ErrBatchTooLarge,
				MaxBatchExpandedBytes,
			)
		}
		unsignedBytes += added
	}
	if completeBatchSize(unsignedBytes) > MaxBatchExpandedBytes {
		return fmt.Errorf(
			"%w: complete batch exceeds %d bytes",
			ErrBatchTooLarge,
			MaxBatchExpandedBytes,
		)
	}
	return nil
}

func validateBatchLinks(input BatchInput) error {
	resultHead := input.StartResultHash
	chainIndex := input.StartChainIndex
	chainHead := input.StartChainHash
	for index, encoded := range input.Results {
		result, err := chain.DecodeResult(encoded)
		if err != nil {
			return fmt.Errorf(
				"%w: result %d: %v",
				ErrInvalidBatch,
				index,
				err,
			)
		}
		expectedResultIndex := input.FromResultIndex + uint64(index)
		if result.ResultIndex != expectedResultIndex {
			return fmt.Errorf(
				"%w: result %d has index %d, want %d",
				ErrInvalidBatch,
				index,
				result.ResultIndex,
				expectedResultIndex,
			)
		}
		nextResult, canonical, err := chain.AppendResult(resultHead, result)
		if err != nil || !bytes.Equal(canonical, encoded) {
			return fmt.Errorf(
				"%w: result %d does not round trip",
				ErrInvalidBatch,
				index,
			)
		}
		if result.ChainIndex != nil {
			if chainIndex == domain.MaxSafeInteger ||
				*result.ChainIndex != chainIndex+1 {
				return fmt.Errorf(
					"%w: result %d event position is not contiguous",
					ErrInvalidBatch,
					index,
				)
			}
			nextChain, err := chain.AppendEvent(chainHead, result.Proposal)
			if err != nil ||
				result.ChainHash == nil ||
				nextChain != *result.ChainHash {
				return fmt.Errorf(
					"%w: result %d event link differs",
					ErrInvalidBatch,
					index,
				)
			}
			chainIndex++
			chainHead = nextChain
		}
		resultHead = nextResult
	}
	if resultHead != input.EndResultHash ||
		chainIndex != input.EndChainIndex ||
		chainHead != input.EndChainHash {
		return fmt.Errorf("%w: ending heads differ", ErrInvalidBatch)
	}
	return nil
}

func decodeBatchWire(encoded []byte) (batchWire, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil {
		return batchWire{}, fmt.Errorf("%w: decode: %v", ErrInvalidBatch, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return batchWire{}, fmt.Errorf(
			"%w: batch must be an object",
			ErrInvalidBatch,
		)
	}

	var wire batchWire
	seen := make(map[string]struct{}, 20)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return batchWire{}, fmt.Errorf(
				"%w: decode field name: %v",
				ErrInvalidBatch,
				err,
			)
		}
		name, ok := token.(string)
		if !ok {
			return batchWire{}, fmt.Errorf(
				"%w: field name is not a string",
				ErrInvalidBatch,
			)
		}
		if _, duplicate := seen[name]; duplicate {
			return batchWire{}, fmt.Errorf(
				"%w: duplicate field %q",
				ErrInvalidBatch,
				name,
			)
		}
		seen[name] = struct{}{}

		switch name {
		case "batch_signature":
			err = decodeBatchField(decoder, &wire.BatchSignature)
		case "end_chain_hash":
			err = decodeBatchField(decoder, &wire.EndChainHash)
		case "end_chain_index":
			err = decodeBatchField(decoder, &wire.EndChainIndex)
		case "end_projection_accumulator":
			err = decodeBatchField(
				decoder,
				&wire.EndProjectionAccumulator,
			)
		case "end_projection_state_digest":
			err = decodeBatchField(
				decoder,
				&wire.EndProjectionStateDigest,
			)
		case "end_result_hash":
			err = decodeBatchField(decoder, &wire.EndResultHash)
		case "from_result_index":
			err = decodeBatchField(decoder, &wire.FromResultIndex)
		case "recovery_generation":
			err = decodeBatchField(decoder, &wire.RecoveryGeneration)
		case "results":
			wire.Results, err = decodeBatchResults(decoder)
		case "server_applied_result_index":
			err = decodeBatchField(
				decoder,
				&wire.ServerAppliedResultIndex,
			)
		case "server_authority_version":
			err = decodeBatchField(
				decoder,
				&wire.ServerAuthorityVersion,
			)
		case "server_device_id":
			err = decodeBatchField(decoder, &wire.ServerDeviceID)
		case "session_id":
			err = decodeBatchField(decoder, &wire.SessionID)
		case "start_chain_hash":
			err = decodeBatchField(decoder, &wire.StartChainHash)
		case "start_chain_index":
			err = decodeBatchField(decoder, &wire.StartChainIndex)
		case "start_projection_accumulator":
			err = decodeBatchField(
				decoder,
				&wire.StartProjectionAccumulator,
			)
		case "start_projection_state_digest":
			err = decodeBatchField(
				decoder,
				&wire.StartProjectionStateDigest,
			)
		case "start_result_hash":
			err = decodeBatchField(decoder, &wire.StartResultHash)
		case "to_result_index":
			err = decodeBatchField(decoder, &wire.ToResultIndex)
		case "workspace_id":
			err = decodeBatchField(decoder, &wire.WorkspaceID)
		default:
			return batchWire{}, fmt.Errorf(
				"%w: unknown field %q",
				ErrInvalidBatch,
				name,
			)
		}
		if err != nil {
			return batchWire{}, fmt.Errorf(
				"%w: field %s: %v",
				ErrInvalidBatch,
				name,
				err,
			)
		}
	}
	token, err = decoder.Token()
	if err != nil {
		return batchWire{}, fmt.Errorf(
			"%w: close object: %v",
			ErrInvalidBatch,
			err,
		)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return batchWire{}, fmt.Errorf(
			"%w: invalid object terminator",
			ErrInvalidBatch,
		)
	}
	if token, err = decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("unexpected token %v", token)
		}
		return batchWire{}, fmt.Errorf(
			"%w: trailing data: %v",
			ErrInvalidBatch,
			err,
		)
	}
	if len(seen) != 20 {
		return batchWire{}, fmt.Errorf(
			"%w: got %d fields, want 20",
			ErrInvalidBatch,
			len(seen),
		)
	}
	return wire, nil
}

func decodeBatchField(decoder *json.Decoder, destination any) error {
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if bytes.Equal(raw, []byte("null")) {
		return errors.New("must not be null")
	}
	return json.Unmarshal(raw, destination)
}

func decodeBatchResults(
	decoder *json.Decoder,
) ([]json.RawMessage, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return nil, errors.New("must be an array")
	}
	results := make([]json.RawMessage, 0, 16)
	encodedBytes := 2
	for decoder.More() {
		if len(results) == MaxBatchResults {
			return nil, fmt.Errorf(
				"contains more than %d results",
				MaxBatchResults,
			)
		}
		var result json.RawMessage
		if err := decoder.Decode(&result); err != nil {
			return nil, err
		}
		added := len(result)
		if len(results) != 0 {
			added++
		}
		if added > MaxBatchExpandedBytes-encodedBytes {
			return nil, ErrBatchTooLarge
		}
		encodedBytes += added
		results = append(results, result)
	}
	token, err = decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != ']' {
		return nil, errors.New("invalid array terminator")
	}
	return results, nil
}

func inputFromWire(wire batchWire) (BatchInput, error) {
	startResult, err := decodeDigest("start_result_hash", wire.StartResultHash)
	if err != nil {
		return BatchInput{}, err
	}
	endResult, err := decodeDigest("end_result_hash", wire.EndResultHash)
	if err != nil {
		return BatchInput{}, err
	}
	startChain, err := decodeDigest("start_chain_hash", wire.StartChainHash)
	if err != nil {
		return BatchInput{}, err
	}
	endChain, err := decodeDigest("end_chain_hash", wire.EndChainHash)
	if err != nil {
		return BatchInput{}, err
	}
	startAccumulator, err := decodeDigest(
		"start_projection_accumulator",
		wire.StartProjectionAccumulator,
	)
	if err != nil {
		return BatchInput{}, err
	}
	endAccumulator, err := decodeDigest(
		"end_projection_accumulator",
		wire.EndProjectionAccumulator,
	)
	if err != nil {
		return BatchInput{}, err
	}
	startStateDigest, err := decodeDigest(
		"start_projection_state_digest",
		wire.StartProjectionStateDigest,
	)
	if err != nil {
		return BatchInput{}, err
	}
	endStateDigest, err := decodeDigest(
		"end_projection_state_digest",
		wire.EndProjectionStateDigest,
	)
	if err != nil {
		return BatchInput{}, err
	}
	results := make([][]byte, len(wire.Results))
	for index := range wire.Results {
		results[index] = wire.Results[index]
	}
	return BatchInput{
		FromResultIndex:            wire.FromResultIndex,
		ToResultIndex:              wire.ToResultIndex,
		StartResultHash:            startResult,
		EndResultHash:              endResult,
		StartChainIndex:            wire.StartChainIndex,
		StartChainHash:             startChain,
		EndChainIndex:              wire.EndChainIndex,
		EndChainHash:               endChain,
		StartProjectionAccumulator: startAccumulator,
		EndProjectionAccumulator:   endAccumulator,
		StartProjectionStateDigest: startStateDigest,
		EndProjectionStateDigest:   endStateDigest,
		Results:                    results,
		SessionID:                  domain.UUIDv7(wire.SessionID),
		WorkspaceID:                domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration:         wire.RecoveryGeneration,
		ServerDeviceID:             domain.DeviceID(wire.ServerDeviceID),
		ServerAppliedResultIndex:   wire.ServerAppliedResultIndex,
		ServerAuthorityVersion:     wire.ServerAuthorityVersion,
	}, nil
}

func decodeDigest(name, text string) (chain.Digest, error) {
	decoded, err := codec.DecodeBase64URLExact(text, len(chain.Digest{}))
	if err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: %s: %v",
			ErrInvalidBatch,
			name,
			err,
		)
	}
	var digest chain.Digest
	copy(digest[:], decoded)
	return digest, nil
}

func encodeUnsignedBatch(input BatchInput) ([]byte, []resultSpan) {
	capacity := 768
	for _, result := range input.Results {
		capacity += len(result) + 1
	}
	encoded := make([]byte, 0, capacity)
	spans := make([]resultSpan, 0, len(input.Results))
	encoded = append(encoded, `{"end_chain_hash":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(input.EndChainHash[:]))
	encoded = append(encoded, `,"end_chain_index":`...)
	encoded = strconv.AppendUint(encoded, input.EndChainIndex, 10)
	encoded = append(encoded, `,"end_projection_accumulator":`...)
	encoded = appendQuoted(
		encoded,
		codec.EncodeBase64URL(input.EndProjectionAccumulator[:]),
	)
	encoded = append(encoded, `,"end_projection_state_digest":`...)
	encoded = appendQuoted(
		encoded,
		codec.EncodeBase64URL(input.EndProjectionStateDigest[:]),
	)
	encoded = append(encoded, `,"end_result_hash":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(input.EndResultHash[:]))
	encoded = append(encoded, `,"from_result_index":`...)
	encoded = strconv.AppendUint(encoded, input.FromResultIndex, 10)
	encoded = append(encoded, `,"recovery_generation":`...)
	encoded = strconv.AppendUint(encoded, input.RecoveryGeneration, 10)
	encoded = append(encoded, `,"results":[`...)
	for index, result := range input.Results {
		if index != 0 {
			encoded = append(encoded, ',')
		}
		start := len(encoded)
		encoded = append(encoded, result...)
		spans = append(spans, resultSpan{start: start, end: len(encoded)})
	}
	encoded = append(encoded, `],"server_applied_result_index":`...)
	encoded = strconv.AppendUint(encoded, input.ServerAppliedResultIndex, 10)
	encoded = append(encoded, `,"server_authority_version":`...)
	encoded = strconv.AppendUint(encoded, input.ServerAuthorityVersion, 10)
	encoded = append(encoded, `,"server_device_id":`...)
	encoded = appendQuoted(encoded, string(input.ServerDeviceID))
	encoded = append(encoded, `,"session_id":`...)
	encoded = appendQuoted(encoded, string(input.SessionID))
	encoded = append(encoded, `,"start_chain_hash":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(input.StartChainHash[:]))
	encoded = append(encoded, `,"start_chain_index":`...)
	encoded = strconv.AppendUint(encoded, input.StartChainIndex, 10)
	encoded = append(encoded, `,"start_projection_accumulator":`...)
	encoded = appendQuoted(
		encoded,
		codec.EncodeBase64URL(input.StartProjectionAccumulator[:]),
	)
	encoded = append(encoded, `,"start_projection_state_digest":`...)
	encoded = appendQuoted(
		encoded,
		codec.EncodeBase64URL(input.StartProjectionStateDigest[:]),
	)
	encoded = append(encoded, `,"start_result_hash":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(input.StartResultHash[:]))
	encoded = append(encoded, `,"to_result_index":`...)
	encoded = strconv.AppendUint(encoded, input.ToResultIndex, 10)
	encoded = append(encoded, `,"workspace_id":`...)
	encoded = appendQuoted(encoded, string(input.WorkspaceID))
	encoded = append(encoded, '}')
	return encoded, spans
}

func encodeAttestationEnvelope(input BatchInput) []byte {
	encoded := make([]byte, 0, 704)
	encoded = append(encoded, `{"end_chain_hash":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(input.EndChainHash[:]))
	encoded = append(encoded, `,"end_chain_index":`...)
	encoded = strconv.AppendUint(encoded, input.EndChainIndex, 10)
	encoded = append(encoded, `,"end_projection_accumulator":`...)
	encoded = appendQuoted(
		encoded,
		codec.EncodeBase64URL(input.EndProjectionAccumulator[:]),
	)
	encoded = append(encoded, `,"end_projection_state_digest":`...)
	encoded = appendQuoted(
		encoded,
		codec.EncodeBase64URL(input.EndProjectionStateDigest[:]),
	)
	encoded = append(encoded, `,"end_result_hash":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(input.EndResultHash[:]))
	encoded = append(encoded, `,"from_result_index":`...)
	encoded = strconv.AppendUint(encoded, input.FromResultIndex, 10)
	encoded = append(encoded, `,"recovery_generation":`...)
	encoded = strconv.AppendUint(encoded, input.RecoveryGeneration, 10)
	encoded = append(encoded, `,"server_applied_result_index":`...)
	encoded = strconv.AppendUint(encoded, input.ServerAppliedResultIndex, 10)
	encoded = append(encoded, `,"server_authority_version":`...)
	encoded = strconv.AppendUint(encoded, input.ServerAuthorityVersion, 10)
	encoded = append(encoded, `,"server_device_id":`...)
	encoded = appendQuoted(encoded, string(input.ServerDeviceID))
	encoded = append(encoded, `,"session_id":`...)
	encoded = appendQuoted(encoded, string(input.SessionID))
	encoded = append(encoded, `,"start_chain_hash":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(input.StartChainHash[:]))
	encoded = append(encoded, `,"start_chain_index":`...)
	encoded = strconv.AppendUint(encoded, input.StartChainIndex, 10)
	encoded = append(encoded, `,"start_projection_accumulator":`...)
	encoded = appendQuoted(
		encoded,
		codec.EncodeBase64URL(input.StartProjectionAccumulator[:]),
	)
	encoded = append(encoded, `,"start_projection_state_digest":`...)
	encoded = appendQuoted(
		encoded,
		codec.EncodeBase64URL(input.StartProjectionStateDigest[:]),
	)
	encoded = append(encoded, `,"start_result_hash":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(input.StartResultHash[:]))
	encoded = append(encoded, `,"to_result_index":`...)
	encoded = strconv.AppendUint(encoded, input.ToResultIndex, 10)
	encoded = append(encoded, `,"workspace_id":`...)
	encoded = appendQuoted(encoded, string(input.WorkspaceID))
	return append(encoded, '}')
}

func encodeCompleteBatch(
	unsigned []byte,
	signature [ed25519.SignatureSize]byte,
) []byte {
	prefix := completeBatchPrefix(signature)
	encoded := make([]byte, 0, completeBatchSize(len(unsigned)))
	encoded = append(encoded, prefix...)
	encoded = append(encoded, unsigned[1:]...)
	return encoded
}

func completeBatchPrefix(
	signature [ed25519.SignatureSize]byte,
) []byte {
	encoded := make([]byte, 0, 108)
	encoded = append(encoded, `{"batch_signature":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(signature[:]))
	return append(encoded, ',')
}

func completeBatchSize(unsignedBytes int) int {
	return unsignedBytes - 1 +
		len(`{"batch_signature":`) +
		3 +
		batchSignatureTextBytes
}

func matchesCompleteBatch(
	complete []byte,
	unsigned []byte,
	signature [ed25519.SignatureSize]byte,
) bool {
	prefix := completeBatchPrefix(signature)
	return len(complete) == len(prefix)+len(unsigned)-1 &&
		bytes.Equal(complete[:len(prefix)], prefix) &&
		bytes.Equal(complete[len(prefix):], unsigned[1:])
}

func appendQuoted(destination []byte, value string) []byte {
	destination = append(destination, '"')
	destination = append(destination, value...)
	return append(destination, '"')
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if written < 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
