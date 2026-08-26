package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
)

const (
	raftSnapshotEnvelopeSchemaVersion        = 1
	maxRaftSnapshotEnvelopeBytes             = 8 << 10
	raftSnapshotFramePrefixBytes             = len(raftSnapshotFrameMagic) + 4
	maxRaftSnapshotPayloadBytes       uint64 = logicalsnapshot.MaxArtifactExpandedBytes +
		logicalsnapshot.MaxRootBytes + 4
)

var (
	raftSnapshotFrameMagic = [8]byte{'C', 'C', 'R', 'S', 'N', 'A', 'P', 1}

	ErrInvalidRaftSnapshotEnvelope = errors.New(
		"consensus: invalid Raft snapshot envelope",
	)
	ErrRaftSnapshotMetadataMismatch = errors.New(
		"consensus: Raft snapshot metadata mismatch",
	)
	ErrRaftSnapshotPayloadIntegrity = errors.New(
		"consensus: Raft snapshot payload integrity failure",
	)
)

// raftSnapshotEnvelope binds an identity-signed logical snapshot payload to
// the exact metadata supplied independently by HashiCorp Raft. SourceServerID
// is the signed logical-root signer, not the immediate transport peer:
// SnapshotStore.Create does not receive the inbound peer identity.
type raftSnapshotEnvelope struct {
	SchemaVersion           uint64
	SourceServerID          domain.DeviceID
	SnapshotIndex           uint64
	SnapshotTerm            uint64
	ConfigurationIndex      uint64
	ConfigurationDigest     [sha256.Size]byte
	BaselineCommandLogIndex *uint64
	BaselineCommandTerm     *uint64
	PayloadDigest           [sha256.Size]byte
	PayloadBytes            uint64
}

type raftSnapshotEnvelopeWire struct {
	BaselineCommandLogIndex *uint64 `json:"baseline_command_log_index"`
	BaselineCommandTerm     *uint64 `json:"baseline_command_term"`
	ConfigurationDigest     string  `json:"configuration_digest"`
	ConfigurationIndex      uint64  `json:"configuration_index"`
	PayloadBytes            uint64  `json:"payload_bytes"`
	PayloadDigest           string  `json:"payload_digest"`
	SchemaVersion           uint64  `json:"schema_version"`
	SnapshotIndex           uint64  `json:"snapshot_index"`
	SnapshotTerm            uint64  `json:"snapshot_term"`
	SourceServerID          string  `json:"source_server_id"`
}

var raftSnapshotEnvelopeMembers = [...]string{
	"baseline_command_log_index",
	"baseline_command_term",
	"configuration_digest",
	"configuration_index",
	"payload_bytes",
	"payload_digest",
	"schema_version",
	"snapshot_index",
	"snapshot_term",
	"source_server_id",
}

func encodeRaftSnapshotEnvelope(
	envelope raftSnapshotEnvelope,
) ([]byte, error) {
	if err := validateRaftSnapshotEnvelope(envelope); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(raftSnapshotEnvelopeWire{
		BaselineCommandLogIndex: cloneUint64Pointer(
			envelope.BaselineCommandLogIndex,
		),
		BaselineCommandTerm: cloneUint64Pointer(
			envelope.BaselineCommandTerm,
		),
		ConfigurationDigest: codec.EncodeBase64URL(
			envelope.ConfigurationDigest[:],
		),
		ConfigurationIndex: envelope.ConfigurationIndex,
		PayloadBytes:       envelope.PayloadBytes,
		PayloadDigest: codec.EncodeBase64URL(
			envelope.PayloadDigest[:],
		),
		SchemaVersion:  envelope.SchemaVersion,
		SnapshotIndex:  envelope.SnapshotIndex,
		SnapshotTerm:   envelope.SnapshotTerm,
		SourceServerID: string(envelope.SourceServerID),
	})
	if err != nil {
		return nil, fmt.Errorf(
			"%w: encode header: %v",
			ErrInvalidRaftSnapshotEnvelope,
			err,
		)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil ||
		len(canonical) == 0 ||
		len(canonical) > maxRaftSnapshotEnvelopeBytes {
		return nil, ErrInvalidRaftSnapshotEnvelope
	}
	return canonical, nil
}

func decodeRaftSnapshotEnvelope(
	encoded []byte,
) (raftSnapshotEnvelope, error) {
	if len(encoded) == 0 || len(encoded) > maxRaftSnapshotEnvelopeBytes {
		return raftSnapshotEnvelope{}, ErrInvalidRaftSnapshotEnvelope
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return raftSnapshotEnvelope{}, fmt.Errorf(
			"%w: noncanonical header",
			ErrInvalidRaftSnapshotEnvelope,
		)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil ||
		len(members) != len(raftSnapshotEnvelopeMembers) {
		return raftSnapshotEnvelope{}, ErrInvalidRaftSnapshotEnvelope
	}
	for _, member := range raftSnapshotEnvelopeMembers {
		if _, exists := members[member]; !exists {
			return raftSnapshotEnvelope{}, ErrInvalidRaftSnapshotEnvelope
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire raftSnapshotEnvelopeWire
	if err := decoder.Decode(&wire); err != nil {
		return raftSnapshotEnvelope{}, fmt.Errorf(
			"%w: decode header: %v",
			ErrInvalidRaftSnapshotEnvelope,
			err,
		)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return raftSnapshotEnvelope{}, ErrInvalidRaftSnapshotEnvelope
	}
	configurationDigest, err := codec.DecodeBase64URLExact(
		wire.ConfigurationDigest,
		sha256.Size,
	)
	if err != nil {
		return raftSnapshotEnvelope{}, ErrInvalidRaftSnapshotEnvelope
	}
	payloadDigest, err := codec.DecodeBase64URLExact(
		wire.PayloadDigest,
		sha256.Size,
	)
	if err != nil {
		return raftSnapshotEnvelope{}, ErrInvalidRaftSnapshotEnvelope
	}
	envelope := raftSnapshotEnvelope{
		SchemaVersion:      wire.SchemaVersion,
		SourceServerID:     domain.DeviceID(wire.SourceServerID),
		SnapshotIndex:      wire.SnapshotIndex,
		SnapshotTerm:       wire.SnapshotTerm,
		ConfigurationIndex: wire.ConfigurationIndex,
		BaselineCommandLogIndex: cloneUint64Pointer(
			wire.BaselineCommandLogIndex,
		),
		BaselineCommandTerm: cloneUint64Pointer(
			wire.BaselineCommandTerm,
		),
		PayloadBytes: wire.PayloadBytes,
	}
	copy(envelope.ConfigurationDigest[:], configurationDigest)
	copy(envelope.PayloadDigest[:], payloadDigest)
	if err := validateRaftSnapshotEnvelope(envelope); err != nil {
		return raftSnapshotEnvelope{}, err
	}
	return envelope, nil
}

func validateRaftSnapshotEnvelope(
	envelope raftSnapshotEnvelope,
) error {
	if envelope.SchemaVersion != raftSnapshotEnvelopeSchemaVersion ||
		!envelope.SourceServerID.Valid() ||
		envelope.SnapshotIndex < 1 ||
		!domain.ValidUnsignedInteger(envelope.SnapshotIndex) ||
		envelope.SnapshotTerm < 1 ||
		!domain.ValidUnsignedInteger(envelope.SnapshotTerm) ||
		envelope.ConfigurationIndex < 1 ||
		envelope.ConfigurationIndex > envelope.SnapshotIndex ||
		!domain.ValidUnsignedInteger(envelope.ConfigurationIndex) ||
		envelope.PayloadBytes < 1 ||
		envelope.PayloadBytes > maxRaftSnapshotPayloadBytes {
		return ErrInvalidRaftSnapshotEnvelope
	}
	if (envelope.BaselineCommandLogIndex == nil) !=
		(envelope.BaselineCommandTerm == nil) {
		return ErrInvalidRaftSnapshotEnvelope
	}
	if envelope.BaselineCommandLogIndex != nil {
		if *envelope.BaselineCommandLogIndex < 1 ||
			*envelope.BaselineCommandLogIndex > envelope.SnapshotIndex ||
			!domain.ValidUnsignedInteger(
				*envelope.BaselineCommandLogIndex,
			) ||
			*envelope.BaselineCommandTerm < 1 ||
			*envelope.BaselineCommandTerm > envelope.SnapshotTerm ||
			!domain.ValidUnsignedInteger(*envelope.BaselineCommandTerm) {
			return ErrInvalidRaftSnapshotEnvelope
		}
	}
	return nil
}

func raftSnapshotConfigurationDigest(
	configuration raft.Configuration,
) ([sha256.Size]byte, error) {
	encoded, err := encodeRaftConfiguration(configuration)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func validateRaftSnapshotEnvelopeMetadata(
	envelope raftSnapshotEnvelope,
	meta *raft.SnapshotMeta,
	headerBytes int,
	requireSize bool,
) error {
	if err := validateRaftSnapshotMetadata(meta, requireSize); err != nil {
		return err
	}
	if headerBytes < 1 || headerBytes > maxRaftSnapshotEnvelopeBytes {
		return ErrInvalidRaftSnapshotEnvelope
	}
	digest, err := raftSnapshotConfigurationDigest(meta.Configuration)
	if err != nil {
		return err
	}
	if envelope.SnapshotIndex != meta.Index ||
		envelope.SnapshotTerm != meta.Term ||
		envelope.ConfigurationIndex != meta.ConfigurationIndex ||
		envelope.ConfigurationDigest != digest ||
		!raftConfigurationContainsDevice(
			meta.Configuration,
			envelope.SourceServerID,
		) {
		return ErrRaftSnapshotMetadataMismatch
	}
	if requireSize {
		frameBytes, ok := raftSnapshotFrameSize(
			headerBytes,
			envelope.PayloadBytes,
		)
		if !ok || meta.Size != frameBytes {
			return ErrRaftSnapshotMetadataMismatch
		}
	}
	return nil
}

func raftConfigurationContainsDevice(
	configuration raft.Configuration,
	deviceID domain.DeviceID,
) bool {
	for _, server := range configuration.Servers {
		if server.ID == raft.ServerID(deviceID) &&
			server.Address == raft.ServerAddress(deviceID) {
			return true
		}
	}
	return false
}

func raftSnapshotFrameSize(
	headerBytes int,
	payloadBytes uint64,
) (int64, bool) {
	if headerBytes < 1 ||
		headerBytes > maxRaftSnapshotEnvelopeBytes ||
		payloadBytes < 1 ||
		payloadBytes > maxRaftSnapshotPayloadBytes {
		return 0, false
	}
	total := uint64(raftSnapshotFramePrefixBytes) +
		uint64(headerBytes) + payloadBytes
	if total > uint64(^uint64(0)>>1) {
		return 0, false
	}
	return int64(total), true
}

func writeRaftSnapshotFrame(
	writer io.Writer,
	envelope raftSnapshotEnvelope,
	payload io.Reader,
) error {
	if writer == nil || payload == nil {
		return ErrInvalidRaftSnapshotEnvelope
	}
	header, err := encodeRaftSnapshotEnvelope(envelope)
	if err != nil {
		return err
	}
	var prefix [raftSnapshotFramePrefixBytes]byte
	copy(prefix[:len(raftSnapshotFrameMagic)], raftSnapshotFrameMagic[:])
	binary.BigEndian.PutUint32(
		prefix[len(raftSnapshotFrameMagic):],
		uint32(len(header)),
	)
	if err := writeRaftSnapshotFrameBytes(writer, prefix[:]); err != nil {
		return err
	}
	if err := writeRaftSnapshotFrameBytes(writer, header); err != nil {
		return err
	}
	hasher := sha256.New()
	limited := &io.LimitedReader{
		R: payload,
		N: int64(envelope.PayloadBytes),
	}
	written, err := io.Copy(
		writer,
		io.TeeReader(limited, hasher),
	)
	if err != nil {
		return err
	}
	if written != int64(envelope.PayloadBytes) ||
		limited.N != 0 {
		return ErrRaftSnapshotPayloadIntegrity
	}
	var trailing [1]byte
	trailingBytes, trailingErr := payload.Read(trailing[:])
	if trailingBytes != 0 || !errors.Is(trailingErr, io.EOF) {
		return ErrRaftSnapshotPayloadIntegrity
	}
	if !bytes.Equal(hasher.Sum(nil), envelope.PayloadDigest[:]) {
		return ErrRaftSnapshotPayloadIntegrity
	}
	return nil
}

func readRaftSnapshotFrameHeader(
	reader io.Reader,
) (raftSnapshotEnvelope, []byte, error) {
	if reader == nil {
		return raftSnapshotEnvelope{}, nil, ErrInvalidRaftSnapshotEnvelope
	}
	var prefix [raftSnapshotFramePrefixBytes]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return raftSnapshotEnvelope{}, nil, fmt.Errorf(
			"%w: read prefix: %v",
			ErrInvalidRaftSnapshotEnvelope,
			err,
		)
	}
	if !bytes.Equal(
		prefix[:len(raftSnapshotFrameMagic)],
		raftSnapshotFrameMagic[:],
	) {
		return raftSnapshotEnvelope{}, nil, ErrInvalidRaftSnapshotEnvelope
	}
	headerBytes := binary.BigEndian.Uint32(
		prefix[len(raftSnapshotFrameMagic):],
	)
	if headerBytes < 1 ||
		headerBytes > uint32(maxRaftSnapshotEnvelopeBytes) {
		return raftSnapshotEnvelope{}, nil, ErrInvalidRaftSnapshotEnvelope
	}
	header := make([]byte, int(headerBytes))
	if _, err := io.ReadFull(reader, header); err != nil {
		return raftSnapshotEnvelope{}, nil, fmt.Errorf(
			"%w: read header: %v",
			ErrInvalidRaftSnapshotEnvelope,
			err,
		)
	}
	envelope, err := decodeRaftSnapshotEnvelope(header)
	if err != nil {
		return raftSnapshotEnvelope{}, nil, err
	}
	framing := make([]byte, 0, len(prefix)+len(header))
	framing = append(framing, prefix[:]...)
	framing = append(framing, header...)
	return envelope, framing, nil
}

func writeRaftSnapshotFrameBytes(writer io.Writer, value []byte) error {
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

func cloneRaftSnapshotEnvelope(
	envelope raftSnapshotEnvelope,
) raftSnapshotEnvelope {
	envelope.BaselineCommandLogIndex = cloneUint64Pointer(
		envelope.BaselineCommandLogIndex,
	)
	envelope.BaselineCommandTerm = cloneUint64Pointer(
		envelope.BaselineCommandTerm,
	)
	return envelope
}

func cloneUint64Pointer(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
