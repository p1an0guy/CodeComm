package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
)

func TestRaftSnapshotEnvelopeRoundTripAndClosedSchema(t *testing.T) {
	t.Parallel()

	configuration, sourceID := raftSnapshotTestConfiguration()
	payload := []byte("complete logical snapshot payload")
	envelope := raftSnapshotTestEnvelope(
		t,
		configuration,
		sourceID,
		payload,
	)
	encoded, err := encodeRaftSnapshotEnvelope(envelope)
	if err != nil {
		t.Fatalf("encodeRaftSnapshotEnvelope(): %v", err)
	}
	decoded, err := decodeRaftSnapshotEnvelope(encoded)
	if err != nil {
		t.Fatalf("decodeRaftSnapshotEnvelope(): %v", err)
	}
	if !sameRaftSnapshotEnvelope(decoded, envelope) {
		t.Fatalf("decoded envelope = %#v, want %#v", decoded, envelope)
	}

	if _, err := decodeRaftSnapshotEnvelope(
		append([]byte(" "), encoded...),
	); !errors.Is(err, ErrInvalidRaftSnapshotEnvelope) {
		t.Fatalf("decode noncanonical header error = %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	object["unknown"] = "rejected"
	rawUnknown, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("json.Marshal(unknown): %v", err)
	}
	canonicalUnknown, err := codec.CanonicalizeSignedObject(rawUnknown)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(unknown): %v", err)
	}
	if _, err := decodeRaftSnapshotEnvelope(
		canonicalUnknown,
	); !errors.Is(err, ErrInvalidRaftSnapshotEnvelope) {
		t.Fatalf("decode unknown member error = %v", err)
	}
	delete(object, "unknown")
	delete(object, "baseline_command_log_index")
	delete(object, "baseline_command_term")
	rawMissing, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("json.Marshal(missing): %v", err)
	}
	canonicalMissing, err := codec.CanonicalizeSignedObject(rawMissing)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(missing): %v", err)
	}
	if _, err := decodeRaftSnapshotEnvelope(
		canonicalMissing,
	); !errors.Is(err, ErrInvalidRaftSnapshotEnvelope) {
		t.Fatalf("decode missing nullable members error = %v", err)
	}
}

func TestRaftSnapshotEnvelopeRejectsInvalidBounds(t *testing.T) {
	t.Parallel()

	configuration, sourceID := raftSnapshotTestConfiguration()
	valid := raftSnapshotTestEnvelope(
		t,
		configuration,
		sourceID,
		[]byte("payload"),
	)
	baselineIndex := *valid.BaselineCommandLogIndex
	baselineTerm := *valid.BaselineCommandTerm
	tests := []struct {
		name   string
		mutate func(*raftSnapshotEnvelope)
	}{
		{
			name: "schema",
			mutate: func(value *raftSnapshotEnvelope) {
				value.SchemaVersion++
			},
		},
		{
			name: "source",
			mutate: func(value *raftSnapshotEnvelope) {
				value.SourceServerID = "invalid"
			},
		},
		{
			name: "snapshot index",
			mutate: func(value *raftSnapshotEnvelope) {
				value.SnapshotIndex = 0
			},
		},
		{
			name: "snapshot term",
			mutate: func(value *raftSnapshotEnvelope) {
				value.SnapshotTerm = domain.MaxSafeInteger + 1
			},
		},
		{
			name: "configuration follows snapshot",
			mutate: func(value *raftSnapshotEnvelope) {
				value.ConfigurationIndex = value.SnapshotIndex + 1
			},
		},
		{
			name: "baseline null mismatch",
			mutate: func(value *raftSnapshotEnvelope) {
				value.BaselineCommandTerm = nil
			},
		},
		{
			name: "baseline follows snapshot",
			mutate: func(value *raftSnapshotEnvelope) {
				following := value.SnapshotIndex + 1
				value.BaselineCommandLogIndex = &following
			},
		},
		{
			name: "baseline term follows snapshot",
			mutate: func(value *raftSnapshotEnvelope) {
				following := value.SnapshotTerm + 1
				value.BaselineCommandTerm = &following
			},
		},
		{
			name: "empty payload",
			mutate: func(value *raftSnapshotEnvelope) {
				value.PayloadBytes = 0
			},
		},
		{
			name: "oversized payload",
			mutate: func(value *raftSnapshotEnvelope) {
				value.PayloadBytes = maxRaftSnapshotPayloadBytes + 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := cloneRaftSnapshotEnvelope(valid)
			test.mutate(&value)
			if err := validateRaftSnapshotEnvelope(value); !errors.Is(
				err,
				ErrInvalidRaftSnapshotEnvelope,
			) {
				t.Fatalf("validateRaftSnapshotEnvelope() error = %v", err)
			}
		})
	}
	if baselineIndex != *valid.BaselineCommandLogIndex ||
		baselineTerm != *valid.BaselineCommandTerm {
		t.Fatal("test mutations changed the original envelope")
	}

	nullable := cloneRaftSnapshotEnvelope(valid)
	nullable.BaselineCommandLogIndex = nil
	nullable.BaselineCommandTerm = nil
	if err := validateRaftSnapshotEnvelope(nullable); err != nil {
		t.Fatalf("nullable baseline rejected: %v", err)
	}
}

func TestRaftSnapshotConfigurationDigestIsPermutationStable(t *testing.T) {
	t.Parallel()

	configuration, _ := raftSnapshotTestConfiguration()
	original := configuration.Clone()
	first, err := raftSnapshotConfigurationDigest(configuration)
	if err != nil {
		t.Fatalf("raftSnapshotConfigurationDigest(): %v", err)
	}
	permuted := configuration.Clone()
	permuted.Servers[0], permuted.Servers[1] =
		permuted.Servers[1], permuted.Servers[0]
	second, err := raftSnapshotConfigurationDigest(permuted)
	if err != nil {
		t.Fatalf("raftSnapshotConfigurationDigest(permuted): %v", err)
	}
	if first != second {
		t.Fatalf("configuration permutation changed digest: %x != %x", first, second)
	}
	if !sameRaftSnapshotTestConfiguration(configuration, original) {
		t.Fatal("digesting mutated the caller's configuration")
	}

	changed := configuration.Clone()
	changed.Servers[1].Suffrage = raft.Voter
	third, err := raftSnapshotConfigurationDigest(changed)
	if err != nil {
		t.Fatalf("raftSnapshotConfigurationDigest(changed): %v", err)
	}
	if first == third {
		t.Fatal("suffrage change retained configuration digest")
	}

	duplicate := configuration.Clone()
	duplicate.Servers[1] = duplicate.Servers[0]
	if _, err := raftSnapshotConfigurationDigest(
		duplicate,
	); !errors.Is(err, ErrInvalidRaftTopology) {
		t.Fatalf("duplicate configuration error = %v", err)
	}
	wrongAddress := configuration.Clone()
	wrongAddress.Servers[1].Address = "wrong"
	if _, err := raftSnapshotConfigurationDigest(
		wrongAddress,
	); !errors.Is(err, ErrInvalidRaftTopology) {
		t.Fatalf("wrong-address configuration error = %v", err)
	}
}

func TestRaftSnapshotFrameRequiresExactPayload(t *testing.T) {
	t.Parallel()

	configuration, sourceID := raftSnapshotTestConfiguration()
	payload := []byte("payload bytes")
	envelope := raftSnapshotTestEnvelope(
		t,
		configuration,
		sourceID,
		payload,
	)
	var frame bytes.Buffer
	if err := writeRaftSnapshotFrame(
		&frame,
		envelope,
		bytes.NewReader(payload),
	); err != nil {
		t.Fatalf("writeRaftSnapshotFrame(): %v", err)
	}
	decoded, framing, err := readRaftSnapshotFrameHeader(
		bytes.NewReader(frame.Bytes()),
	)
	if err != nil {
		t.Fatalf("readRaftSnapshotFrameHeader(): %v", err)
	}
	if !sameRaftSnapshotEnvelope(decoded, envelope) ||
		len(framing) <= raftSnapshotFramePrefixBytes {
		t.Fatal("frame header did not preserve envelope")
	}

	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{name: "short", payload: payload[:len(payload)-1]},
		{name: "appended", payload: append(bytes.Clone(payload), 'x')},
		{name: "changed", payload: append([]byte{'x'}, payload[1:]...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := writeRaftSnapshotFrame(
				&output,
				envelope,
				bytes.NewReader(test.payload),
			); !errors.Is(err, ErrRaftSnapshotPayloadIntegrity) {
				t.Fatalf("writeRaftSnapshotFrame() error = %v", err)
			}
		})
	}
}

func raftSnapshotTestConfiguration() (
	raft.Configuration,
	domain.DeviceID,
) {
	first := domain.DeviceID("cc1" + string(bytes.Repeat([]byte{'1'}, 64)))
	second := domain.DeviceID("cc1" + string(bytes.Repeat([]byte{'2'}, 64)))
	return raft.Configuration{Servers: []raft.Server{
		{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(first),
			Address:  raft.ServerAddress(first),
		},
		{
			Suffrage: raft.Nonvoter,
			ID:       raft.ServerID(second),
			Address:  raft.ServerAddress(second),
		},
	}}, first
}

func raftSnapshotTestEnvelope(
	t *testing.T,
	configuration raft.Configuration,
	sourceID domain.DeviceID,
	payload []byte,
) raftSnapshotEnvelope {
	t.Helper()
	configurationDigest, err := raftSnapshotConfigurationDigest(configuration)
	if err != nil {
		t.Fatalf("raftSnapshotConfigurationDigest(): %v", err)
	}
	baselineIndex := uint64(10)
	baselineTerm := uint64(3)
	return raftSnapshotEnvelope{
		SchemaVersion:           raftSnapshotEnvelopeSchemaVersion,
		SourceServerID:          sourceID,
		SnapshotIndex:           11,
		SnapshotTerm:            3,
		ConfigurationIndex:      7,
		ConfigurationDigest:     configurationDigest,
		BaselineCommandLogIndex: &baselineIndex,
		BaselineCommandTerm:     &baselineTerm,
		PayloadDigest:           sha256.Sum256(payload),
		PayloadBytes:            uint64(len(payload)),
	}
}

func sameRaftSnapshotEnvelope(
	left raftSnapshotEnvelope,
	right raftSnapshotEnvelope,
) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.SourceServerID == right.SourceServerID &&
		left.SnapshotIndex == right.SnapshotIndex &&
		left.SnapshotTerm == right.SnapshotTerm &&
		left.ConfigurationIndex == right.ConfigurationIndex &&
		left.ConfigurationDigest == right.ConfigurationDigest &&
		sameUint64Pointer(
			left.BaselineCommandLogIndex,
			right.BaselineCommandLogIndex,
		) &&
		sameUint64Pointer(
			left.BaselineCommandTerm,
			right.BaselineCommandTerm,
		) &&
		left.PayloadDigest == right.PayloadDigest &&
		left.PayloadBytes == right.PayloadBytes
}

func sameUint64Pointer(left, right *uint64) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

func sameRaftSnapshotTestConfiguration(
	left raft.Configuration,
	right raft.Configuration,
) bool {
	if len(left.Servers) != len(right.Servers) {
		return false
	}
	for index := range left.Servers {
		if left.Servers[index] != right.Servers[index] {
			return false
		}
	}
	return true
}
