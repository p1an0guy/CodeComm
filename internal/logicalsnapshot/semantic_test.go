package logicalsnapshot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/event"
)

const (
	semanticWorkspaceID = domain.UUIDv4(
		"550e8400-e29b-41d4-a716-446655440000",
	)
	semanticSession0 = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000001",
	)
	semanticSession1 = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000002",
	)
	semanticEvent1 = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000011",
	)
	semanticCheckpointEvent = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000012",
	)
	semanticBootID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000021",
	)
)

func TestSemanticPayloadCodecsRoundTripClosedCanonicalObjects(t *testing.T) {
	t.Parallel()

	fixture := newSemanticFixture(t, true, semanticProjectionRows())
	payloads := map[string]struct {
		record  Record
		decode  func([]byte) error
		members []string
	}{
		"genesis": {
			record: fixture.records[1],
			decode: func(encoded []byte) error {
				value, err := DecodeGenesisPayload(encoded)
				if err != nil {
					return err
				}
				reencoded, err := EncodeGenesisPayload(value)
				if err != nil {
					return err
				}
				if !bytes.Equal(reencoded, encoded) {
					return errors.New("genesis round trip differs")
				}
				value.GenesisJSON[0] = '!'
				if bytes.Equal(
					value.GenesisJSON,
					fixture.successorGenesis,
				) {
					return errors.New("genesis aliases fixture")
				}
				return nil
			},
			members: []string{
				"boundary_transform_digest",
				"genesis",
				"recovery_authorization",
			},
		},
		"result": {
			record: fixture.records[2],
			decode: func(encoded []byte) error {
				value, err := DecodeResultPayload(encoded)
				if err != nil {
					return err
				}
				reencoded, err := EncodeResultPayload(value)
				if err != nil {
					return err
				}
				if !bytes.Equal(reencoded, encoded) {
					return errors.New("result round trip differs")
				}
				value.Result.Proposal[0] = '!'
				if bytes.Equal(
					value.Result.Proposal,
					fixture.firstProposal,
				) {
					return errors.New("result aliases fixture")
				}
				return nil
			},
			members: []string{
				"mutation_bytes",
				"mutation_chunk_count",
				"mutation_sha256",
				"result",
			},
		},
		"mutation": {
			record: fixture.records[3],
			decode: func(encoded []byte) error {
				value, err := DecodeMutationChunkPayload(encoded)
				if err != nil {
					return err
				}
				reencoded, err := EncodeMutationChunkPayload(value)
				if err != nil {
					return err
				}
				if !bytes.Equal(reencoded, encoded) {
					return errors.New("mutation chunk round trip differs")
				}
				value.Data[0] ^= 0xff
				if bytes.Equal(value.Data, []byte("[]")) {
					return errors.New("mutation chunk aliases fixture")
				}
				return nil
			},
			members: []string{"chunk_index", "data", "result_index"},
		},
		"event": {
			record: fixture.records[6],
			decode: func(encoded []byte) error {
				value, err := DecodeEventPayload(encoded)
				if err != nil {
					return err
				}
				reencoded, err := EncodeEventPayload(value)
				if err != nil {
					return err
				}
				if !bytes.Equal(reencoded, encoded) {
					return errors.New("event round trip differs")
				}
				value.Proposal[0] = '!'
				if bytes.Equal(value.Proposal, fixture.firstProposal) {
					return errors.New("event aliases fixture")
				}
				return nil
			},
			members: []string{"chain_hash", "chain_index", "proposal"},
		},
		"projection": {
			record: fixture.records[8],
			decode: func(encoded []byte) error {
				value, err := DecodeProjectionPayload(encoded)
				if err != nil {
					return err
				}
				reencoded, err := EncodeProjectionPayload(value)
				if err != nil {
					return err
				}
				if !bytes.Equal(reencoded, encoded) {
					return errors.New("projection round trip differs")
				}
				value.Row.PrimaryKey[0] = '!'
				if bytes.Equal(
					value.Row.PrimaryKey,
					semanticProjectionRows()[0].PrimaryKey,
				) {
					return errors.New("projection aliases fixture")
				}
				return nil
			},
			members: []string{"primary_key", "row", "table"},
		},
		"checkpoint": {
			record: fixture.records[len(fixture.records)-1],
			decode: func(encoded []byte) error {
				value, err := DecodeCheckpointPayload(encoded)
				if err != nil {
					return err
				}
				reencoded, err := EncodeCheckpointPayload(value)
				if err != nil {
					return err
				}
				if !bytes.Equal(reencoded, encoded) {
					return errors.New("checkpoint round trip differs")
				}
				value.SignedPayload[0] = '!'
				if bytes.Equal(
					value.SignedPayload,
					fixture.checkpointPayload,
				) {
					return errors.New("checkpoint aliases fixture")
				}
				return nil
			},
			members: []string{"checkpoint_event_id", "payload"},
		},
	}

	for name, test := range payloads {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := test.decode(test.record.Payload); err != nil {
				t.Fatalf("decode/encode: %v", err)
			}
			assertSemanticMembers(t, test.record.Payload, test.members)
			canonical, err := codec.Canonicalize(test.record.Payload)
			if err != nil || !bytes.Equal(canonical, test.record.Payload) {
				t.Fatalf("payload is not exact canonical JSON: %v", err)
			}
		})
	}
}

func TestSemanticPayloadCodecsRejectUnknownMissingAndNoncanonicalFields(
	t *testing.T,
) {
	t.Parallel()

	fixture := newSemanticFixture(t, false, nil)
	tests := []struct {
		name   string
		record Record
		decode func([]byte) error
	}{
		{
			name:   "genesis",
			record: fixture.records[0],
			decode: func(value []byte) error {
				_, err := DecodeGenesisPayload(value)
				return err
			},
		},
		{
			name:   "result",
			record: fixture.records[1],
			decode: func(value []byte) error {
				_, err := DecodeResultPayload(value)
				return err
			},
		},
		{
			name:   "mutation",
			record: fixture.records[2],
			decode: func(value []byte) error {
				_, err := DecodeMutationChunkPayload(value)
				return err
			},
		},
		{
			name:   "event",
			record: fixture.records[3],
			decode: func(value []byte) error {
				_, err := DecodeEventPayload(value)
				return err
			},
		},
		{
			name: "projection",
			record: Record{
				Type: RecordProjection,
				Payload: mustEncodeProjectionPayload(
					t,
					semanticProjectionRows()[0],
				),
			},
			decode: func(value []byte) error {
				_, err := DecodeProjectionPayload(value)
				return err
			},
		},
		{
			name:   "checkpoint",
			record: fixture.records[4],
			decode: func(value []byte) error {
				_, err := DecodeCheckpointPayload(value)
				return err
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			unknown := addSemanticMember(
				t,
				test.record.Payload,
				"unknown",
				json.RawMessage("true"),
			)
			if err := test.decode(unknown); err == nil {
				t.Fatal("unknown member was accepted")
			}

			var members map[string]json.RawMessage
			if err := json.Unmarshal(test.record.Payload, &members); err != nil {
				t.Fatal(err)
			}
			for member := range members {
				delete(members, member)
				break
			}
			missing := canonicalSemanticJSON(t, members)
			if err := test.decode(missing); err == nil {
				t.Fatal("missing member was accepted")
			}
			noncanonical := append([]byte(" "), test.record.Payload...)
			if err := test.decode(noncanonical); err == nil {
				t.Fatal("noncanonical payload was accepted")
			}
		})
	}
}

func TestSequenceValidatorAcceptsPostCheckpointSuccessorSnapshot(
	t *testing.T,
) {
	t.Parallel()

	fixture := newSemanticFixture(t, true, semanticProjectionRows())
	validator := newTestSequenceValidator(t, fixture.root)
	for index, record := range fixture.records {
		if err := validator.Consume(record); err != nil {
			t.Fatalf("Consume(record %d %s): %v", index, record.Type, err)
		}
	}
	if err := validator.Finish(); err != nil {
		t.Fatalf("Finish(): %v", err)
	}
	if err := validator.Finish(); err != nil {
		t.Fatalf("Finish(second): %v", err)
	}
	if err := validator.Consume(fixture.records[0]); !errors.Is(
		err,
		ErrSequenceFinished,
	) {
		t.Fatalf("Consume(after finish) = %v, want ErrSequenceFinished", err)
	}
}

func TestSequenceValidatorRejectsAnyPriorGenesisSessionReuse(
	t *testing.T,
) {
	t.Parallel()

	scratch, err := os.CreateTemp(t.TempDir(), "generation-scratch-*")
	if err != nil {
		t.Fatal(err)
	}
	defer scratch.Close()
	validator := &SequenceValidator{
		root:    RootInput{RecoveryGeneration: 2},
		scratch: scratch,
	}
	for generation, sessionID := range []domain.UUIDv7{
		semanticSession0,
		semanticSession1,
	} {
		seen, err := validator.priorGenesisSessionID(sessionID)
		if err != nil || seen {
			t.Fatalf(
				"priorGenesisSessionID(new %d) = %t, %v",
				generation,
				seen,
				err,
			)
		}
		if err := writeSequenceBoundary(scratch, sequenceBoundary{
			generation: uint64(generation),
			sessionID:  sessionID,
		}); err != nil {
			t.Fatal(err)
		}
		validator.genesisCount++
	}
	seen, err := validator.priorGenesisSessionID(semanticSession0)
	if err != nil || !seen {
		t.Fatalf("priorGenesisSessionID(reused) = %t, %v", seen, err)
	}
	unseen := domain.UUIDv7("01890f47-3e72-7000-8000-000000000003")
	seen, err = validator.priorGenesisSessionID(unseen)
	if err != nil || seen {
		t.Fatalf("priorGenesisSessionID(fresh) = %t, %v", seen, err)
	}
	if err := writeSequenceBoundary(scratch, sequenceBoundary{
		generation: 2,
		sessionID:  unseen,
	}); err != nil {
		t.Fatalf("write after restored append offset: %v", err)
	}
}

func TestSequenceValidatorRejectsOrderCountsAndCommitmentChanges(
	t *testing.T,
) {
	t.Parallel()

	rows := semanticProjectionRows()
	tests := []struct {
		name   string
		mutate func(*testing.T, *semanticFixture)
	}{
		{
			name: "event before results",
			mutate: func(_ *testing.T, fixture *semanticFixture) {
				fixture.records[2], fixture.records[6] =
					fixture.records[6], fixture.records[2]
			},
		},
		{
			name: "result mutation changes accumulator",
			mutate: func(t *testing.T, fixture *semanticFixture) {
				payload, err := DecodeResultPayload(
					fixture.records[2].Payload,
				)
				if err != nil {
					t.Fatal(err)
				}
				mutations := []chain.Mutation{{
					Table:      rows[0].Table,
					PrimaryKey: rows[0].PrimaryKey,
					After:      rows[0].Row,
				}}
				payload, encoded, err := NewResultPayload(
					payload.Result,
					mutations,
				)
				if err != nil {
					t.Fatal(err)
				}
				fixture.records[2].Payload = mustEncodeResultPayload(
					t,
					payload,
				)
				fixture.records[3].Payload =
					mustEncodeMutationChunkPayload(
						t,
						MutationChunkPayload{
							ResultIndex: payload.Result.ResultIndex,
							ChunkIndex:  0,
							Data:        encoded,
						},
					)
			},
		},
		{
			name: "mutation chunk index changes",
			mutate: func(t *testing.T, fixture *semanticFixture) {
				payload, err := DecodeMutationChunkPayload(
					fixture.records[3].Payload,
				)
				if err != nil {
					t.Fatal(err)
				}
				payload.ChunkIndex = 1
				fixture.records[3].Payload =
					mustEncodeMutationChunkPayload(t, payload)
			},
		},
		{
			name: "mutation stream digest changes",
			mutate: func(t *testing.T, fixture *semanticFixture) {
				payload, err := DecodeResultPayload(
					fixture.records[2].Payload,
				)
				if err != nil {
					t.Fatal(err)
				}
				payload.MutationDigest[0] ^= 0xff
				fixture.records[2].Payload = mustEncodeResultPayload(
					t,
					payload,
				)
			},
		},
		{
			name: "mutation chunk is missing",
			mutate: func(_ *testing.T, fixture *semanticFixture) {
				fixture.records = append(
					fixture.records[:3],
					fixture.records[4:]...,
				)
			},
		},
		{
			name: "event chain hash changes",
			mutate: func(t *testing.T, fixture *semanticFixture) {
				payload, err := DecodeEventPayload(
					fixture.records[6].Payload,
				)
				if err != nil {
					t.Fatal(err)
				}
				payload.ChainHash[0] ^= 0xff
				fixture.records[6].Payload = mustEncodeEventPayload(
					t,
					payload,
				)
			},
		},
		{
			name: "projection key order changes",
			mutate: func(_ *testing.T, fixture *semanticFixture) {
				fixture.records[8], fixture.records[9] =
					fixture.records[9], fixture.records[8]
			},
		},
		{
			name: "checkpoint payload changes",
			mutate: func(t *testing.T, fixture *semanticFixture) {
				payload, err := DecodeCheckpointPayload(
					fixture.records[10].Payload,
				)
				if err != nil {
					t.Fatal(err)
				}
				payload.CheckpointEventID = semanticEvent1
				fixture.records[10].Payload = mustEncodeCheckpointPayload(
					t,
					payload,
				)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSemanticFixture(t, true, rows)
			test.mutate(t, &fixture)
			validator := newTestSequenceValidator(t, fixture.root)
			var got error
			for _, record := range fixture.records {
				if got = validator.Consume(record); got != nil {
					break
				}
			}
			if got == nil {
				got = validator.Finish()
			}
			if !errors.Is(got, ErrInvalidRecordSequence) {
				t.Fatalf(
					"validation error = %v, want ErrInvalidRecordSequence",
					got,
				)
			}
			if again := validator.Finish(); again != got {
				t.Fatalf("latched error = %v, want identical %v", again, got)
			}
		})
	}
}

func TestSequenceValidatorRequiresTerminalCheckpointAndExactRootCount(
	t *testing.T,
) {
	t.Parallel()

	fixture := newSemanticFixture(t, false, nil)
	validator := newTestSequenceValidator(t, fixture.root)
	for _, record := range fixture.records[:len(fixture.records)-1] {
		if err := validator.Consume(record); err != nil {
			t.Fatalf("Consume(): %v", err)
		}
	}
	if err := validator.Finish(); !errors.Is(
		err,
		ErrInvalidRecordSequence,
	) {
		t.Fatalf("Finish(missing checkpoint) = %v", err)
	}

	input := fixture.root.Unsigned().Input()
	input.RecordCount++
	input.ExpandedBytes++
	input.CompressedBytes++
	unsigned, err := NewUnsignedRoot(input)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	wrongCount, err := SignRoot(unsigned, fixture.privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}
	validator = newTestSequenceValidator(t, wrongCount)
	var got error
	for _, record := range fixture.records {
		if got = validator.Consume(record); got != nil {
			break
		}
	}
	if !errors.Is(got, ErrInvalidRecordSequence) {
		t.Fatalf("Consume(wrong count) = %v", got)
	}
}

func TestProjectionStreamDigestMatchesChainStateDigest(t *testing.T) {
	t.Parallel()

	rows := semanticProjectionRows()
	want, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		rows,
	)
	if err != nil {
		t.Fatalf("chain.StateDigest(): %v", err)
	}
	fixture := newSemanticFixture(t, false, rows)
	if fixture.root.Unsigned().Input().ProjectionStateDigest != want {
		t.Fatal("fixture did not bind chain.StateDigest")
	}
	validator := newTestSequenceValidator(t, fixture.root)
	for _, record := range fixture.records {
		if err := validator.Consume(record); err != nil {
			t.Fatalf("Consume(%s): %v", record.Type, err)
		}
	}
	if err := validator.Finish(); err != nil {
		t.Fatalf("Finish(): %v", err)
	}
}

func TestResultMutationsDriveAccumulatorToPostCheckpointState(
	t *testing.T,
) {
	t.Parallel()

	finalRows := semanticProjectionRows()[:1]
	fixture := newSemanticFixtureFromState(
		t,
		false,
		nil,
		finalRows,
		[]chain.Mutation{{
			Table:      finalRows[0].Table,
			PrimaryKey: finalRows[0].PrimaryKey,
			After:      finalRows[0].Row,
		}},
	)
	validator := newTestSequenceValidator(t, fixture.root)
	for _, record := range fixture.records {
		if err := validator.Consume(record); err != nil {
			t.Fatalf("Consume(%s): %v", record.Type, err)
		}
	}
	if err := validator.Finish(); err != nil {
		t.Fatalf("Finish(): %v", err)
	}
}

func TestResultMutationChunksRepresentEncodingAboveChunkLimit(t *testing.T) {
	t.Parallel()

	fixture := newSemanticFixture(t, false, nil)
	header, err := DecodeResultPayload(fixture.records[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	mutations := largeSemanticLeaseMutations(256)
	payload, encoded, err := NewResultPayload(header.Result, mutations)
	if err != nil {
		t.Fatalf("NewResultPayload(): %v", err)
	}
	if len(encoded) <= MaxChunkCompressedBytes {
		t.Fatalf(
			"mutation encoding = %d bytes, want above %d-byte chunk limit",
			len(encoded),
			MaxChunkCompressedBytes,
		)
	}
	if payload.MutationChunkCount < 3 {
		t.Fatalf(
			"mutation chunk count = %d, want at least 3",
			payload.MutationChunkCount,
		)
	}
	headerBytes := mustEncodeResultPayload(t, payload)
	if len(headerBytes) > MaxRecordPayloadBytes {
		t.Fatalf("result header = %d bytes", len(headerBytes))
	}

	var reconstructed []byte
	for offset := 0; offset < len(encoded); {
		end := min(offset+MaxMutationChunkBytes, len(encoded))
		chunkBytes := mustEncodeMutationChunkPayload(
			t,
			MutationChunkPayload{
				ResultIndex: payload.Result.ResultIndex,
				ChunkIndex:  uint64(offset / MaxMutationChunkBytes),
				Data:        encoded[offset:end],
			},
		)
		if len(chunkBytes) > MaxRecordPayloadBytes {
			t.Fatalf("chunk payload = %d bytes", len(chunkBytes))
		}
		chunk, err := DecodeMutationChunkPayload(chunkBytes)
		if err != nil {
			t.Fatalf("DecodeMutationChunkPayload(): %v", err)
		}
		reconstructed = append(reconstructed, chunk.Data...)
		offset = end
	}
	if !bytes.Equal(reconstructed, encoded) {
		t.Fatal("mutation chunks did not reconstruct exact encoding")
	}
	if _, err := chain.DecodeMutations(reconstructed); err != nil {
		t.Fatalf("chain.DecodeMutations(reconstructed): %v", err)
	}
}

type semanticFixture struct {
	root              Root
	privateKey        ed25519.PrivateKey
	records           []Record
	firstProposal     []byte
	successorGenesis  []byte
	checkpointPayload []byte
}

func newSemanticFixture(
	t *testing.T,
	successor bool,
	rows []chain.LogicalRow,
) semanticFixture {
	t.Helper()
	return newSemanticFixtureFromState(t, successor, rows, rows, nil)
}

func newSemanticFixtureFromState(
	t *testing.T,
	successor bool,
	boundaryRows []chain.LogicalRow,
	finalRows []chain.LogicalRow,
	checkpointMutations []chain.Mutation,
) semanticFixture {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x42}, ed25519.SeedSize),
	)
	signerID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	boundaryStateDigest, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		boundaryRows,
	)
	if err != nil {
		t.Fatalf("chain.StateDigest(boundary): %v", err)
	}
	finalStateDigest, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		finalRows,
	)
	if err != nil {
		t.Fatalf("chain.StateDigest(final): %v", err)
	}
	initialGenesis := canonicalSemanticJSON(t, map[string]any{
		"creator_signature": codec.EncodeBase64URL(
			bytes.Repeat([]byte{0x31}, ed25519.SignatureSize),
		),
		"recovery_generation": uint64(0),
		"session_id":          string(semanticSession0),
		"workspace_id":        string(semanticWorkspaceID),
	})
	initialDigest, err := chain.GenesisDigest(initialGenesis)
	if err != nil {
		t.Fatalf("chain.GenesisDigest(initial): %v", err)
	}
	eventHead, err := chain.EventSeed(chain.Boundary{
		Genesis: initialDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	resultHead, err := chain.ResultSeed(chain.Boundary{
		Genesis: initialDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	accumulator := chain.AccumulatorSeedInitial(
		initialDigest,
		boundaryStateDigest,
	)
	records := []Record{{
		Type: RecordGenesis,
		Payload: mustEncodeGenesisPayload(t, GenesisPayload{
			GenesisJSON:             initialGenesis,
			BoundaryTransformDigest: boundaryStateDigest,
		}),
	}}
	activeSession := semanticSession0
	var (
		firstProposal    []byte
		successorGenesis []byte
		results          []Record
		events           []Record
		resultIndex      uint64
		chainIndex       uint64
	)

	if successor {
		first := signedSemanticEvent(
			t,
			privateKey,
			semanticSession0,
			semanticEvent1,
			1,
			event.KindActivityRecorded,
			[]byte(`{}`),
			"pre-recovery activity",
		)
		firstProposal = first.CanonicalBytes()
		var resultRecords []Record
		var eventRecord Record
		resultRecords, eventRecord, eventHead, resultHead, accumulator =
			appendSemanticAccepted(
				t,
				1,
				1,
				eventHead,
				resultHead,
				accumulator,
				firstProposal,
				nil,
			)
		results = append(results, resultRecords...)
		events = append(events, eventRecord)
		resultIndex = 1
		chainIndex = 1

		successorGenesis = canonicalSemanticJSON(t, map[string]any{
			"digest_version": uint64(1),
			"post_transform_state_digest": codec.EncodeBase64URL(
				boundaryStateDigest[:],
			),
			"predecessor_chain_hash": codec.EncodeBase64URL(
				eventHead[:],
			),
			"predecessor_chain_index": chainIndex,
			"predecessor_genesis_digest": codec.EncodeBase64URL(
				initialDigest[:],
			),
			"predecessor_projection_accumulator": codec.EncodeBase64URL(
				accumulator[:],
			),
			"predecessor_result_hash": codec.EncodeBase64URL(
				resultHead[:],
			),
			"predecessor_result_index":  resultIndex,
			"projection_schema_version": uint64(1),
			"quorum_recovery_signature": codec.EncodeBase64URL(
				bytes.Repeat([]byte{0x52}, ed25519.SignatureSize),
			),
			"recovering_identity_signature": codec.EncodeBase64URL(
				bytes.Repeat([]byte{0x49}, ed25519.SignatureSize),
			),
			"recovery_generation": uint64(1),
			"session_id":          string(semanticSession1),
			"workspace_id":        string(semanticWorkspaceID),
		})
		successorDigest, digestErr := chain.GenesisDigest(successorGenesis)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		records = append(records, Record{
			Type: RecordGenesis,
			Payload: mustEncodeGenesisPayload(t, GenesisPayload{
				GenesisJSON: successorGenesis,
				RecoveryAuthorizationJSON: []byte(
					`{"kind":"test-recovery"}`,
				),
				BoundaryTransformDigest: boundaryStateDigest,
			}),
		})
		boundary := chain.Boundary{
			Genesis:     successorDigest,
			Generation:  1,
			ChainIndex:  chainIndex,
			ResultIndex: resultIndex,
			ChainHash:   eventHead,
			ResultHash:  resultHead,
		}
		eventHead, err = chain.EventSeed(boundary)
		if err != nil {
			t.Fatal(err)
		}
		resultHead, err = chain.ResultSeed(boundary)
		if err != nil {
			t.Fatal(err)
		}
		accumulator = chain.AccumulatorSeedSuccessor(
			accumulator,
			successorDigest,
			boundaryStateDigest,
		)
		activeSession = semanticSession1
	}

	checkpoint := domain.Checkpoint{
		SessionID:                activeSession,
		WorkspaceID:              semanticWorkspaceID,
		RecoveryGeneration:       boolUint64(successor),
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           signerID,
		Term:                     1,
		CoveredAppliedLogIndex:   10,
		CoveredChainIndex:        chainIndex,
		CoveredChainHash:         eventHead,
		CoveredResultIndex:       resultIndex,
		CoveredResultHash:        resultHead,
		ProjectionAccumulator:    accumulator,
		DigestVersion:            1,
		ProjectionSchemaVersion:  1,
	}
	signature, err := event.SignCheckpoint(checkpoint, privateKey)
	if err != nil {
		t.Fatalf("event.SignCheckpoint(): %v", err)
	}
	checkpointPayload, err := event.EncodeCheckpointPayload(
		checkpoint,
		signature,
	)
	if err != nil {
		t.Fatalf("event.EncodeCheckpointPayload(): %v", err)
	}
	checkpointEvent := signedSemanticEvent(
		t,
		privateKey,
		activeSession,
		semanticCheckpointEvent,
		1,
		event.KindConsensusCheckpoint,
		checkpointPayload,
		"",
	)
	checkpointProposal := checkpointEvent.CanonicalBytes()
	resultIndex++
	chainIndex++
	resultRecords, eventRecord, eventHead, resultHead, accumulator :=
		appendSemanticAccepted(
			t,
			resultIndex,
			chainIndex,
			eventHead,
			resultHead,
			accumulator,
			checkpointProposal,
			checkpointMutations,
		)
	results = append(results, resultRecords...)
	events = append(events, eventRecord)
	if firstProposal == nil {
		firstProposal = checkpointProposal
	}

	records = append(records, results...)
	records = append(records, events...)
	for _, row := range finalRows {
		records = append(records, Record{
			Type:    RecordProjection,
			Payload: mustEncodeProjectionPayload(t, row),
		})
	}
	records = append(records, Record{
		Type: RecordCheckpoint,
		Payload: mustEncodeCheckpointPayload(t, CheckpointPayload{
			CheckpointEventID: semanticCheckpointEvent,
			SignedPayload:     checkpointPayload,
		}),
	})

	unsigned, err := NewUnsignedRoot(RootInput{
		ArtifactID:              "semantic-snapshot",
		SessionID:               activeSession,
		WorkspaceID:             semanticWorkspaceID,
		RecoveryGeneration:      boolUint64(successor),
		CheckpointEventID:       semanticCheckpointEvent,
		ChainIndex:              chainIndex,
		ChainHash:               eventHead,
		ResultIndex:             resultIndex,
		ResultHash:              resultHead,
		ProjectionAccumulator:   accumulator,
		ProjectionStateDigest:   finalStateDigest,
		AuthorityVersion:        1,
		SignerDeviceID:          signerID,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
		ContentEncoding:         EncodingIdentity,
		ExpandedBytes:           uint64(len(records)),
		CompressedBytes:         uint64(len(records)),
		RecordCount:             uint64(len(records)),
		DescriptorPageCount:     1,
		ChunkCount:              1,
		ArtifactDigest:          sha256.Sum256([]byte("artifact")),
		FinalDescriptorPageHash: sha256.Sum256([]byte("page")),
	})
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}
	return semanticFixture{
		root:              root,
		privateKey:        privateKey,
		records:           records,
		firstProposal:     firstProposal,
		successorGenesis:  successorGenesis,
		checkpointPayload: checkpointPayload,
	}
}

func appendSemanticAccepted(
	t *testing.T,
	resultIndex uint64,
	chainIndex uint64,
	eventHead chain.Digest,
	resultHead chain.Digest,
	accumulator chain.Digest,
	proposal []byte,
	mutations []chain.Mutation,
) ([]Record, Record, chain.Digest, chain.Digest, chain.Digest) {
	t.Helper()
	nextEvent, err := chain.AppendEvent(eventHead, proposal)
	if err != nil {
		t.Fatal(err)
	}
	proposalDigest := sha256.Sum256(proposal)
	index := chainIndex
	eventDigest := nextEvent
	result := chain.Result{
		ResultIndex:    resultIndex,
		Proposal:       proposal,
		Outcome:        []byte(`{"code":"accepted","status":"accepted"}`),
		ProposalDigest: proposalDigest,
		ChainIndex:     &index,
		ChainHash:      &eventDigest,
	}
	nextResult, _, err := chain.AppendResult(resultHead, result)
	if err != nil {
		t.Fatal(err)
	}
	nextAccumulator, _, err := chain.AppendAccumulator(
		accumulator,
		resultIndex,
		nextResult,
		mutations,
	)
	if err != nil {
		t.Fatal(err)
	}
	resultPayload, encodedMutations, err := NewResultPayload(
		result,
		mutations,
	)
	if err != nil {
		t.Fatal(err)
	}
	resultRecords := []Record{{
		Type:    RecordResult,
		Payload: mustEncodeResultPayload(t, resultPayload),
	}}
	for offset := 0; offset < len(encodedMutations); {
		end := min(offset+MaxMutationChunkBytes, len(encodedMutations))
		resultRecords = append(resultRecords, Record{
			Type: RecordMutation,
			Payload: mustEncodeMutationChunkPayload(
				t,
				MutationChunkPayload{
					ResultIndex: resultIndex,
					ChunkIndex: uint64(
						offset / MaxMutationChunkBytes,
					),
					Data: encodedMutations[offset:end],
				},
			),
		})
		offset = end
	}
	return resultRecords, Record{
		Type: RecordEvent,
		Payload: mustEncodeEventPayload(t, EventPayload{
			ChainIndex: chainIndex,
			ChainHash:  nextEvent,
			Proposal:   proposal,
		}),
	}, nextEvent, nextResult, nextAccumulator
}

func signedSemanticEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	sessionID domain.UUIDv7,
	eventID domain.UUIDv7,
	sequence uint64,
	kind event.Kind,
	payload []byte,
	rationale string,
) event.SignedEvent {
	t.Helper()
	deviceID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := event.NewLocalAuthority(deviceID, semanticBootID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             kind,
			EntityID:         event.NullEntityID(),
			RationaleSummary: rationale,
			Actions:          []event.Action{},
			Payload:          payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      sessionID,
			WorkspaceID:    semanticWorkspaceID,
			CreatedAt:      "2026-08-10T12:00:00Z",
			OriginSequence: sequence,
		},
	)
	if err != nil {
		t.Fatalf("event.BuildProposal(): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign(): %v", err)
	}
	return signed
}

func semanticProjectionRows() []chain.LogicalRow {
	return []chain.LogicalRow{
		{
			Table:      "audit_counters",
			PrimaryKey: []byte(`["device-a"]`),
			Row: []byte(
				`{"accepted_count":1,"credential_epoch":1,"device_id":"device-a"}`,
			),
		},
		{
			Table:      "audit_counters",
			PrimaryKey: []byte(`["device-b"]`),
			Row: []byte(
				`{"accepted_count":2,"credential_epoch":1,"device_id":"device-b"}`,
			),
		},
	}
}

func largeSemanticLeaseMutations(count int) []chain.Mutation {
	paths := make([]string, lease.MaxPathPatterns)
	for index := range paths {
		prefix := fmt.Sprintf("src/%02d/", index)
		paths[index] = prefix + strings.Repeat("x", 512-len(prefix))
	}
	mutations := make([]chain.Mutation, count)
	for index := range mutations {
		leaseID := fmt.Sprintf(
			"01890f47-3e72-7000-8001-%012x",
			index,
		)
		before := canonicalSemanticJSONValue(map[string]any{
			"entity_version":          1,
			"holder_agent_session_id": string(semanticBootID),
			"holder_device_id":        "cc1" + strings.Repeat("a", 64),
			"lease_id":                leaseID,
			"path_globs":              paths,
			"release_reason":          nil,
			"scope":                   "path",
			"status":                  "active",
			"task_id":                 nil,
			"ttl_seconds":             86_400,
		})
		after := canonicalSemanticJSONValue(map[string]any{
			"entity_version":          2,
			"holder_agent_session_id": string(semanticBootID),
			"holder_device_id":        "cc1" + strings.Repeat("a", 64),
			"lease_id":                leaseID,
			"path_globs":              paths,
			"release_reason":          "session_ended",
			"scope":                   "path",
			"status":                  "released",
			"task_id":                 nil,
			"ttl_seconds":             86_400,
		})
		mutations[index] = chain.Mutation{
			Table:      "leases",
			PrimaryKey: canonicalSemanticJSONValue([]any{leaseID}),
			Before:     before,
			After:      after,
		}
	}
	return mutations
}

func newTestSequenceValidator(
	t *testing.T,
	root Root,
) *SequenceValidator {
	t.Helper()
	scratch, err := os.CreateTemp(t.TempDir(), "sequence-scratch-*")
	if err != nil {
		t.Fatalf("os.CreateTemp(): %v", err)
	}
	t.Cleanup(func() {
		if err := scratch.Close(); err != nil {
			t.Errorf("scratch.Close(): %v", err)
		}
	})
	validator, err := NewSequenceValidator(root, scratch)
	if err != nil {
		t.Fatalf("NewSequenceValidator(): %v", err)
	}
	return validator
}

func mustEncodeGenesisPayload(
	t *testing.T,
	payload GenesisPayload,
) []byte {
	t.Helper()
	encoded, err := EncodeGenesisPayload(payload)
	if err != nil {
		t.Fatalf("EncodeGenesisPayload(): %v", err)
	}
	return encoded
}

func mustEncodeResultPayload(
	t *testing.T,
	payload ResultPayload,
) []byte {
	t.Helper()
	encoded, err := EncodeResultPayload(payload)
	if err != nil {
		t.Fatalf("EncodeResultPayload(): %v", err)
	}
	return encoded
}

func mustEncodeMutationChunkPayload(
	t *testing.T,
	payload MutationChunkPayload,
) []byte {
	t.Helper()
	encoded, err := EncodeMutationChunkPayload(payload)
	if err != nil {
		t.Fatalf("EncodeMutationChunkPayload(): %v", err)
	}
	return encoded
}

func mustEncodeEventPayload(
	t *testing.T,
	payload EventPayload,
) []byte {
	t.Helper()
	encoded, err := EncodeEventPayload(payload)
	if err != nil {
		t.Fatalf("EncodeEventPayload(): %v", err)
	}
	return encoded
}

func mustEncodeProjectionPayload(
	t *testing.T,
	row chain.LogicalRow,
) []byte {
	t.Helper()
	encoded, err := EncodeProjectionPayload(ProjectionPayload{Row: row})
	if err != nil {
		t.Fatalf("EncodeProjectionPayload(): %v", err)
	}
	return encoded
}

func mustEncodeCheckpointPayload(
	t *testing.T,
	payload CheckpointPayload,
) []byte {
	t.Helper()
	encoded, err := EncodeCheckpointPayload(payload)
	if err != nil {
		t.Fatalf("EncodeCheckpointPayload(): %v", err)
	}
	return encoded
}

func canonicalSemanticJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	canonical, err := codec.Canonicalize(raw)
	if err != nil {
		t.Fatalf("codec.Canonicalize(): %v", err)
	}
	return canonical
}

func canonicalSemanticJSONValue(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	canonical, err := codec.Canonicalize(raw)
	if err != nil {
		panic(err)
	}
	return canonical
}

func addSemanticMember(
	t *testing.T,
	encoded []byte,
	name string,
	value json.RawMessage,
) []byte {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatal(err)
	}
	members[name] = value
	return canonicalSemanticJSON(t, members)
}

func assertSemanticMembers(
	t *testing.T,
	encoded []byte,
	want []string,
) {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(members))
	for member := range members {
		got = append(got, member)
	}
	for left := 0; left < len(got); left++ {
		for right := left + 1; right < len(got); right++ {
			if got[right] < got[left] {
				got[left], got[right] = got[right], got[left]
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("members = %q, want %q", got, want)
	}
}

func boolUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
