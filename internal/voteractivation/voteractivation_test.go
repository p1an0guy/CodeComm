package voteractivation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
)

const (
	testSessionID  domain.UUIDv7 = "018f1f6e-7b2c-7def-8abc-1234567890ab"
	testWorkspace  domain.UUIDv4 = "550e8400-e29b-41d4-a716-446655440000"
	testCheckpoint domain.UUIDv7 = "018f1f6e-7b2c-7def-8abc-1234567890ac"
)

type testSigner struct {
	id      domain.DeviceID
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

type activationFixture struct {
	target     []testSigner
	prior      testSigner
	checkpoint domain.Checkpoint
	proofs     []Proof
	handoff    UnsignedAuthorityHandoff
	payload    ActivationPayload
}

func TestProofAndHandoffRoundTripExactClosedObjects(t *testing.T) {
	fixture := newActivationFixture(t)

	for index, proof := range fixture.proofs {
		if err := VerifyProof(proof, fixture.target[index].public); err != nil {
			t.Fatalf("VerifyProof(%d): %v", index, err)
		}
		unsigned := proof.Unsigned()
		parsedUnsigned, err := ParseUnsignedProof(unsigned.CanonicalBytes())
		if err != nil {
			t.Fatalf("ParseUnsignedProof(%d): %v", index, err)
		}
		if !bytes.Equal(
			parsedUnsigned.CanonicalBytes(),
			unsigned.CanonicalBytes(),
		) {
			t.Fatalf("unsigned proof %d changed across parse", index)
		}
		parsed, err := ParseProof(proof.CanonicalBytes())
		if err != nil {
			t.Fatalf("ParseProof(%d): %v", index, err)
		}
		if !bytes.Equal(parsed.CanonicalBytes(), proof.CanonicalBytes()) {
			t.Fatalf("proof %d changed across parse", index)
		}
		assertExactFields(
			t,
			unsigned.CanonicalBytes(),
			unsignedProofFields,
		)
		assertExactFields(t, proof.CanonicalBytes(), completeProofFields)
	}

	parsedHandoff, err := ParseUnsignedAuthorityHandoff(
		fixture.handoff.CanonicalBytes(),
	)
	if err != nil {
		t.Fatalf("ParseUnsignedAuthorityHandoff(): %v", err)
	}
	if !bytes.Equal(
		parsedHandoff.CanonicalBytes(),
		fixture.handoff.CanonicalBytes(),
	) {
		t.Fatal("handoff changed across parse")
	}
	assertExactFields(
		t,
		fixture.handoff.CanonicalBytes(),
		unsignedHandoffFields,
	)

	encoded, err := EncodeActivationPayload(fixture.payload)
	if err != nil {
		t.Fatalf("EncodeActivationPayload(): %v", err)
	}
	decoded, err := DecodeActivationPayload(encoded)
	if err != nil {
		t.Fatalf("DecodeActivationPayload(): %v", err)
	}
	if !bytes.Equal(decoded.CanonicalBytes(), encoded) {
		t.Fatal("activation payload changed across decode")
	}
	if err := VerifyAuthorityHandoff(
		decoded,
		fixture.prior.public,
	); err != nil {
		t.Fatalf("VerifyAuthorityHandoff(): %v", err)
	}
	assertExactFields(t, encoded, activationPayloadFields)
}

func TestProofStructuralValidation(t *testing.T) {
	fixture := newActivationFixture(t)
	valid := fixture.proofs[0].Unsigned().Input()
	outsider := newTestSigner(t, 90)

	tests := []struct {
		name   string
		mutate func(*ProofInput)
		want   error
	}{
		{
			name: "unsorted target",
			mutate: func(input *ProofInput) {
				input.VoterSet[0], input.VoterSet[1] =
					input.VoterSet[1], input.VoterSet[0]
			},
			want: ErrInvalidProof,
		},
		{
			name: "illegal target count",
			mutate: func(input *ProofInput) {
				input.VoterSet = input.VoterSet[:2]
			},
			want: ErrInvalidProof,
		},
		{
			name: "proof voter outside target",
			mutate: func(input *ProofInput) {
				input.VoterDeviceID = outsider.id
			},
			want: ErrInvalidProof,
		},
		{
			name: "checkpoint session",
			mutate: func(input *ProofInput) {
				input.Checkpoint.SessionID =
					"018f1f6e-7b2c-7def-8abc-1234567890ad"
			},
			want: ErrProofContext,
		},
		{
			name: "target version does not advance authority",
			mutate: func(input *ProofInput) {
				input.TargetVoterSetVersion =
					input.CurrentAuthorityVoterSetVersion
			},
			want: ErrInvalidProof,
		},
		{
			name: "checkpoint authority",
			mutate: func(input *ProofInput) {
				input.Checkpoint.AuthorityVoterSetVersion++
			},
			want: ErrProofContext,
		},
		{
			name: "checkpoint predates configuration",
			mutate: func(input *ProofInput) {
				input.LiveConfigurationIndex =
					input.Checkpoint.CoveredAppliedLogIndex + 1
			},
			want: ErrProofContext,
		},
		{
			name: "zero configuration index",
			mutate: func(input *ProofInput) {
				input.LiveConfigurationIndex = 0
			},
			want: ErrInvalidProof,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneProofInput(valid)
			test.mutate(&input)
			if _, err := NewUnsignedProof(input); !errors.Is(err, test.want) {
				t.Fatalf("NewUnsignedProof() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestHandoffRequiresExactOrderedCommonProofCut(t *testing.T) {
	fixture := newActivationFixture(t)
	valid := fixture.handoff.Input()

	tests := []struct {
		name   string
		mutate func(*AuthorityHandoffInput)
		want   error
	}{
		{
			name: "target version does not advance authority",
			mutate: func(input *AuthorityHandoffInput) {
				input.TargetVoterSetVersion =
					input.ExpectedAuthorityVoterSetVersion
			},
			want: ErrInvalidHandoff,
		},
		{
			name: "proof count",
			mutate: func(input *AuthorityHandoffInput) {
				input.ActivationProofs = input.ActivationProofs[:2]
			},
			want: ErrProofOrder,
		},
		{
			name: "proof order",
			mutate: func(input *AuthorityHandoffInput) {
				input.ActivationProofs[0], input.ActivationProofs[1] =
					input.ActivationProofs[1], input.ActivationProofs[0]
			},
			want: ErrProofOrder,
		},
		{
			name: "configuration index differs",
			mutate: func(input *AuthorityHandoffInput) {
				unsigned := input.ActivationProofs[1].Unsigned().Input()
				unsigned.LiveConfigurationIndex++
				input.ActivationProofs[1] = mustSignProof(
					t,
					unsigned,
					keyForID(fixture.target, unsigned.VoterDeviceID),
				)
			},
			want: ErrCheckpointMismatch,
		},
		{
			name: "checkpoint differs",
			mutate: func(input *AuthorityHandoffInput) {
				unsigned := input.ActivationProofs[1].Unsigned().Input()
				unsigned.Checkpoint.Term++
				input.ActivationProofs[1] = mustSignProof(
					t,
					unsigned,
					keyForID(fixture.target, unsigned.VoterDeviceID),
				)
			},
			want: ErrCheckpointMismatch,
		},
		{
			name: "checkpoint signature differs",
			mutate: func(input *AuthorityHandoffInput) {
				unsigned := input.ActivationProofs[1].Unsigned().Input()
				unsigned.CheckpointSignature[0] ^= 0xff
				input.ActivationProofs[1] = mustSignProof(
					t,
					unsigned,
					keyForID(fixture.target, unsigned.VoterDeviceID),
				)
			},
			want: ErrCheckpointMismatch,
		},
		{
			name: "outer checkpoint event",
			mutate: func(input *AuthorityHandoffInput) {
				input.ActivationCheckpointEventID =
					"018f1f6e-7b2c-7def-8abc-1234567890ad"
			},
			want: ErrProofContext,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneAuthorityInput(valid)
			test.mutate(&input)
			if _, err := NewUnsignedAuthorityHandoff(input); !errors.Is(
				err,
				test.want,
			) {
				t.Fatalf(
					"NewUnsignedAuthorityHandoff() error = %v, want %v",
					err,
					test.want,
				)
			}
		})
	}
}

func TestParsersRejectNoncanonicalAndNonclosedJSON(t *testing.T) {
	fixture := newActivationFixture(t)
	unsignedProof := fixture.proofs[0].Unsigned().CanonicalBytes()
	completeProof := fixture.proofs[0].CanonicalBytes()
	handoff := fixture.handoff.CanonicalBytes()
	payload := fixture.payload.CanonicalBytes()

	tests := []struct {
		name  string
		input []byte
		parse func([]byte) error
		want  error
	}{
		{
			name:  "unsigned proof whitespace",
			input: append(bytes.Clone(unsignedProof), '\n'),
			parse: parseUnsignedProofError,
			want:  ErrNoncanonicalJSON,
		},
		{
			name:  "complete proof unknown",
			input: mutateObject(t, completeProof, "unknown", json.RawMessage(`1`), ""),
			parse: parseProofError,
			want:  ErrInvalidFieldSet,
		},
		{
			name:  "complete proof missing",
			input: mutateObject(t, completeProof, "", nil, "voter_signature"),
			parse: parseProofError,
			want:  ErrInvalidFieldSet,
		},
		{
			name: "complete proof null",
			input: mutateObject(
				t,
				completeProof,
				"voter_signature",
				json.RawMessage(`null`),
				"",
			),
			parse: parseProofError,
			want:  ErrInvalidFieldSet,
		},
		{
			name:  "handoff whitespace",
			input: append(bytes.Clone(handoff), ' '),
			parse: parseHandoffError,
			want:  ErrNoncanonicalJSON,
		},
		{
			name:  "handoff unknown",
			input: mutateObject(t, handoff, "unknown", json.RawMessage(`true`), ""),
			parse: parseHandoffError,
			want:  ErrInvalidFieldSet,
		},
		{
			name:  "payload whitespace",
			input: append(bytes.Clone(payload), '\n'),
			parse: parsePayloadError,
			want:  ErrNoncanonicalJSON,
		},
		{
			name:  "payload missing",
			input: mutateObject(t, payload, "", nil, "prior_authority_handoff"),
			parse: parsePayloadError,
			want:  ErrInvalidFieldSet,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.parse(test.input); !errors.Is(err, test.want) {
				t.Fatalf("parse error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNarrowSignersBindIdentityAndDomainLabels(t *testing.T) {
	fixture := newActivationFixture(t)
	other := newTestSigner(t, 91)
	unsigned := fixture.proofs[0].Unsigned()

	if _, err := SignProof(unsigned, other.private); !errors.Is(
		err,
		ErrSignerMismatch,
	) {
		t.Fatalf("SignProof(other) error = %v, want ErrSignerMismatch", err)
	}
	if err := VerifyProof(fixture.proofs[0], other.public); !errors.Is(
		err,
		ErrSignatureInvalid,
	) {
		t.Fatalf("VerifyProof(other) error = %v, want ErrSignatureInvalid", err)
	}
	tamperedSignature := fixture.proofs[0].VoterSignature()
	tamperedSignature[0] ^= 0xff
	tamperedProof, err := NewProof(unsigned, tamperedSignature)
	if err != nil {
		t.Fatalf("NewProof(tampered signature): %v", err)
	}
	if err := VerifyProof(
		tamperedProof,
		fixture.target[0].public,
	); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("VerifyProof(tampered) error = %v, want ErrSignatureInvalid", err)
	}
	voterSignature := fixture.proofs[0].VoterSignature()
	if err := codecommcrypto.VerifyEd25519(
		fixture.target[0].public,
		codec.SignatureCheckpoint,
		unsigned.CanonicalBytes(),
		voterSignature[:],
	); err == nil {
		t.Fatal("voter proof signature verified under checkpoint label")
	}

	if _, err := SignAuthorityHandoff(
		fixture.handoff,
		other.private,
	); !errors.Is(err, ErrSignerMismatch) {
		t.Fatalf(
			"SignAuthorityHandoff(other) error = %v, want ErrSignerMismatch",
			err,
		)
	}
	tamperedHandoff := fixture.payload.HandoffSignature()
	tamperedHandoff[0] ^= 0xff
	tamperedPayload, err := NewActivationPayload(
		fixture.handoff,
		tamperedHandoff,
	)
	if err != nil {
		t.Fatalf("NewActivationPayload(tampered): %v", err)
	}
	if err := VerifyAuthorityHandoff(
		tamperedPayload,
		fixture.prior.public,
	); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf(
			"VerifyAuthorityHandoff(tampered) error = %v, want ErrSignatureInvalid",
			err,
		)
	}
	handoffSignature := fixture.payload.HandoffSignature()
	if err := codecommcrypto.VerifyEd25519(
		fixture.prior.public,
		codec.SignatureVoterActivationProof,
		fixture.handoff.CanonicalBytes(),
		handoffSignature[:],
	); err == nil {
		t.Fatal("authority handoff verified under voter-proof label")
	}
}

func TestValuesDefensivelyCopyInputsAndOutputs(t *testing.T) {
	fixture := newActivationFixture(t)
	input := fixture.proofs[0].Unsigned().Input()
	originalFirst := input.VoterSet[0]
	unsigned, err := NewUnsignedProof(input)
	if err != nil {
		t.Fatalf("NewUnsignedProof(): %v", err)
	}
	input.VoterSet[0] = newTestSigner(t, 92).id
	if unsigned.Input().VoterSet[0] != originalFirst {
		t.Fatal("unsigned proof aliases input voter set")
	}
	canonical := unsigned.CanonicalBytes()
	canonical[0] = '['
	if unsigned.CanonicalBytes()[0] != '{' {
		t.Fatal("unsigned proof aliases returned canonical bytes")
	}

	handoffInput := fixture.handoff.Input()
	originalProof := fixture.proofs[0].CanonicalBytes()
	handoffInput.VoterSet[0] = newTestSigner(t, 93).id
	handoffInput.ActivationProofs[0] = Proof{}
	after := fixture.handoff.Input()
	if after.VoterSet[0] != fixture.target[0].id ||
		!bytes.Equal(after.ActivationProofs[0].CanonicalBytes(), originalProof) {
		t.Fatal("handoff aliases returned input")
	}

	encoded, err := EncodeActivationPayload(fixture.payload)
	if err != nil {
		t.Fatalf("EncodeActivationPayload(): %v", err)
	}
	encoded[0] = '['
	if fixture.payload.CanonicalBytes()[0] != '{' {
		t.Fatal("activation payload aliases encoded output")
	}
}

func newActivationFixture(t *testing.T) activationFixture {
	t.Helper()
	target := []testSigner{
		newTestSigner(t, 1),
		newTestSigner(t, 2),
		newTestSigner(t, 3),
	}
	sort.Slice(target, func(left, right int) bool {
		return target[left].id < target[right].id
	})
	prior := newTestSigner(t, 10)
	checkpoint := domain.Checkpoint{
		SessionID:                testSessionID,
		WorkspaceID:              testWorkspace,
		RecoveryGeneration:       4,
		AuthorityVoterSetVersion: 2,
		SignerDeviceID:           prior.id,
		Term:                     7,
		CoveredAppliedLogIndex:   31,
		CoveredChainIndex:        20,
		CoveredResultIndex:       22,
		DigestVersion:            1,
		ProjectionSchemaVersion:  1,
	}
	fillDigest(&checkpoint.CoveredChainHash, 0x31)
	fillDigest(&checkpoint.CoveredResultHash, 0x32)
	fillDigest(&checkpoint.ProjectionAccumulator, 0x33)
	checkpointSignature, err := event.SignCheckpoint(checkpoint, prior.private)
	if err != nil {
		t.Fatalf("event.SignCheckpoint(): %v", err)
	}
	voterIDs := make([]domain.DeviceID, len(target))
	for index, signer := range target {
		voterIDs[index] = signer.id
	}
	proofs := make([]Proof, len(target))
	for index, signer := range target {
		proofs[index] = mustSignProof(t, ProofInput{
			SessionID:                       testSessionID,
			WorkspaceID:                     testWorkspace,
			RecoveryGeneration:              4,
			TargetVoterSetVersion:           3,
			CurrentAuthorityVoterSetVersion: 2,
			VoterSet:                        voterIDs,
			VoterDeviceID:                   signer.id,
			LiveConfigurationIndex:          30,
			CheckpointEventID:               testCheckpoint,
			Checkpoint:                      checkpoint,
			CheckpointSignature:             checkpointSignature,
		}, signer.private)
	}
	handoff, err := NewUnsignedAuthorityHandoff(AuthorityHandoffInput{
		SessionID:                        testSessionID,
		WorkspaceID:                      testWorkspace,
		RecoveryGeneration:               4,
		TargetVoterSetVersion:            3,
		ExpectedAuthorityVoterSetVersion: 2,
		VoterSet:                         voterIDs,
		ActivationCheckpointEventID:      testCheckpoint,
		ActivationProofs:                 proofs,
		PriorAuthoritySigner:             prior.id,
	})
	if err != nil {
		t.Fatalf("NewUnsignedAuthorityHandoff(): %v", err)
	}
	payload, err := SignAuthorityHandoff(handoff, prior.private)
	if err != nil {
		t.Fatalf("SignAuthorityHandoff(): %v", err)
	}
	return activationFixture{
		target:     target,
		prior:      prior,
		checkpoint: checkpoint,
		proofs:     proofs,
		handoff:    handoff,
		payload:    payload,
	}
}

func newTestSigner(t *testing.T, fill byte) testSigner {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	text, err := codec.DeriveDeviceID(public)
	if err != nil {
		t.Fatalf("codec.DeriveDeviceID(): %v", err)
	}
	return testSigner{
		id:      domain.DeviceID(text),
		private: bytes.Clone(private),
		public:  bytes.Clone(public),
	}
}

func mustSignProof(
	t *testing.T,
	input ProofInput,
	private ed25519.PrivateKey,
) Proof {
	t.Helper()
	unsigned, err := NewUnsignedProof(input)
	if err != nil {
		t.Fatalf("NewUnsignedProof(): %v", err)
	}
	proof, err := SignProof(unsigned, private)
	if err != nil {
		t.Fatalf("SignProof(): %v", err)
	}
	return proof
}

func keyForID(
	signers []testSigner,
	id domain.DeviceID,
) ed25519.PrivateKey {
	for _, signer := range signers {
		if signer.id == id {
			return signer.private
		}
	}
	return nil
}

func fillDigest(destination *[32]byte, fill byte) {
	copy(destination[:], bytes.Repeat([]byte{fill}, len(destination)))
}

func cloneProofInput(input ProofInput) ProofInput {
	input.VoterSet = cloneDeviceIDs(input.VoterSet)
	return input
}

func cloneAuthorityInput(input AuthorityHandoffInput) AuthorityHandoffInput {
	input.VoterSet = cloneDeviceIDs(input.VoterSet)
	input.ActivationProofs = append([]Proof(nil), input.ActivationProofs...)
	return input
}

func assertExactFields(
	t *testing.T,
	encoded []byte,
	expected map[string]struct{},
) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	if len(object) != len(expected) {
		t.Fatalf("field count = %d, want %d", len(object), len(expected))
	}
	for field := range expected {
		if _, exists := object[field]; !exists {
			t.Fatalf("missing field %q", field)
		}
	}
}

func mutateObject(
	t *testing.T,
	encoded []byte,
	set string,
	value json.RawMessage,
	remove string,
) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	if set != "" {
		object[set] = bytes.Clone(value)
	}
	if remove != "" {
		delete(object, remove)
	}
	result, err := marshalCanonical(object)
	if err != nil {
		t.Fatalf("marshalCanonical(): %v", err)
	}
	return result
}

func parseUnsignedProofError(encoded []byte) error {
	_, err := ParseUnsignedProof(encoded)
	return err
}

func parseProofError(encoded []byte) error {
	_, err := ParseProof(encoded)
	return err
}

func parseHandoffError(encoded []byte) error {
	_, err := ParseUnsignedAuthorityHandoff(encoded)
	return err
}

func parsePayloadError(encoded []byte) error {
	_, err := DecodeActivationPayload(encoded)
	return err
}
