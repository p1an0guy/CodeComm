package replication

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func TestAcknowledgementCanonicalGoldenRoundTripAndSignature(t *testing.T) {
	t.Parallel()

	input, privateKey := validAcknowledgementInput(t)
	unsigned, err := NewUnsignedAcknowledgement(input)
	if err != nil {
		t.Fatalf("NewUnsignedAcknowledgement() error = %v", err)
	}
	const wantUnsigned = `{"chain_hash":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","chain_index":7,"object_kind":"replication_acknowledgement","projection_accumulator":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM","projection_state_digest":"REREREREREREREREREREREREREREREREREREREREREQ","recovery_generation":2,"result_hash":"ERERERERERERERERERERERERERERERERERERERERERE","result_index":11,"server_applied_result_index":11,"server_authority_version":4,"server_device_id":"cc14b735ac174e40636507716ed5c9a8a75fbf6f462357fabb71ac42b7bd502c64a","session_id":"018f0000-0000-7000-8000-000000000001","workspace_id":"018f0000-0000-4000-8000-000000000001"}`
	if got := string(unsigned.CanonicalBytes()); got != wantUnsigned {
		t.Fatalf("unsigned canonical bytes:\n got: %s\nwant: %s", got, wantUnsigned)
	}
	canonical, err := codec.CanonicalizeSignedObject(
		unsigned.CanonicalBytes(),
	)
	if err != nil || !bytes.Equal(canonical, unsigned.CanonicalBytes()) {
		t.Fatalf("unsigned acknowledgement is not canonical: %v", err)
	}

	acknowledgement, err := SignAcknowledgement(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignAcknowledgement() error = %v", err)
	}
	if !acknowledgement.MatchesUnsigned(unsigned) {
		t.Fatal("signed acknowledgement changed its preimage")
	}
	const wantComplete = `{"acknowledgement_signature":"AfdGDGWn5TDXQYEWKZrGeNvM6bv81-DEe3BQjUJ_3ZLYDnbpiYmmGMIYgvoIUPjziXIWbCwdzc27rynKOGqYDA","chain_hash":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","chain_index":7,"object_kind":"replication_acknowledgement","projection_accumulator":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM","projection_state_digest":"REREREREREREREREREREREREREREREREREREREREREQ","recovery_generation":2,"result_hash":"ERERERERERERERERERERERERERERERERERERERERERE","result_index":11,"server_applied_result_index":11,"server_authority_version":4,"server_device_id":"cc14b735ac174e40636507716ed5c9a8a75fbf6f462357fabb71ac42b7bd502c64a","session_id":"018f0000-0000-7000-8000-000000000001","workspace_id":"018f0000-0000-4000-8000-000000000001"}`
	if got := string(acknowledgement.CanonicalBytes()); got != wantComplete {
		t.Fatalf("complete canonical bytes:\n got: %s\nwant: %s", got, wantComplete)
	}
	const wantAttestationID = "acknowledgement:eIhpuHIejOSBZm74KXQ7DETX8jIVyKh7jk8jbu_q0WM"
	if got := acknowledgement.AttestationID(); got != wantAttestationID {
		t.Fatalf("AttestationID() = %q, want %q", got, wantAttestationID)
	}

	metadata := unsigned.Metadata()
	if metadata.ObjectKind != AcknowledgementObjectKind ||
		metadata.SessionID != input.SessionID ||
		metadata.WorkspaceID != input.WorkspaceID ||
		metadata.RecoveryGeneration != input.RecoveryGeneration ||
		metadata.ServerDeviceID != input.ServerDeviceID ||
		metadata.ServerAuthorityVersion != input.ServerAuthorityVersion ||
		metadata.ResultIndex != input.ResultIndex ||
		metadata.ResultHash != input.ResultHash ||
		metadata.ChainIndex != input.ChainIndex ||
		metadata.ChainHash != input.ChainHash ||
		metadata.ProjectionAccumulator != input.ProjectionAccumulator ||
		metadata.ProjectionStateDigest != input.ProjectionStateDigest ||
		metadata.ServerAppliedResultIndex !=
			input.ServerAppliedResultIndex {
		t.Fatalf("Metadata() = %+v", metadata)
	}

	parsed, err := ParseAcknowledgement(acknowledgement.CanonicalBytes())
	if err != nil {
		t.Fatalf("ParseAcknowledgement() error = %v", err)
	}
	if !bytes.Equal(
		parsed.CanonicalBytes(),
		acknowledgement.CanonicalBytes(),
	) || !bytes.Equal(
		parsed.Unsigned().CanonicalBytes(),
		unsigned.CanonicalBytes(),
	) {
		t.Fatal("parsed acknowledgement changed canonical bytes")
	}
	if err := VerifyAcknowledgement(
		parsed,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatalf("VerifyAcknowledgement() error = %v", err)
	}
}

func TestAcknowledgementTamperInvalidatesSignature(t *testing.T) {
	t.Parallel()

	acknowledgement, privateKey := signedAcknowledgement(t)
	tampered := bytes.Replace(
		acknowledgement.CanonicalBytes(),
		[]byte(`"server_authority_version":4`),
		[]byte(`"server_authority_version":5`),
		1,
	)
	parsed, err := ParseAcknowledgement(tampered)
	if err != nil {
		t.Fatalf("ParseAcknowledgement(tampered) error = %v", err)
	}
	if err := VerifyAcknowledgement(
		parsed,
		privateKey.Public().(ed25519.PublicKey),
	); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf(
			"VerifyAcknowledgement(tampered) error = %v, want %v",
			err,
			ErrSignatureInvalid,
		)
	}

	changedInput := acknowledgement.Unsigned().Input()
	changedInput.ProjectionStateDigest[0] ^= 0xff
	changedUnsigned, err := NewUnsignedAcknowledgement(changedInput)
	if err != nil {
		t.Fatalf("NewUnsignedAcknowledgement(changed digest): %v", err)
	}
	changed, err := NewAcknowledgement(
		changedUnsigned,
		acknowledgement.Signature(),
	)
	if err != nil {
		t.Fatalf("NewAcknowledgement(changed digest): %v", err)
	}
	if err := VerifyAcknowledgement(
		changed,
		privateKey.Public().(ed25519.PublicKey),
	); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf(
			"VerifyAcknowledgement(changed digest) error = %v, want %v",
			err,
			ErrSignatureInvalid,
		)
	}
}

func TestParseAcknowledgementRejectsMalformedNoncanonicalAndOpenObjects(
	t *testing.T,
) {
	t.Parallel()

	acknowledgement, _ := signedAcknowledgement(t)
	valid := acknowledgement.CanonicalBytes()
	duplicate := append(
		bytes.Clone(valid[:len(valid)-1]),
		[]byte(`,"workspace_id":"018f0000-0000-4000-8000-000000000001"}`)...,
	)
	missing := bytes.Replace(
		valid,
		[]byte(`,"result_index":11`),
		nil,
		1,
	)
	const chainFields = `"chain_hash":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","chain_index":7`
	const reorderedChainFields = `"chain_index":7,"chain_hash":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"`

	tests := []struct {
		name  string
		value []byte
		want  error
	}{
		{name: "empty", value: nil, want: ErrInvalidAcknowledgement},
		{
			name:  "trailing data",
			value: append(bytes.Clone(valid), 'x'),
			want:  ErrInvalidAcknowledgement,
		},
		{
			name: "unknown field",
			value: bytes.Replace(
				valid,
				[]byte(`,"workspace_id":`),
				[]byte(`,"unknown":1,"workspace_id":`),
				1,
			),
			want: ErrInvalidAcknowledgement,
		},
		{
			name:  "duplicate field",
			value: duplicate,
			want:  ErrInvalidAcknowledgement,
		},
		{
			name:  "missing field",
			value: missing,
			want:  ErrInvalidAcknowledgement,
		},
		{
			name: "null field",
			value: bytes.Replace(
				valid,
				[]byte(`"result_index":11`),
				[]byte(`"result_index":null`),
				1,
			),
			want: ErrInvalidAcknowledgement,
		},
		{
			name: "wrong object kind",
			value: bytes.Replace(
				valid,
				[]byte(AcknowledgementObjectKind),
				[]byte("replication_batch__________"),
				1,
			),
			want: ErrInvalidAcknowledgement,
		},
		{
			name:  "leading whitespace",
			value: append([]byte(" "), valid...),
			want:  ErrNoncanonicalAcknowledgement,
		},
		{
			name: "noncanonical field order",
			value: bytes.Replace(
				valid,
				[]byte(chainFields),
				[]byte(reorderedChainFields),
				1,
			),
			want: ErrNoncanonicalAcknowledgement,
		},
		{
			name: "short digest",
			value: bytes.Replace(
				valid,
				[]byte(`"result_hash":"ERERERERERERERERERERERERERERERERERERERERERE"`),
				[]byte(`"result_hash":"ERER"`),
				1,
			),
			want: ErrInvalidAcknowledgement,
		},
		{
			name: "padded digest",
			value: bytes.Replace(
				valid,
				[]byte(`"result_hash":"ERERERERERERERERERERERERERERERERERERERERERE"`),
				[]byte(`"result_hash":"ERERERERERERERERERERERERERERERERERERERERERE="`),
				1,
			),
			want: ErrInvalidAcknowledgement,
		},
		{
			name: "I-JSON overflow",
			value: bytes.Replace(
				valid,
				[]byte(`"server_applied_result_index":11`),
				[]byte(`"server_applied_result_index":9007199254740992`),
				1,
			),
			want: ErrInvalidAcknowledgement,
		},
		{
			name: "padded signature",
			value: bytes.Replace(
				valid,
				[]byte(`","chain_hash"`),
				[]byte(`=","chain_hash"`),
				1,
			),
			want: ErrInvalidAcknowledgement,
		},
		{
			name:  "oversized",
			value: bytes.Repeat([]byte{' '}, MaxAcknowledgementBytes+1),
			want:  ErrAcknowledgementTooLarge,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseAcknowledgement(test.value); !errors.Is(
				err,
				test.want,
			) {
				t.Fatalf(
					"ParseAcknowledgement() error = %v, want %v",
					err,
					test.want,
				)
			}
		})
	}
}

func TestAcknowledgementBindsSignerIdentity(t *testing.T) {
	t.Parallel()

	input, privateKey := validAcknowledgementInput(t)
	unsigned, err := NewUnsignedAcknowledgement(input)
	if err != nil {
		t.Fatalf("NewUnsignedAcknowledgement() error = %v", err)
	}
	otherPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, 32))
	if _, err := SignAcknowledgement(
		unsigned,
		otherPrivate,
	); !errors.Is(err, ErrSignerMismatch) {
		t.Fatalf(
			"SignAcknowledgement(other identity) error = %v, want %v",
			err,
			ErrSignerMismatch,
		)
	}
	acknowledgement, err := SignAcknowledgement(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignAcknowledgement() error = %v", err)
	}
	if err := VerifyAcknowledgement(
		acknowledgement,
		otherPrivate.Public().(ed25519.PublicKey),
	); !errors.Is(err, ErrSignerMismatch) {
		t.Fatalf(
			"VerifyAcknowledgement(other identity) error = %v, want %v",
			err,
			ErrSignerMismatch,
		)
	}
}

func TestAcknowledgementRejectsInvalidIDsAndNumericBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*AcknowledgementInput)
	}{
		{
			name: "invalid session ID",
			mutate: func(input *AcknowledgementInput) {
				input.SessionID = "018f0000-0000-4000-8000-000000000001"
			},
		},
		{
			name: "invalid workspace ID",
			mutate: func(input *AcknowledgementInput) {
				input.WorkspaceID = "018f0000-0000-7000-8000-000000000001"
			},
		},
		{
			name: "invalid server device ID",
			mutate: func(input *AcknowledgementInput) {
				input.ServerDeviceID = "cc1ABC"
			},
		},
		{
			name: "recovery generation exceeds I-JSON",
			mutate: func(input *AcknowledgementInput) {
				input.RecoveryGeneration = domain.MaxSafeInteger + 1
			},
		},
		{
			name: "result index exceeds I-JSON",
			mutate: func(input *AcknowledgementInput) {
				input.ResultIndex = domain.MaxSafeInteger + 1
				input.ServerAppliedResultIndex = input.ResultIndex
			},
		},
		{
			name: "chain index exceeds I-JSON",
			mutate: func(input *AcknowledgementInput) {
				input.ChainIndex = domain.MaxSafeInteger + 1
				input.ResultIndex = input.ChainIndex
				input.ServerAppliedResultIndex = input.ResultIndex
			},
		},
		{
			name: "authority version exceeds I-JSON",
			mutate: func(input *AcknowledgementInput) {
				input.ServerAuthorityVersion = domain.MaxSafeInteger + 1
			},
		},
		{
			name: "applied result index exceeds I-JSON",
			mutate: func(input *AcknowledgementInput) {
				input.ServerAppliedResultIndex = domain.MaxSafeInteger + 1
			},
		},
		{
			name: "zero authority version",
			mutate: func(input *AcknowledgementInput) {
				input.ServerAuthorityVersion = 0
			},
		},
		{
			name: "server behind acknowledged result",
			mutate: func(input *AcknowledgementInput) {
				input.ServerAppliedResultIndex = input.ResultIndex - 1
			},
		},
		{
			name: "server ahead of acknowledged result",
			mutate: func(input *AcknowledgementInput) {
				input.ServerAppliedResultIndex = input.ResultIndex + 1
			},
		},
		{
			name: "chain ahead of result",
			mutate: func(input *AcknowledgementInput) {
				input.ChainIndex = input.ResultIndex + 1
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input, _ := validAcknowledgementInput(t)
			test.mutate(&input)
			if _, err := NewUnsignedAcknowledgement(input); !errors.Is(
				err,
				ErrInvalidAcknowledgement,
			) {
				t.Fatalf(
					"NewUnsignedAcknowledgement() error = %v, want %v",
					err,
					ErrInvalidAcknowledgement,
				)
			}
		})
	}
}

func TestAcknowledgementAcceptsGenesisAndIJSONBoundaries(t *testing.T) {
	t.Parallel()

	input, _ := validAcknowledgementInput(t)
	input.RecoveryGeneration = 0
	input.ResultIndex = 0
	input.ChainIndex = 0
	input.ServerAppliedResultIndex = 0
	if _, err := NewUnsignedAcknowledgement(input); err != nil {
		t.Fatalf("NewUnsignedAcknowledgement(genesis) error = %v", err)
	}

	input.RecoveryGeneration = domain.MaxSafeInteger
	input.ResultIndex = domain.MaxSafeInteger
	input.ChainIndex = domain.MaxSafeInteger
	input.ServerAppliedResultIndex = domain.MaxSafeInteger
	input.ServerAuthorityVersion = domain.MaxSafeInteger
	if _, err := NewUnsignedAcknowledgement(input); err != nil {
		t.Fatalf("NewUnsignedAcknowledgement(maximums) error = %v", err)
	}
}

func TestAcknowledgementValuesAreDefensivelyCopied(t *testing.T) {
	t.Parallel()

	input, privateKey := validAcknowledgementInput(t)
	unsigned, err := NewUnsignedAcknowledgement(input)
	if err != nil {
		t.Fatalf("NewUnsignedAcknowledgement() error = %v", err)
	}
	unsignedBytes := unsigned.CanonicalBytes()
	unsignedBytes[0] ^= 0xff
	if unsigned.CanonicalBytes()[0] != '{' {
		t.Fatal("unsigned CanonicalBytes() aliases internal storage")
	}
	returnedInput := unsigned.Input()
	returnedInput.ResultHash[0] ^= 0xff
	if unsigned.Input().ResultHash != input.ResultHash {
		t.Fatal("Input() aliases acknowledgement digest storage")
	}
	metadata := unsigned.Metadata()
	metadata.ProjectionAccumulator[0] ^= 0xff
	if unsigned.Metadata().ProjectionAccumulator !=
		input.ProjectionAccumulator {
		t.Fatal("Metadata() aliases acknowledgement digest storage")
	}

	acknowledgement, err := SignAcknowledgement(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignAcknowledgement() error = %v", err)
	}
	complete := acknowledgement.CanonicalBytes()
	complete[0] ^= 0xff
	if acknowledgement.CanonicalBytes()[0] != '{' {
		t.Fatal("signed CanonicalBytes() aliases internal storage")
	}
	clone := acknowledgement.Unsigned()
	clone.canonical[0] ^= 0xff
	if acknowledgement.Unsigned().CanonicalBytes()[0] != '{' {
		t.Fatal("Unsigned() aliases signed acknowledgement storage")
	}
	signature := acknowledgement.Signature()
	wantSignatureByte := signature[0]
	signature[0] ^= 0xff
	if acknowledgement.Signature()[0] != wantSignatureByte {
		t.Fatal("Signature() aliases acknowledgement storage")
	}
}

func TestAcknowledgementAttestationIDBindsCompleteSignature(t *testing.T) {
	t.Parallel()

	acknowledgement, _ := signedAcknowledgement(t)
	same, err := ParseAcknowledgement(acknowledgement.CanonicalBytes())
	if err != nil {
		t.Fatalf("ParseAcknowledgement() error = %v", err)
	}
	if same.AttestationID() != acknowledgement.AttestationID() {
		t.Fatal("equal signed values have different attestation IDs")
	}
	signature := acknowledgement.Signature()
	signature[0] ^= 0xff
	changed, err := NewAcknowledgement(acknowledgement.Unsigned(), signature)
	if err != nil {
		t.Fatalf("NewAcknowledgement(changed signature) error = %v", err)
	}
	if changed.AttestationID() == acknowledgement.AttestationID() {
		t.Fatal("attestation ID does not bind the signature")
	}
}

func TestAcknowledgementZeroValuesFailClosed(t *testing.T) {
	t.Parallel()

	var unsigned UnsignedAcknowledgement
	if unsigned.CanonicalBytes() != nil ||
		unsigned.Metadata() != (AcknowledgementMetadata{}) {
		t.Fatal("zero unsigned acknowledgement exposes data")
	}
	if _, err := NewAcknowledgement(
		unsigned,
		[ed25519.SignatureSize]byte{},
	); !errors.Is(err, ErrInvalidAcknowledgement) {
		t.Fatalf("NewAcknowledgement(zero) error = %v", err)
	}

	var acknowledgement Acknowledgement
	if acknowledgement.CanonicalBytes() != nil ||
		acknowledgement.AttestationID() != "" ||
		acknowledgement.Unsigned().CanonicalBytes() != nil {
		t.Fatal("zero signed acknowledgement exposes data")
	}
	if err := VerifyAcknowledgement(
		acknowledgement,
		make([]byte, ed25519.PublicKeySize),
	); !errors.Is(err, ErrInvalidAcknowledgement) {
		t.Fatalf("VerifyAcknowledgement(zero) error = %v", err)
	}
}

func validAcknowledgementInput(
	t *testing.T,
) (AcknowledgementInput, ed25519.PrivateKey) {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, 32))
	serverID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("DeriveID(): %v", err)
	}
	return AcknowledgementInput{
		SessionID:                "018f0000-0000-7000-8000-000000000001",
		WorkspaceID:              "018f0000-0000-4000-8000-000000000001",
		RecoveryGeneration:       2,
		ServerDeviceID:           serverID,
		ServerAuthorityVersion:   4,
		ResultIndex:              11,
		ResultHash:               acknowledgementDigest(0x11),
		ChainIndex:               7,
		ChainHash:                acknowledgementDigest(0x22),
		ProjectionAccumulator:    acknowledgementDigest(0x33),
		ProjectionStateDigest:    acknowledgementDigest(0x44),
		ServerAppliedResultIndex: 11,
	}, privateKey
}

func signedAcknowledgement(
	t *testing.T,
) (Acknowledgement, ed25519.PrivateKey) {
	t.Helper()

	input, privateKey := validAcknowledgementInput(t)
	unsigned, err := NewUnsignedAcknowledgement(input)
	if err != nil {
		t.Fatalf("NewUnsignedAcknowledgement() error = %v", err)
	}
	return mustSignAcknowledgement(t, unsigned, privateKey), privateKey
}

func mustSignAcknowledgement(
	t *testing.T,
	unsigned UnsignedAcknowledgement,
	privateKey ed25519.PrivateKey,
) Acknowledgement {
	t.Helper()

	acknowledgement, err := SignAcknowledgement(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignAcknowledgement() error = %v", err)
	}
	return acknowledgement
}

func acknowledgementDigest(value byte) [sha256.Size]byte {
	var digest [sha256.Size]byte
	for index := range digest {
		digest[index] = value
	}
	return digest
}

func TestAcknowledgementObjectKindPreventsBatchConfusion(t *testing.T) {
	t.Parallel()

	acknowledgement, _ := signedAcknowledgement(t)
	if !strings.Contains(
		string(acknowledgement.Unsigned().CanonicalBytes()),
		`"object_kind":"replication_acknowledgement"`,
	) {
		t.Fatal("signature preimage omits the acknowledgement object kind")
	}
	if _, err := ParseBatch(acknowledgement.CanonicalBytes()); !errors.Is(
		err,
		ErrInvalidBatch,
	) {
		t.Fatalf("ParseBatch(acknowledgement) error = %v", err)
	}
}
