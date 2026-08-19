package replication

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func TestBatchCanonicalRoundTripAndSignature(t *testing.T) {
	t.Parallel()

	input, privateKey := validBatchInput(t)
	unsigned, err := NewUnsignedBatch(input)
	if err != nil {
		t.Fatalf("NewUnsignedBatch() error = %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(
		unsigned.CanonicalBytes(),
	)
	if err != nil || !bytes.Equal(canonical, unsigned.CanonicalBytes()) {
		t.Fatalf(
			"unsigned batch is not canonical: canonical=%s err=%v",
			canonical,
			err,
		)
	}
	batch, err := SignBatch(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignBatch() error = %v", err)
	}
	signature := batch.Signature()
	if encoded := codec.EncodeBase64URL(signature[:]); len(encoded) !=
		batchSignatureTextBytes {
		t.Fatalf(
			"encoded signature length = %d, want %d",
			len(encoded),
			batchSignatureTextBytes,
		)
	}
	if got, want := len(batch.CanonicalBytes()),
		completeBatchSize(len(unsigned.CanonicalBytes())); got != want {
		t.Fatalf("complete batch size = %d, want %d", got, want)
	}
	parsed, err := ParseBatch(batch.CanonicalBytes())
	if err != nil {
		t.Fatalf("ParseBatch() error = %v", err)
	}
	if !bytes.Equal(parsed.CanonicalBytes(), batch.CanonicalBytes()) ||
		!bytes.Equal(
			parsed.Unsigned().CanonicalBytes(),
			unsigned.CanonicalBytes(),
		) {
		t.Fatal("parsed batch changed canonical bytes")
	}
	if err := VerifyBatch(
		parsed,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatalf("VerifyBatch() error = %v", err)
	}

	const prefix = `{"batch_signature":`
	if !bytes.HasPrefix(batch.CanonicalBytes(), []byte(prefix)) {
		t.Fatalf("complete batch does not begin with %q", prefix)
	}
	for _, excluded := range [][]byte{
		[]byte(`"previous_result_hash"`),
		[]byte(`"result_hash"`),
	} {
		if bytes.Contains(unsigned.CanonicalBytes(), excluded) {
			t.Errorf("batch command-result record contains %q", excluded)
		}
	}
}

func TestBatchValuesDoNotAliasCallerStorage(t *testing.T) {
	t.Parallel()

	input, privateKey := validBatchInput(t)
	unsigned, err := NewUnsignedBatch(input)
	if err != nil {
		t.Fatalf("NewUnsignedBatch() error = %v", err)
	}
	pristine := unsigned.CanonicalBytes()
	input.Results[0][0] ^= 0xff
	if !bytes.Equal(unsigned.CanonicalBytes(), pristine) {
		t.Fatal("unsigned batch aliases input result bytes")
	}

	returned := unsigned.Input()
	returned.Results[0][0] ^= 0xff
	returned.Results = nil
	if !bytes.Equal(unsigned.CanonicalBytes(), pristine) {
		t.Fatal("unsigned batch aliases returned input")
	}

	batch, err := SignBatch(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignBatch() error = %v", err)
	}
	complete := batch.CanonicalBytes()
	complete[0] ^= 0xff
	if batch.CanonicalBytes()[0] != '{' {
		t.Fatal("CanonicalBytes() aliases complete batch storage")
	}
	clone := batch.Unsigned()
	cloneBytes := clone.CanonicalBytes()
	cloneBytes[0] ^= 0xff
	if batch.Unsigned().CanonicalBytes()[0] != '{' {
		t.Fatal("Unsigned() aliases batch storage")
	}
}

func TestBatchRejectsInvalidRangesAndLinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*BatchInput)
	}{
		{
			name: "zero from",
			mutate: func(input *BatchInput) {
				input.FromResultIndex = 0
			},
		},
		{
			name: "count mismatch",
			mutate: func(input *BatchInput) {
				input.ToResultIndex++
			},
		},
		{
			name: "result gap",
			mutate: func(input *BatchInput) {
				input.Results[1] = resultAtIndex(
					t,
					8,
					nil,
					nil,
					`{"code":"task_not_ready","status":"rejected"}`,
				)
			},
		},
		{
			name: "wrong start result head",
			mutate: func(input *BatchInput) {
				input.StartResultHash[0] ^= 0xff
			},
		},
		{
			name: "wrong end result head",
			mutate: func(input *BatchInput) {
				input.EndResultHash[0] ^= 0xff
			},
		},
		{
			name: "wrong start event head",
			mutate: func(input *BatchInput) {
				input.StartChainHash[0] ^= 0xff
			},
		},
		{
			name: "wrong end event position",
			mutate: func(input *BatchInput) {
				input.EndChainIndex = input.StartChainIndex
			},
		},
		{
			name: "server behind batch",
			mutate: func(input *BatchInput) {
				input.ServerAppliedResultIndex = input.ToResultIndex - 1
			},
		},
		{
			name: "zero authority version",
			mutate: func(input *BatchInput) {
				input.ServerAuthorityVersion = 0
			},
		},
		{
			name: "too many records",
			mutate: func(input *BatchInput) {
				input.Results = make([][]byte, MaxBatchResults+1)
				input.ToResultIndex =
					input.FromResultIndex + MaxBatchResults
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			input, _ := validBatchInput(t)
			test.mutate(&input)
			if _, err := NewUnsignedBatch(input); !errors.Is(
				err,
				ErrInvalidBatch,
			) {
				t.Fatalf(
					"NewUnsignedBatch() error = %v, want ErrInvalidBatch",
					err,
				)
			}
		})
	}
}

func TestParseBatchRejectsMalformedOrNoncanonicalObjects(t *testing.T) {
	t.Parallel()

	input, privateKey := validBatchInput(t)
	unsigned, err := NewUnsignedBatch(input)
	if err != nil {
		t.Fatalf("NewUnsignedBatch() error = %v", err)
	}
	batch, err := SignBatch(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignBatch() error = %v", err)
	}
	valid := batch.CanonicalBytes()
	duplicate := append(bytes.Clone(valid[:len(valid)-1]),
		[]byte(`,"workspace_id":"018f0000-0000-4000-8000-000000000001"}`)...)
	resultsMarker := bytes.Index(valid, []byte(`"results":[`))
	if resultsMarker < 0 {
		t.Fatal("valid batch omits results marker")
	}
	resultsStart := resultsMarker + len(`"results":[`)
	resultsSuffix := bytes.Index(
		valid[resultsStart:],
		[]byte(`],"server_applied_result_index"`),
	)
	if resultsSuffix < 0 {
		t.Fatal("valid batch omits results suffix")
	}
	resultsEnd := resultsStart + resultsSuffix
	tooManyResults := bytes.Clone(valid[:resultsStart])
	for index := 0; index <= MaxBatchResults; index++ {
		if index != 0 {
			tooManyResults = append(tooManyResults, ',')
		}
		tooManyResults = append(tooManyResults, input.Results[0]...)
	}
	tooManyResults = append(tooManyResults, valid[resultsEnd:]...)

	tests := []struct {
		name  string
		value []byte
		want  error
	}{
		{name: "empty", value: nil, want: ErrInvalidBatch},
		{name: "trailing", value: append(bytes.Clone(valid), 'x'), want: ErrInvalidBatch},
		{
			name: "unknown field",
			value: bytes.Replace(
				valid,
				[]byte(`,"workspace_id":`),
				[]byte(`,"unknown":1,"workspace_id":`),
				1,
			),
			want: ErrInvalidBatch,
		},
		{
			name:  "duplicate field",
			value: duplicate,
			want:  ErrInvalidBatch,
		},
		{name: "more than 256 results", value: tooManyResults, want: ErrInvalidBatch},
		{
			name:  "whitespace",
			value: append([]byte(" "), valid...),
			want:  ErrNoncanonicalBatch,
		},
		{
			name: "padded signature",
			value: bytes.Replace(
				valid,
				[]byte(`","end_chain_hash"`),
				[]byte(`=","end_chain_hash"`),
				1,
			),
			want: ErrInvalidBatch,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseBatch(test.value); !errors.Is(err, test.want) {
				t.Fatalf("ParseBatch() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyBatchBindsSignatureAndServerIdentity(t *testing.T) {
	t.Parallel()

	input, privateKey := validBatchInput(t)
	unsigned, err := NewUnsignedBatch(input)
	if err != nil {
		t.Fatalf("NewUnsignedBatch() error = %v", err)
	}
	batch, err := SignBatch(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignBatch() error = %v", err)
	}

	otherPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, 32))
	if err := VerifyBatch(
		batch,
		otherPrivate.Public().(ed25519.PublicKey),
	); !errors.Is(err, ErrSignerMismatch) {
		t.Fatalf("VerifyBatch(other identity) error = %v, want ErrSignerMismatch", err)
	}
	otherID, err := device.DeriveID(
		otherPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("DeriveID(other): %v", err)
	}
	changedInput := unsigned.Input()
	changedInput.ServerDeviceID = otherID
	changed, err := NewUnsignedBatch(changedInput)
	if err != nil {
		t.Fatalf("NewUnsignedBatch(changed signer): %v", err)
	}
	if _, err := SignBatch(
		changed,
		privateKey,
	); !errors.Is(err, ErrSignerMismatch) {
		t.Fatalf("SignBatch(wrong key) error = %v, want ErrSignerMismatch", err)
	}

	tampered := bytes.Replace(
		batch.CanonicalBytes(),
		[]byte(`"server_authority_version":4`),
		[]byte(`"server_authority_version":5`),
		1,
	)
	parsed, err := ParseBatch(tampered)
	if err != nil {
		t.Fatalf("ParseBatch(tampered signed field): %v", err)
	}
	if err := VerifyBatch(
		parsed,
		privateKey.Public().(ed25519.PublicKey),
	); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf(
			"VerifyBatch(tampered) error = %v, want ErrSignatureInvalid",
			err,
		)
	}
}

func validBatchInput(t *testing.T) (BatchInput, ed25519.PrivateKey) {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, 32))
	serverID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("DeriveID(): %v", err)
	}
	startResult := filledDigest(0x11)
	startChain := filledDigest(0x22)
	firstProposal := []byte(
		`{"event_id":"018f0000-0000-7000-8000-000000000005","kind":"task.created","origin_signature":"AA","sequence":5}`,
	)
	firstChain, err := chain.AppendEvent(startChain, firstProposal)
	if err != nil {
		t.Fatalf("AppendEvent(): %v", err)
	}
	firstIndex := uint64(3)
	first := resultAtIndexWithProposal(
		t,
		5,
		&firstIndex,
		&firstChain,
		firstProposal,
		`{"code":"accepted","status":"accepted"}`,
	)
	firstResult, _, err := chain.AppendResult(startResult, mustDecodeResult(t, first))
	if err != nil {
		t.Fatalf("AppendResult(first): %v", err)
	}
	second := resultAtIndex(
		t,
		6,
		nil,
		nil,
		`{"code":"task_not_ready","status":"rejected"}`,
	)
	endResult, _, err := chain.AppendResult(firstResult, mustDecodeResult(t, second))
	if err != nil {
		t.Fatalf("AppendResult(second): %v", err)
	}
	return BatchInput{
		FromResultIndex:          5,
		ToResultIndex:            6,
		StartResultHash:          startResult,
		EndResultHash:            endResult,
		StartChainIndex:          2,
		StartChainHash:           startChain,
		EndChainIndex:            3,
		EndChainHash:             firstChain,
		Results:                  [][]byte{first, second},
		SessionID:                "018f0000-0000-7000-8000-000000000001",
		WorkspaceID:              "018f0000-0000-4000-8000-000000000001",
		RecoveryGeneration:       2,
		ServerDeviceID:           serverID,
		ServerAppliedResultIndex: 9,
		ServerAuthorityVersion:   4,
	}, privateKey
}

func resultAtIndex(
	t *testing.T,
	resultIndex uint64,
	chainIndex *uint64,
	chainHash *chain.Digest,
	outcome string,
) []byte {
	t.Helper()
	proposal := []byte(
		`{"event_id":"018f0000-0000-7000-8000-000000000006","kind":"task.claimed","origin_signature":"AQ","sequence":6}`,
	)
	return resultAtIndexWithProposal(
		t,
		resultIndex,
		chainIndex,
		chainHash,
		proposal,
		outcome,
	)
}

func resultAtIndexWithProposal(
	t *testing.T,
	resultIndex uint64,
	chainIndex *uint64,
	chainHash *chain.Digest,
	proposal []byte,
	outcome string,
) []byte {
	t.Helper()
	encoded, err := chain.EncodeResult(chain.Result{
		ResultIndex:    resultIndex,
		Proposal:       proposal,
		Outcome:        []byte(outcome),
		ProposalDigest: chain.Digest(sha256.Sum256(proposal)),
		ChainIndex:     chainIndex,
		ChainHash:      chainHash,
	})
	if err != nil {
		t.Fatalf("EncodeResult(%d): %v", resultIndex, err)
	}
	return encoded
}

func mustDecodeResult(t *testing.T, encoded []byte) chain.Result {
	t.Helper()
	result, err := chain.DecodeResult(encoded)
	if err != nil {
		t.Fatalf("DecodeResult(): %v", err)
	}
	return result
}

func filledDigest(value byte) chain.Digest {
	var result chain.Digest
	for index := range result {
		result[index] = value
	}
	return result
}
