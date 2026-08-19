package chain_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
)

func TestCommandResultGoldenVectors(t *testing.T) {
	t.Parallel()

	accepted := validAcceptedResult()
	encoded, err := chain.EncodeResult(accepted)
	if err != nil {
		t.Fatalf("EncodeResult(accepted) error = %v", err)
	}
	const wantAccepted = `{"chain_hash":"REREREREREREREREREREREREREREREREREREREREREQ","chain_index":1,"outcome":{"code":"accepted","status":"accepted"},"proposal":{"event_id":"018f0000-0000-7000-8000-000000000002","kind":"task.created","origin_signature":"AA","sequence":1},"proposal_digest":"I8ct7tSAgwS5lJjQCyHEecuY4PLO4dEBoMI2twtIzFw","result_index":3}`
	if string(encoded) != wantAccepted {
		t.Errorf("EncodeResult(accepted) = %s, want %s", encoded, wantAccepted)
	}
	assertResultDecode(t, []byte(wantAccepted), accepted)

	previous := filledDigest(0x55)
	head, appended, err := chain.AppendResult(previous, accepted)
	if err != nil {
		t.Fatalf("AppendResult(accepted) error = %v", err)
	}
	if !bytes.Equal(appended, encoded) {
		t.Fatalf("AppendResult() bytes = %s, EncodeResult() = %s", appended, encoded)
	}
	assertDigest(
		t,
		"accepted result append",
		head,
		"9c599467b66bffce292b921798934e7235388483fba17d70a2947d122f274156",
	)
	if want := manualDomainDigest(
		"codecomm/v1/result-chain",
		previous[:],
		encoded,
	); head != want {
		t.Fatalf("AppendResult() = %x, manual preimage = %x", head, want)
	}

	rejected := validRejectedResult()
	rejectedBytes, err := chain.EncodeResult(rejected)
	if err != nil {
		t.Fatalf("EncodeResult(rejected) error = %v", err)
	}
	const wantRejected = `{"chain_hash":null,"chain_index":null,"outcome":{"code":"task_not_ready","status":"rejected"},"proposal":{"event_id":"018f0000-0000-7000-8000-000000000003","kind":"task.claimed","origin_signature":"AQ","sequence":2},"proposal_digest":"Skj616_HhamVyR3sQTc5B4ym_-BROzook6B3pVK5oi8","result_index":4}`
	if string(rejectedBytes) != wantRejected {
		t.Errorf("EncodeResult(rejected) = %s, want %s", rejectedBytes, wantRejected)
	}
	assertResultDecode(t, []byte(wantRejected), rejected)
	rejectedHead, _, err := chain.AppendResult(head, rejected)
	if err != nil {
		t.Fatalf("AppendResult(rejected) error = %v", err)
	}
	assertDigest(
		t,
		"rejected result append",
		rejectedHead,
		"2489cf3f0194efd249436826622cd00af107462f9f0d75186d9606226e1379e3",
	)
	if want := manualDomainDigest(
		"codecomm/v1/result-chain",
		head[:],
		rejectedBytes,
	); rejectedHead != want {
		t.Fatalf(
			"AppendResult(rejected) = %x, manual preimage = %x",
			rejectedHead,
			want,
		)
	}

	for _, excluded := range [][]byte{
		[]byte("previous_result_hash"),
		[]byte(`"result_hash"`),
	} {
		if bytes.Contains(encoded, excluded) {
			t.Errorf("command result contains excluded field %q", excluded)
		}
	}
}

func TestDecodeResultRequiresExactCanonicalEncoding(t *testing.T) {
	t.Parallel()

	acceptedBytes, err := chain.EncodeResult(validAcceptedResult())
	if err != nil {
		t.Fatalf("EncodeResult(accepted) error = %v", err)
	}
	rejectedBytes, err := chain.EncodeResult(validRejectedResult())
	if err != nil {
		t.Fatalf("EncodeResult(rejected) error = %v", err)
	}
	accepted := string(acceptedBytes)
	rejected := string(rejectedBytes)

	tests := []struct {
		name  string
		input string
		also  error
	}{
		{name: "empty input"},
		{name: "not an object", input: `[]`},
		{
			name: "unknown member",
			input: strings.Replace(
				accepted,
				`"chain_index":1,`,
				`"chain_index":1,"extra":true,`,
				1,
			),
		},
		{
			name: "missing nullable member",
			input: strings.Replace(
				accepted,
				`"chain_hash":"REREREREREREREREREREREREREREREREREREREREREQ",`,
				"",
				1,
			),
		},
		{
			name: "missing nonnullable member",
			input: strings.Replace(
				accepted,
				`,"result_index":3`,
				"",
				1,
			),
		},
		{
			name: "duplicate member",
			input: strings.Replace(
				accepted,
				`"chain_index":1,`,
				`"chain_index":1,"chain_index":1,`,
				1,
			),
		},
		{name: "noncanonical whitespace", input: accepted + " "},
		{
			name: "noncanonical outcome",
			input: strings.Replace(
				accepted,
				`{"code":"accepted","status":"accepted"}`,
				`{"status":"accepted","code":"accepted"}`,
				1,
			),
		},
		{
			name: "noncanonical proposal",
			input: strings.Replace(
				accepted,
				`{"event_id":"018f0000-0000-7000-8000-000000000002","kind":"task.created","origin_signature":"AA","sequence":1}`,
				`{"kind":"task.created","event_id":"018f0000-0000-7000-8000-000000000002","origin_signature":"AA","sequence":1}`,
				1,
			),
		},
		{
			name: "fractional result index",
			input: strings.Replace(
				accepted,
				`"result_index":3`,
				`"result_index":3.0`,
				1,
			),
		},
		{
			name: "exponent chain index",
			input: strings.Replace(
				accepted,
				`"chain_index":1`,
				`"chain_index":1e0`,
				1,
			),
		},
		{
			name: "inexact result index",
			input: strings.Replace(
				accepted,
				`"result_index":3`,
				`"result_index":9007199254740992`,
				1,
			),
			also: chain.ErrInvalidIndex,
		},
		{
			name: "padded proposal digest",
			input: strings.Replace(
				accepted,
				`"proposal_digest":"I8ct7tSAgwS5lJjQCyHEecuY4PLO4dEBoMI2twtIzFw"`,
				`"proposal_digest":"I8ct7tSAgwS5lJjQCyHEecuY4PLO4dEBoMI2twtIzFw="`,
				1,
			),
		},
		{
			name: "short chain hash",
			input: strings.Replace(
				accepted,
				`"chain_hash":"REREREREREREREREREREREREREREREREREREREREREQ"`,
				`"chain_hash":"AA"`,
				1,
			),
		},
		{
			name: "accepted without chain tuple",
			input: strings.NewReplacer(
				`"chain_hash":"REREREREREREREREREREREREREREREREREREREREREQ"`,
				`"chain_hash":null`,
				`"chain_index":1`,
				`"chain_index":null`,
			).Replace(accepted),
		},
		{
			name: "rejected with chain tuple",
			input: strings.NewReplacer(
				`"chain_hash":null`,
				`"chain_hash":"REREREREREREREREREREREREREREREREREREREREREQ"`,
				`"chain_index":null`,
				`"chain_index":1`,
			).Replace(rejected),
		},
		{
			name: "partial chain tuple",
			input: strings.Replace(
				accepted,
				`"chain_index":1`,
				`"chain_index":null`,
				1,
			),
		},
		{
			name: "proposal digest mismatch",
			input: strings.Replace(
				accepted,
				`I8ct7tSAgwS5lJjQCyHEecuY4PLO4dEBoMI2twtIzFw`,
				`Skj616_HhamVyR3sQTc5B4ym_-BROzook6B3pVK5oi8`,
				1,
			),
			also: chain.ErrProposalDigest,
		},
		{name: "trailing JSON value", input: accepted + `{}`},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := chain.DecodeResult([]byte(test.input))
			if !errors.Is(err, chain.ErrInvalidResult) {
				t.Fatalf(
					"DecodeResult() error = %v, want ErrInvalidResult",
					err,
				)
			}
			if test.also != nil && !errors.Is(err, test.also) {
				t.Fatalf("DecodeResult() error = %v, also want %v", err, test.also)
			}
		})
	}

	if _, err := chain.DecodeResult(
		make([]byte, 4<<20+1),
	); !errors.Is(err, chain.ErrInvalidResult) {
		t.Fatalf(
			"DecodeResult(oversize) error = %v, want ErrInvalidResult",
			err,
		)
	}
}

func TestDecodeResultDoesNotAliasCallerInput(t *testing.T) {
	t.Parallel()

	encoded, err := chain.EncodeResult(validAcceptedResult())
	if err != nil {
		t.Fatalf("EncodeResult() error = %v", err)
	}
	original := bytes.Clone(encoded)
	decoded, err := chain.DecodeResult(encoded)
	if err != nil {
		t.Fatalf("DecodeResult() error = %v", err)
	}
	proposal := bytes.Clone(decoded.Proposal)
	outcome := bytes.Clone(decoded.Outcome)
	for index := range encoded {
		encoded[index] = 0
	}
	if !bytes.Equal(decoded.Proposal, proposal) ||
		!bytes.Equal(decoded.Outcome, outcome) {
		t.Fatal("DecodeResult() output aliases caller input")
	}

	encoded = bytes.Clone(original)
	decoded, err = chain.DecodeResult(encoded)
	if err != nil {
		t.Fatalf("DecodeResult() second error = %v", err)
	}
	decoded.Proposal[0] ^= 0xff
	decoded.Outcome[0] ^= 0xff
	if !bytes.Equal(encoded, original) {
		t.Fatal("DecodeResult() caller-mutable output aliases input")
	}
}

func TestCommandResultValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*chain.Result)
		want   error
	}{
		{
			name: "zero result index",
			mutate: func(result *chain.Result) {
				result.ResultIndex = 0
			},
			want: chain.ErrInvalidIndex,
		},
		{
			name: "inexact result index",
			mutate: func(result *chain.Result) {
				result.ResultIndex = 1 << 53
			},
			want: chain.ErrInvalidIndex,
		},
		{
			name: "noncanonical proposal",
			mutate: func(result *chain.Result) {
				result.Proposal = []byte(`{"z":1,"a":2}`)
				result.ProposalDigest = proposalDigest(result.Proposal)
			},
			want: chain.ErrInvalidObject,
		},
		{
			name: "proposal is not object",
			mutate: func(result *chain.Result) {
				result.Proposal = []byte(`[]`)
				result.ProposalDigest = proposalDigest(result.Proposal)
			},
			want: chain.ErrInvalidObject,
		},
		{
			name: "noncanonical outcome",
			mutate: func(result *chain.Result) {
				result.Outcome = []byte(`{ "code":"accepted","status":"accepted"}`)
			},
			want: chain.ErrInvalidObject,
		},
		{
			name: "proposal digest mismatch",
			mutate: func(result *chain.Result) {
				result.ProposalDigest = filledDigest(0xff)
			},
			want: chain.ErrProposalDigest,
		},
		{
			name: "missing outcome status",
			mutate: func(result *chain.Result) {
				result.Outcome = []byte(`{"code":"accepted"}`)
			},
			want: chain.ErrInvalidResult,
		},
		{
			name: "unknown outcome status",
			mutate: func(result *chain.Result) {
				result.Outcome = []byte(`{"code":"accepted","status":"pending"}`)
			},
			want: chain.ErrInvalidResult,
		},
		{
			name: "missing outcome code",
			mutate: func(result *chain.Result) {
				result.Outcome = []byte(`{"status":"accepted"}`)
			},
			want: chain.ErrInvalidResult,
		},
		{
			name: "empty outcome code",
			mutate: func(result *chain.Result) {
				result.Outcome = []byte(`{"code":"","status":"accepted"}`)
			},
			want: chain.ErrInvalidResult,
		},
		{
			name: "rejected outcome with chain tuple",
			mutate: func(result *chain.Result) {
				result.Outcome = []byte(`{"code":"rejected","status":"rejected"}`)
			},
			want: chain.ErrInvalidResult,
		},
		{
			name: "chain index without hash",
			mutate: func(result *chain.Result) {
				result.ChainHash = nil
			},
			want: chain.ErrInvalidResult,
		},
		{
			name: "chain hash without index",
			mutate: func(result *chain.Result) {
				result.ChainIndex = nil
			},
			want: chain.ErrInvalidResult,
		},
		{
			name: "accepted outcome without chain tuple",
			mutate: func(result *chain.Result) {
				result.ChainIndex = nil
				result.ChainHash = nil
			},
			want: chain.ErrInvalidResult,
		},
		{
			name: "zero chain index",
			mutate: func(result *chain.Result) {
				index := uint64(0)
				result.ChainIndex = &index
			},
			want: chain.ErrInvalidIndex,
		},
		{
			name: "chain index exceeds result index",
			mutate: func(result *chain.Result) {
				index := result.ResultIndex + 1
				result.ChainIndex = &index
			},
			want: chain.ErrInvalidIndex,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := validAcceptedResult()
			test.mutate(&result)
			if _, err := chain.EncodeResult(result); !errors.Is(err, test.want) {
				t.Fatalf("EncodeResult() error = %v, want %v", err, test.want)
			}
			if _, _, err := chain.AppendResult(chain.Digest{}, result); !errors.Is(
				err,
				test.want,
			) {
				t.Fatalf("AppendResult() error = %v, want %v", err, test.want)
			}
		})
	}
}

func assertResultDecode(t *testing.T, encoded []byte, want chain.Result) {
	t.Helper()

	decoded, err := chain.DecodeResult(encoded)
	if err != nil {
		t.Fatalf("DecodeResult() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("DecodeResult() = %#v, want %#v", decoded, want)
	}
	roundTrip, err := chain.EncodeResult(decoded)
	if err != nil {
		t.Fatalf("EncodeResult(DecodeResult()) error = %v", err)
	}
	if !bytes.Equal(roundTrip, encoded) {
		t.Fatalf(
			"EncodeResult(DecodeResult()) = %s, want %s",
			roundTrip,
			encoded,
		)
	}
}

func validAcceptedResult() chain.Result {
	proposal := []byte(
		`{"event_id":"018f0000-0000-7000-8000-000000000002","kind":"task.created","origin_signature":"AA","sequence":1}`,
	)
	chainIndex := uint64(1)
	chainHash := filledDigest(0x44)
	return chain.Result{
		ResultIndex:    3,
		Proposal:       proposal,
		Outcome:        []byte(`{"code":"accepted","status":"accepted"}`),
		ProposalDigest: proposalDigest(proposal),
		ChainIndex:     &chainIndex,
		ChainHash:      &chainHash,
	}
}

func validRejectedResult() chain.Result {
	proposal := []byte(
		`{"event_id":"018f0000-0000-7000-8000-000000000003","kind":"task.claimed","origin_signature":"AQ","sequence":2}`,
	)
	return chain.Result{
		ResultIndex:    4,
		Proposal:       proposal,
		Outcome:        []byte(`{"code":"task_not_ready","status":"rejected"}`),
		ProposalDigest: proposalDigest(proposal),
	}
}
