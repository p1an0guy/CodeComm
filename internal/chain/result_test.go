package chain_test

import (
	"bytes"
	"errors"
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
