package controlfile

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	testEventID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000001")
	testSession = domain.UUIDv7("01890f47-3e72-7000-8000-000000000002")
	testDevice  = domain.DeviceID(
		"cc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
)

func TestProposalValidateOperationsAndBounds(t *testing.T) {
	t.Parallel()

	digest := SHA256Digest(sha256.Sum256([]byte("content")))
	upsert := validProposal()
	upsert.ContentDigest = &digest
	upsert.ContentSize = MaxContentBytes
	if err := upsert.Validate(); err != nil {
		t.Fatalf("upsert.Validate() error = %v", err)
	}
	deletion := validProposal()
	deletion.Operation = OperationDelete
	deletion.ContentSize = 0
	if err := deletion.Validate(); err != nil {
		t.Fatalf("deletion.Validate() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Proposal)
		want   error
	}{
		{
			name: "missing event ID",
			mutate: func(value *Proposal) {
				value.ProposalEventID = ""
			},
			want: ErrInvalidIdentity,
		},
		{
			name: "zero chain index",
			mutate: func(value *Proposal) {
				value.ChainIndex = 0
			},
			want: ErrInvalidIdentity,
		},
		{
			name: "chain index one past maximum",
			mutate: func(value *Proposal) {
				value.ChainIndex = domain.MaxSafeInteger + 1
			},
			want: ErrInvalidIdentity,
		},
		{
			name: "invalid path",
			mutate: func(value *Proposal) {
				value.Path = "../AGENTS.md"
			},
			want: ErrInvalidPath,
		},
		{
			name: "unknown operation",
			mutate: func(value *Proposal) {
				value.Operation = "replace"
			},
			want: ErrInvalidOperation,
		},
		{
			name: "upsert without digest",
			mutate: func(value *Proposal) {
				value.ContentDigest = nil
			},
			want: ErrInvalidContent,
		},
		{
			name: "content one past maximum",
			mutate: func(value *Proposal) {
				value.ContentSize = MaxContentBytes + 1
			},
			want: ErrInvalidContent,
		},
		{
			name: "delete with digest",
			mutate: func(value *Proposal) {
				value.Operation = OperationDelete
			},
			want: ErrInvalidContent,
		},
		{
			name: "diff one past maximum",
			mutate: func(value *Proposal) {
				value.Diff = strings.Repeat("x", MaxDiffBytes+1)
			},
			want: ErrInvalidDiff,
		},
		{
			name: "invalid UTF-8 diff",
			mutate: func(value *Proposal) {
				value.Diff = string([]byte{0xff})
			},
			want: ErrInvalidDiff,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validProposal()
			value.ContentDigest = &digest
			test.mutate(&value)
			if err := value.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func validProposal() Proposal {
	return Proposal{
		ProposalEventID:    testEventID,
		SessionID:          testSession,
		Path:               "AGENTS.md",
		Operation:          OperationUpsert,
		ContentSize:        1,
		Diff:               "@@ -1 +1 @@\n-old\n+new\n",
		ProposedByDeviceID: testDevice,
		ChainIndex:         1,
	}
}
