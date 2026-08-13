package reducer

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/controlfile"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestDecodeControlFileProposalAcceptsUpsertAndDelete(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("content"))
	tests := []struct {
		name      string
		operation string
		digest    any
		size      uint64
	}{
		{
			name:      "upsert",
			operation: "upsert",
			digest:    codec.EncodeBase64URL(digest[:]),
			size:      controlfile.MaxContentBytes,
		},
		{
			name:      "delete",
			operation: "delete",
			digest:    nil,
			size:      0,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			context := controlFileReductionContext(
				t,
				fixture,
				"AGENTS.md",
				map[string]any{
					"path":           "AGENTS.md",
					"operation":      test.operation,
					"content_digest": test.digest,
					"content_size":   test.size,
					"diff":           "@@ -1 +1 @@\n-old\n+new\n",
				},
			)

			got, code := decodeControlFileProposal(context)
			if code != "" {
				t.Fatalf("decodeControlFileProposal() code = %q", code)
			}
			if got.Path != "AGENTS.md" ||
				string(got.Operation) != test.operation ||
				got.ContentSize != test.size ||
				got.ProposedByDeviceID != fixture.editorDevice ||
				got.ChainIndex != 1 ||
				got.ProposalEventID != context.proposal.EventID {
				t.Fatalf("proposal = %#v", got)
			}
			if (got.ContentDigest == nil) != (test.digest == nil) {
				t.Fatalf("proposal digest = %#v", got.ContentDigest)
			}
		})
	}
}

func TestDecodeControlFileProposalRejectionMatrix(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("content"))
	valid := func() map[string]any {
		return map[string]any{
			"path":           ".codecommignore",
			"operation":      "upsert",
			"content_digest": codec.EncodeBase64URL(digest[:]),
			"content_size":   7,
			"diff":           "change",
		}
	}
	tests := []struct {
		name       string
		entityPath string
		mutate     func(map[string]any)
		want       Code
	}{
		{
			name:       "path mismatch",
			entityPath: "AGENTS.md",
			want:       CodeControlFilePathMismatch,
		},
		{
			name:       "ordinary path",
			entityPath: "src/main.go",
			mutate: func(payload map[string]any) {
				payload["path"] = "src/main.go"
			},
			want: CodeControlFilePathRequired,
		},
		{
			name:       "upsert null digest",
			entityPath: ".codecommignore",
			mutate: func(payload map[string]any) {
				payload["content_digest"] = nil
			},
			want: CodeInvalidPayload,
		},
		{
			name:       "delete non-null digest",
			entityPath: ".codecommignore",
			mutate: func(payload map[string]any) {
				payload["operation"] = "delete"
				payload["content_size"] = 0
			},
			want: CodeInvalidPayload,
		},
		{
			name:       "content one past maximum",
			entityPath: ".codecommignore",
			mutate: func(payload map[string]any) {
				payload["content_size"] = controlfile.MaxContentBytes + 1
			},
			want: CodeInvalidPayload,
		},
		{
			name:       "diff one past maximum",
			entityPath: ".codecommignore",
			mutate: func(payload map[string]any) {
				payload["diff"] = strings.Repeat("x", controlfile.MaxDiffBytes+1)
			},
			want: CodeInvalidPayload,
		},
		{
			name:       "missing field",
			entityPath: ".codecommignore",
			mutate: func(payload map[string]any) {
				delete(payload, "content_digest")
			},
			want: CodeMissingPayloadField,
		},
		{
			name:       "unknown field",
			entityPath: ".codecommignore",
			mutate: func(payload map[string]any) {
				payload["content"] = "secret"
			},
			want: CodeUnknownPayloadField,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			payload := valid()
			if test.mutate != nil {
				test.mutate(payload)
			}
			context := controlFileReductionContext(
				t,
				fixture,
				test.entityPath,
				payload,
			)

			_, code := decodeControlFileProposal(context)
			if code != test.want {
				t.Fatalf(
					"decodeControlFileProposal() code = %q, want %q",
					code,
					test.want,
				)
			}
		})
	}
}

func TestControlFileProposalDispatchesAppliesAndClonesDigest(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	digest := sha256.Sum256([]byte("content"))
	signed := signedControlFileProposal(
		t,
		fixture,
		"AGENTS.md",
		map[string]any{
			"path":           "AGENTS.md",
			"operation":      "upsert",
			"content_digest": codec.EncodeBase64URL(digest[:]),
			"content_size":   7,
			"diff":           "change",
		},
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() ||
		!outcome.Changes.AdvancesEventChain ||
		len(outcome.Changes.ControlFileProposals) != 1 ||
		outcome.Changes.ControlFileProposals[0].ChainIndex != 1 {
		t.Fatalf("outcome = %#v", outcome)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
	eventID := signed.Proposal().EventID
	applied := fixture.state.controlFileProposals[eventID]
	if applied.ContentDigest == nil || *applied.ContentDigest != digest {
		t.Fatalf("applied proposal = %#v", applied)
	}
	outcome.Changes.ControlFileProposals[0].ContentDigest[0] ^= 0xff
	if *fixture.state.controlFileProposals[eventID].ContentDigest != digest {
		t.Fatal("applied control-file digest aliases reducer output")
	}
}

func TestControlFileSnapshotRetainsPredecessorSessionButChangesRequireCurrent(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	digest := controlfile.SHA256Digest(sha256.Sum256([]byte("content")))
	proposal := controlfile.Proposal{
		ProposalEventID:    domainEventID(160),
		SessionID:          domain.UUIDv7("01890f47-3e72-7000-8000-000000000099"),
		Path:               "AGENTS.md",
		Operation:          controlfile.OperationUpsert,
		ContentDigest:      &digest,
		ContentSize:        7,
		Diff:               "change",
		ProposedByDeviceID: fixture.editorDevice,
		ChainIndex:         1,
	}
	fixture.state.currentChainIndex = 1
	if err := fixture.state.loadControlFileSnapshot(
		map[domain.UUIDv7]controlfile.Proposal{
			proposal.ProposalEventID: proposal,
		},
	); err != nil {
		t.Fatalf("loadControlFileSnapshot() error = %v", err)
	}

	next := proposal.Clone()
	next.ProposalEventID = domainEventID(161)
	next.ChainIndex = 2
	err := fixture.state.Apply(Changes{
		AdvancesEventChain:   true,
		ControlFileProposals: []controlfile.Proposal{next},
		OriginScopes: []OriginScope{{
			OriginScopeKey: OriginScopeKey{
				DeviceID: fixture.editorDevice,
				Kind:     ScopeAgent,
				ScopeID:  testAgentSessionID,
			},
			LastSequence: 2,
		}},
	})
	if !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("State.Apply() error = %v, want invalid state", err)
	}
}

func controlFileReductionContext(
	t *testing.T,
	fixture reducerFixture,
	entityPath string,
	payload map[string]any,
) reductionContext {
	t.Helper()
	signed := signedControlFileProposal(t, fixture, entityPath, payload)
	context, outcome, done, err := beginReduction(fixture.state, signed)
	if err != nil {
		t.Fatalf("beginReduction() error = %v", err)
	}
	if done {
		t.Fatalf("beginReduction() outcome = %#v", outcome)
	}
	return context
}

func signedControlFileProposal(
	t *testing.T,
	fixture reducerFixture,
	entityPath string,
	payload map[string]any,
) event.SignedEvent {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	signed := buildRepositoryProposal(
		t,
		fixture,
		event.ActorAgent,
		fixture.editorDevice,
		testAgentSessionID,
		event.KindControlFileChangeProposed,
		entityPath,
		0,
		encoded,
		domainEventID(130),
		2,
	)
	return signed
}
