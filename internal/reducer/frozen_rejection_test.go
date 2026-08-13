package reducer

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

type frozenRejectionCode struct {
	Name string `json:"name"`
	Wire string `json:"wire"`
}

type frozenRejectionCase struct {
	name           string
	testCase       frozenReducerCase
	wantCode       Code
	consumesOrigin bool
}

type frozenRejectionFixture struct {
	Name                 string                    `json:"name"`
	Kind                 event.Kind                `json:"kind"`
	PriorState           frozenRejectionPrior      `json:"prior_state"`
	SignedInput          json.RawMessage           `json:"signed_input"`
	OutcomeJSON          json.RawMessage           `json:"outcome_json"`
	Consumed             bool                      `json:"consumed_origin"`
	ResultInput          frozenRejectedResult      `json:"result_chain_input"`
	ResultHash           string                    `json:"result_hash"`
	Accumulator          frozenRejectedAccumulator `json:"projection_accumulator_input"`
	ResultingAccumulator string                    `json:"resulting_projection_accumulator"`
}

type frozenRejectionPrior struct {
	ChainIndex            uint64 `json:"chain_index"`
	ChainHash             string `json:"chain_hash"`
	ResultIndex           uint64 `json:"result_index"`
	ResultHash            string `json:"result_hash"`
	StateDigest           string `json:"projection_state_digest"`
	ProjectionAccumulator string `json:"projection_accumulator"`
}

type frozenRejectedResult struct {
	PreviousHash   string  `json:"previous_hash"`
	ResultIndex    uint64  `json:"result_index"`
	ProposalDigest string  `json:"proposal_digest"`
	ChainIndex     *uint64 `json:"chain_index"`
	ChainHash      *string `json:"chain_hash"`
}

type frozenRejectedAccumulator struct {
	PreviousHash string          `json:"previous_hash"`
	ResultIndex  uint64          `json:"result_index"`
	ResultHash   string          `json:"result_hash"`
	Mutations    json.RawMessage `json:"projection_mutations"`
}

func TestFrozenRejectionCodeRegistry(t *testing.T) {
	t.Parallel()

	codes := declaredRejectionCodes(t)
	if len(codes) == 0 {
		t.Fatal("no rejection Code constants discovered")
	}
	seenWire := make(map[string]string, len(codes))
	for _, code := range codes {
		if previous, duplicate := seenWire[code.Wire]; duplicate {
			t.Fatalf(
				"rejection wire code %q is shared by %s and %s",
				code.Wire,
				previous,
				code.Name,
			)
		}
		seenWire[code.Wire] = code.Name
	}
	assertFrozenRejectionJSON(
		t,
		filepath.Join("testdata", "reducer_rejections", "codes.golden.json"),
		codes,
	)
}

func TestFrozenRejectionOutcomes(t *testing.T) {
	cases := frozenRejectionCases(t)
	fixtures := make([]frozenRejectionFixture, 0, len(cases))
	for _, testCase := range cases {
		fixtures = append(fixtures, buildFrozenRejectionFixture(t, testCase))
	}
	assertFrozenRejectionJSON(
		t,
		filepath.Join("testdata", "reducer_rejections", "outcomes.golden.json"),
		fixtures,
	)
}

func frozenRejectionCases(t *testing.T) []frozenRejectionCase {
	t.Helper()

	gapFixture := newReducerFixture(t)
	gap := buildTaskProposalAtSequence(
		t,
		gapFixture,
		event.ActorAgent,
		event.KindTaskCreated,
		0,
		`{"priority":2,"title":"gap"}`,
		3,
	)

	roleFixture := newReducerFixture(t)
	values := policy.DefaultValues()
	values.CheckpointEvents++
	insufficientRole := buildPolicyProposal(
		t,
		roleFixture,
		roleFixture.editorDevice,
		testSessionID,
		1,
		policyPayload(t, values),
	)

	payloadFixture := newReducerFixture(t)
	payloadFixture.state.tasks[testTaskID] = testTask(task.StateReady, 4)
	unknownField := buildTaskProposal(
		t,
		payloadFixture,
		event.ActorAgent,
		event.KindTaskClaimed,
		4,
		`{"unexpected":true}`,
	)

	domainFixture := newReducerFixture(t)
	domainFixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
	notActionable := buildTaskProposal(
		t,
		domainFixture,
		event.ActorAgent,
		event.KindTaskClaimed,
		4,
		`{}`,
	)

	return []frozenRejectionCase{
		{
			name: "preflight_without_origin_consumption",
			testCase: frozenCase(
				event.KindTaskCreated,
				gapFixture,
				gap,
			),
			wantCode: CodeOriginSequenceGap,
		},
		{
			name: "role_check_consumes_origin",
			testCase: frozenCase(
				event.KindPolicyChanged,
				roleFixture,
				insufficientRole,
			),
			wantCode:       CodeInsufficientRole,
			consumesOrigin: true,
		},
		{
			name: "payload_check_consumes_origin",
			testCase: frozenCase(
				event.KindTaskClaimed,
				payloadFixture,
				unknownField,
			),
			wantCode:       CodeUnknownPayloadField,
			consumesOrigin: true,
		},
		{
			name: "domain_check_consumes_origin",
			testCase: frozenCase(
				event.KindTaskClaimed,
				domainFixture,
				notActionable,
			),
			wantCode:       CodeTaskNotActionable,
			consumesOrigin: true,
		},
	}
}

func buildFrozenRejectionFixture(
	t *testing.T,
	rejection frozenRejectionCase,
) frozenRejectionFixture {
	t.Helper()

	before := mustReducerState(t, snapshotFromState(rejection.testCase.state))
	priorRows := frozenProjectionRows(t, before)
	stateDigest, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		frozenChainRows(priorRows),
	)
	if err != nil {
		t.Fatalf("%s: digest prior projection state: %v", rejection.name, err)
	}
	genesis, err := chain.GenesisDigest(
		[]byte(`{"fixture":"codecomm-reducer-rejection-v1"}`),
	)
	if err != nil {
		t.Fatalf("%s: fixture genesis digest: %v", rejection.name, err)
	}
	priorHeads, err := buildFrozenPriorHeads(
		genesis,
		stateDigest,
		before.currentChainIndex,
		before.currentResultIndex,
	)
	if err != nil {
		t.Fatalf("%s: build coherent prior heads: %v", rejection.name, err)
	}

	outcome, err := Reduce(before, rejection.testCase.signed)
	if err != nil {
		t.Fatalf("%s: Reduce() error = %v", rejection.name, err)
	}
	if outcome.Status != StatusRejected || outcome.Code != rejection.wantCode {
		t.Fatalf(
			"%s: outcome = %#v, want rejected/%s",
			rejection.name,
			outcome,
			rejection.wantCode,
		)
	}
	if outcome.Changes.AdvancesEventChain {
		t.Fatalf("%s: rejection advances the event chain", rejection.name)
	}
	if got := len(outcome.Changes.OriginScopes); (got == 1) != rejection.consumesOrigin {
		t.Fatalf(
			"%s: origin-scope writes = %d, consumed = %t",
			rejection.name,
			got,
			rejection.consumesOrigin,
		)
	}
	if rejection.consumesOrigin &&
		outcome.Changes.OriginScopes[0].LastSequence != 2 {
		t.Fatalf(
			"%s: consumed origin sequence = %d, want 2",
			rejection.name,
			outcome.Changes.OriginScopes[0].LastSequence,
		)
	}

	after := mustReducerState(t, snapshotFromState(before))
	if err := after.Apply(outcome.Changes); err != nil {
		t.Fatalf("%s: apply reducer changes: %v", rejection.name, err)
	}
	if after.currentChainIndex != before.currentChainIndex ||
		after.currentResultIndex != before.currentResultIndex+1 {
		t.Fatalf(
			"%s: resulting positions = chain %d/result %d",
			rejection.name,
			after.currentChainIndex,
			after.currentResultIndex,
		)
	}
	mutations := frozenMutations(
		t,
		priorRows,
		frozenProjectionRows(t, after),
	)
	if len(mutations) != len(outcome.Changes.OriginScopes) {
		t.Fatalf(
			"%s: projection mutations = %d, want %d origin-only mutations",
			rejection.name,
			len(mutations),
			len(outcome.Changes.OriginScopes),
		)
	}

	outcomeJSON, err := outcome.ResultJSON()
	if err != nil {
		t.Fatalf("%s: encode outcome: %v", rejection.name, err)
	}
	proposal := rejection.testCase.signed.CanonicalBytes()
	proposalDigest := sha256.Sum256(proposal)
	resultIndex := before.currentResultIndex + 1
	resultHash, _, err := chain.AppendResult(priorHeads.result, chain.Result{
		ResultIndex:    resultIndex,
		Proposal:       proposal,
		Outcome:        outcomeJSON,
		ProposalDigest: proposalDigest,
	})
	if err != nil {
		t.Fatalf("%s: append result: %v", rejection.name, err)
	}
	accumulator, mutationBytes, err := chain.AppendAccumulator(
		priorHeads.accumulator,
		resultIndex,
		resultHash,
		mutations,
	)
	if err != nil {
		t.Fatalf("%s: append projection accumulator: %v", rejection.name, err)
	}
	encodedMutations, err := chain.EncodeMutations(mutations)
	if err != nil {
		t.Fatalf("%s: encode mutations: %v", rejection.name, err)
	}
	if !bytes.Equal(mutationBytes, encodedMutations) {
		t.Fatalf("%s: accumulator changed mutation bytes", rejection.name)
	}

	return frozenRejectionFixture{
		Name: rejection.name,
		Kind: rejection.testCase.kind,
		PriorState: frozenRejectionPrior{
			ChainIndex:            before.currentChainIndex,
			ChainHash:             codec.EncodeBase64URL(priorHeads.event[:]),
			ResultIndex:           before.currentResultIndex,
			ResultHash:            codec.EncodeBase64URL(priorHeads.result[:]),
			StateDigest:           codec.EncodeBase64URL(stateDigest[:]),
			ProjectionAccumulator: codec.EncodeBase64URL(priorHeads.accumulator[:]),
		},
		SignedInput: proposal,
		OutcomeJSON: outcomeJSON,
		Consumed:    rejection.consumesOrigin,
		ResultInput: frozenRejectedResult{
			PreviousHash:   codec.EncodeBase64URL(priorHeads.result[:]),
			ResultIndex:    resultIndex,
			ProposalDigest: codec.EncodeBase64URL(proposalDigest[:]),
		},
		ResultHash: codec.EncodeBase64URL(resultHash[:]),
		Accumulator: frozenRejectedAccumulator{
			PreviousHash: codec.EncodeBase64URL(priorHeads.accumulator[:]),
			ResultIndex:  resultIndex,
			ResultHash:   codec.EncodeBase64URL(resultHash[:]),
			Mutations:    mutationBytes,
		},
		ResultingAccumulator: codec.EncodeBase64URL(accumulator[:]),
	}
}

func declaredRejectionCodes(t *testing.T) []frozenRejectionCode {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read reducer package: %v", err)
	}
	var codes []frozenRejectionCode
	for _, entry := range entries {
		if entry.IsDir() ||
			!strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(
			token.NewFileSet(),
			entry.Name(),
			nil,
			0,
		)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			declaration, ok := node.(*ast.GenDecl)
			if !ok || declaration.Tok != token.CONST {
				return true
			}
			for _, rawSpec := range declaration.Specs {
				spec := rawSpec.(*ast.ValueSpec)
				codeType, ok := spec.Type.(*ast.Ident)
				if !ok || codeType.Name != "Code" {
					continue
				}
				if len(spec.Names) != 1 || len(spec.Values) != 1 {
					t.Fatalf(
						"%s: Code declarations must use one explicit literal per name",
						entry.Name(),
					)
				}
				name := spec.Names[0].Name
				literal, ok := spec.Values[0].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("%s: %s must use a string literal", entry.Name(), name)
				}
				wire, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("%s: decode %s: %v", entry.Name(), name, err)
				}
				if name != "CodeAccepted" {
					codes = append(codes, frozenRejectionCode{
						Name: name,
						Wire: wire,
					})
				}
			}
			return false
		})
	}
	sort.Slice(codes, func(left, right int) bool {
		return codes[left].Name < codes[right].Name
	})
	return codes
}

func assertFrozenRejectionJSON(t *testing.T, path string, value any) {
	t.Helper()

	actual, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	actual = append(actual, '\n')
	if os.Getenv(updateFrozenReducerFixturesEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		if err := os.WriteFile(path, actual, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf(
			"read fixture %s: %v (regenerate with %s=1)",
			path,
			err,
			updateFrozenReducerFixturesEnv,
		)
	}
	if !bytes.Equal(actual, want) {
		t.Fatalf(
			"frozen rejection fixture %s changed; inspect and regenerate explicitly with %s=1",
			path,
			updateFrozenReducerFixturesEnv,
		)
	}
}
