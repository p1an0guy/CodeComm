package reducer

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

const updateFrozenReducerFixturesEnv = "CODECOMM_UPDATE_REDUCER_FIXTURES"

type frozenReducerCase struct {
	kind   event.Kind
	state  State
	signed event.SignedEvent
	reduce func(State, event.SignedEvent) (Outcome, error)
}

type frozenOutcomeFixture struct {
	Kind        event.Kind       `json:"kind"`
	PriorState  frozenPriorState `json:"prior_state"`
	SignedInput json.RawMessage  `json:"signed_input"`
	Outcome     frozenOutcome    `json:"outcome"`
	ResultHash  string           `json:"result_hash"`
	Accumulator string           `json:"resulting_projection_accumulator"`
}

type frozenPriorState struct {
	ChainIndex            uint64                `json:"chain_index"`
	ChainHash             string                `json:"chain_hash"`
	ResultIndex           uint64                `json:"result_index"`
	ResultHash            string                `json:"result_hash"`
	StateDigest           string                `json:"projection_state_digest"`
	ProjectionAccumulator string                `json:"projection_accumulator"`
	Rows                  []frozenProjectionRow `json:"rows"`
}

type frozenPriorHeads struct {
	event       chain.Digest
	result      chain.Digest
	accumulator chain.Digest
}

type frozenOutcome struct {
	Status              Status                  `json:"status"`
	Code                Code                    `json:"code"`
	ProjectionMutations json.RawMessage         `json:"projection_mutations"`
	RecordActivity      bool                    `json:"record_activity"`
	ActivityTaskID      domain.UUIDv7           `json:"activity_task_id,omitempty"`
	Audit               *AuditDirective         `json:"audit,omitempty"`
	RecordedAudit       *AuditRecordedDirective `json:"recorded_audit,omitempty"`
	Alarm               *AlarmDirective         `json:"alarm,omitempty"`
	Checkpoint          *CheckpointDirective    `json:"checkpoint,omitempty"`
}

func TestFrozenReducerFixtureRegistryIsComplete(t *testing.T) {
	t.Parallel()

	registry := frozenReducerRegistry()
	kinds := event.Kinds()
	if len(registry) != len(kinds) {
		t.Fatalf("fixture registry has %d entries, want %d", len(registry), len(kinds))
	}
	for _, kind := range kinds {
		if registry[kind] == nil {
			t.Errorf("event kind %q has no frozen reducer fixture", kind)
		}
	}
	for kind := range registry {
		if _, registered := event.LookupKind(kind); !registered {
			t.Errorf("fixture registry contains unknown event kind %q", kind)
		}
	}
}

func TestFrozenPriorHeadsRejectIncoherentPosition(t *testing.T) {
	t.Parallel()

	if _, err := buildFrozenPriorHeads(chain.Digest{}, chain.Digest{}, 2, 1); err == nil {
		t.Fatal("synthetic history accepted chainIndex > resultIndex")
	}
}

func TestFrozenReducerOutcomes(t *testing.T) {
	registry := frozenReducerRegistry()
	for _, kind := range event.Kinds() {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			testCase := registry[kind](t)
			if testCase.kind != kind {
				t.Fatalf("fixture builder returned kind %q, want %q", testCase.kind, kind)
			}
			if got := testCase.signed.Proposal().Kind; got != kind {
				t.Fatalf("fixture signed input has kind %q, want %q", got, kind)
			}
			actual := buildFrozenOutcomeFixture(t, testCase)
			path := filepath.Join(
				"testdata",
				"reducer_outcomes",
				strings.ReplaceAll(string(kind), ".", "_")+".golden.json",
			)
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
					"frozen outcome changed for %s; inspect the reducer change and regenerate explicitly with %s=1",
					kind,
					updateFrozenReducerFixturesEnv,
				)
			}
		})
	}
}

func buildFrozenOutcomeFixture(
	t *testing.T,
	testCase frozenReducerCase,
) []byte {
	t.Helper()
	before := mustReducerState(t, snapshotFromState(testCase.state))
	priorRows := frozenProjectionRows(t, before)
	stateDigest, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		frozenChainRows(priorRows),
	)
	if err != nil {
		t.Fatalf("digest prior projection state: %v", err)
	}
	genesis, err := chain.GenesisDigest(
		[]byte(`{"fixture":"codecomm-reducer-outcome-v1"}`),
	)
	if err != nil {
		t.Fatalf("fixture genesis digest: %v", err)
	}
	priorHeads, err := buildFrozenPriorHeads(
		genesis,
		stateDigest,
		before.currentChainIndex,
		before.currentResultIndex,
	)
	if err != nil {
		t.Fatalf("build coherent prior heads: %v", err)
	}

	reduce := testCase.reduce
	if reduce == nil {
		reduce = Reduce
	}
	outcome, err := reduce(before, testCase.signed)
	if err != nil {
		t.Fatalf("reduce %s: %v", testCase.kind, err)
	}
	if !outcome.Accepted() {
		t.Fatalf(
			"fixture %s unexpectedly rejected with %s; normal-path fixtures must remain accepted",
			testCase.kind,
			outcome.Code,
		)
	}
	after := mustReducerState(t, snapshotFromState(before))
	if err := after.Apply(outcome.Changes); err != nil {
		t.Fatalf("apply reducer changes for %s: %v", testCase.kind, err)
	}
	afterRows := frozenProjectionRows(t, after)
	mutations := frozenMutations(t, priorRows, afterRows)
	mutationBytes, err := chain.EncodeMutations(mutations)
	if err != nil {
		t.Fatalf("encode mutations for %s: %v", testCase.kind, err)
	}

	eventHash, err := chain.AppendEvent(
		priorHeads.event,
		testCase.signed.CanonicalBytes(),
	)
	if err != nil {
		t.Fatalf("append fixture event: %v", err)
	}
	outcomeJSON, err := outcome.ResultJSON()
	if err != nil {
		t.Fatalf("encode reducer outcome: %v", err)
	}
	resultIndex := before.currentResultIndex + 1
	chainIndex := before.currentChainIndex + 1
	proposalDigest := sha256.Sum256(testCase.signed.CanonicalBytes())
	resultHash, _, err := chain.AppendResult(priorHeads.result, chain.Result{
		ResultIndex:    resultIndex,
		Proposal:       testCase.signed.CanonicalBytes(),
		Outcome:        outcomeJSON,
		ProposalDigest: proposalDigest,
		ChainIndex:     &chainIndex,
		ChainHash:      &eventHash,
	})
	if err != nil {
		t.Fatalf("append fixture result: %v", err)
	}
	accumulator, accumulatedMutations, err := chain.AppendAccumulator(
		priorHeads.accumulator,
		resultIndex,
		resultHash,
		mutations,
	)
	if err != nil {
		t.Fatalf("append fixture accumulator: %v", err)
	}
	if !bytes.Equal(accumulatedMutations, mutationBytes) {
		t.Fatal("accumulator did not retain the exact encoded mutation bytes")
	}

	fixture := frozenOutcomeFixture{
		Kind: testCase.kind,
		PriorState: frozenPriorState{
			ChainIndex:            before.currentChainIndex,
			ChainHash:             codec.EncodeBase64URL(priorHeads.event[:]),
			ResultIndex:           before.currentResultIndex,
			ResultHash:            codec.EncodeBase64URL(priorHeads.result[:]),
			StateDigest:           codec.EncodeBase64URL(stateDigest[:]),
			ProjectionAccumulator: codec.EncodeBase64URL(priorHeads.accumulator[:]),
			Rows:                  priorRows,
		},
		SignedInput: testCase.signed.CanonicalBytes(),
		Outcome: frozenOutcome{
			Status:              outcome.Status,
			Code:                outcome.Code,
			ProjectionMutations: mutationBytes,
			RecordActivity:      outcome.RecordActivity,
			ActivityTaskID:      outcome.ActivityTaskID,
			Audit:               outcome.Audit,
			RecordedAudit:       outcome.RecordedAudit,
			Alarm:               outcome.Alarm,
			Checkpoint:          outcome.Checkpoint,
		},
		ResultHash:  codec.EncodeBase64URL(resultHash[:]),
		Accumulator: codec.EncodeBase64URL(accumulator[:]),
	}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal frozen fixture: %v", err)
	}
	return append(encoded, '\n')
}

func buildFrozenPriorHeads(
	genesis chain.Digest,
	stateDigest chain.Digest,
	chainIndex uint64,
	resultIndex uint64,
) (frozenPriorHeads, error) {
	if chainIndex > resultIndex {
		return frozenPriorHeads{}, fmt.Errorf(
			"chain index %d exceeds result index %d",
			chainIndex,
			resultIndex,
		)
	}
	boundary := chain.Boundary{Genesis: genesis}
	eventHead, err := chain.EventSeed(boundary)
	if err != nil {
		return frozenPriorHeads{}, err
	}
	resultHead, err := chain.ResultSeed(boundary)
	if err != nil {
		return frozenPriorHeads{}, err
	}
	accumulator := chain.AccumulatorSeedInitial(genesis, stateDigest)
	acceptedCount := uint64(0)
	for index := uint64(1); index <= resultIndex; index++ {
		proposal := []byte(fmt.Sprintf(
			`{"fixture_prior_result":%d}`,
			index,
		))
		proposalDigest := sha256.Sum256(proposal)
		result := chain.Result{
			ResultIndex:    index,
			Proposal:       proposal,
			ProposalDigest: proposalDigest,
		}
		if acceptedCount < chainIndex {
			acceptedCount++
			eventHead, err = chain.AppendEvent(eventHead, proposal)
			if err != nil {
				return frozenPriorHeads{}, err
			}
			result.Outcome = []byte(
				`{"code":"synthetic_prior","status":"accepted"}`,
			)
			result.ChainIndex = &acceptedCount
			acceptedHead := eventHead
			result.ChainHash = &acceptedHead
		} else {
			result.Outcome = []byte(
				`{"code":"synthetic_prior","status":"rejected"}`,
			)
		}
		resultHead, _, err = chain.AppendResult(resultHead, result)
		if err != nil {
			return frozenPriorHeads{}, err
		}
		accumulator, _, err = chain.AppendAccumulator(
			accumulator,
			index,
			resultHead,
			nil,
		)
		if err != nil {
			return frozenPriorHeads{}, err
		}
	}
	if acceptedCount != chainIndex {
		return frozenPriorHeads{}, fmt.Errorf(
			"replayed chain index %d, want %d",
			acceptedCount,
			chainIndex,
		)
	}
	return frozenPriorHeads{
		event:       eventHead,
		result:      resultHead,
		accumulator: accumulator,
	}, nil
}

func frozenReducerRegistry() map[event.Kind]func(*testing.T) frozenReducerCase {
	return map[event.Kind]func(*testing.T) frozenReducerCase{
		event.KindTaskCreated:                    frozenTaskCreated,
		event.KindTaskUpdated:                    frozenTaskUpdated,
		event.KindTaskStateChanged:               frozenTaskStateChanged,
		event.KindTaskClaimed:                    frozenTaskClaimed,
		event.KindTaskReleased:                   frozenTaskReleased,
		event.KindTaskReassigned:                 frozenTaskReassigned,
		event.KindTaskCancelled:                  frozenTaskCancelled,
		event.KindWorkspaceConflictDetected:      frozenConflictDetected,
		event.KindWorkspaceConflictForceResolved: frozenConflictForceResolved,
		event.KindWorkspaceConflictResolved:      frozenConflictResolved,
		event.KindPublicationProposed:            frozenPublicationProposed,
		event.KindPublicationReviewed:            frozenPublicationReviewed,
		event.KindPublicationApplied:             frozenPublicationApplied,
		event.KindPublicationWithdrawn:           frozenPublicationWithdrawn,
		event.KindPlanRevisionProposed:           frozenPlanRevisionProposed,
		event.KindPlanCurrentSelected:            frozenPlanCurrentSelected,
		event.KindMemoryAppended:                 frozenMemoryAppended,
		event.KindActivityRecorded:               frozenActivityRecorded,
		event.KindLeaseAcquired:                  frozenLeaseAcquired,
		event.KindLeaseRenewed:                   frozenLeaseRenewed,
		event.KindLeaseReleased:                  frozenLeaseReleased,
		event.KindAgentSessionStarted:            frozenAgentSessionStarted,
		event.KindAgentSessionStateChanged:       frozenAgentSessionStateChanged,
		event.KindAgentSessionEnded:              frozenAgentSessionEnded,
		event.KindMembershipDeviceAdmitted:       frozenMembershipDeviceAdmitted,
		event.KindMembershipVersionReported:      frozenMembershipVersionReported,
		event.KindMembershipRoleChanged:          frozenMembershipRoleChanged,
		event.KindMembershipOwnerRecovered:       frozenMembershipOwnerRecovered,
		event.KindMembershipDeviceRevoked:        frozenMembershipDeviceRevoked,
		event.KindMembershipVoterSetChanged:      frozenMembershipVoterSetChanged,
		event.KindMembershipVoterSetActivated:    frozenMembershipVoterSetActivated,
		event.KindPolicyChanged:                  frozenPolicyChanged,
		event.KindCredentialAuthorized:           frozenCredentialAuthorized,
		event.KindControlFileChangeProposed:      frozenControlFileChangeProposed,
		event.KindConsensusCheckpoint:            frozenConsensusCheckpoint,
		event.KindAuditRecorded:                  frozenAuditRecorded,
	}
}

func frozenCase(
	kind event.Kind,
	fixture reducerFixture,
	signed event.SignedEvent,
) frozenReducerCase {
	return frozenReducerCase{kind: kind, state: fixture.state, signed: signed}
}

func frozenTaskCreated(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	return frozenCase(event.KindTaskCreated, fixture, buildTaskProposal(
		t, fixture, event.ActorHuman, event.KindTaskCreated, 0,
		`{"priority":2,"title":"fixture task"}`,
	))
}

func frozenTaskUpdated(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
	return frozenCase(event.KindTaskUpdated, fixture, buildTaskProposal(
		t, fixture, event.ActorAgent, event.KindTaskUpdated, 4,
		`{"body":"fixture body","labels":["fixture"],"title":"updated"}`,
	))
}

func frozenTaskStateChanged(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
	return frozenCase(event.KindTaskStateChanged, fixture, buildTaskProposal(
		t, fixture, event.ActorHuman, event.KindTaskStateChanged, 4,
		`{"to_state":"ready"}`,
	))
}

func frozenTaskClaimed(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateReady, 4)
	return frozenCase(event.KindTaskClaimed, fixture, buildTaskProposal(
		t, fixture, event.ActorAgent, event.KindTaskClaimed, 4, `{}`,
	))
}

func frozenTaskReleased(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	value := testTask(task.StateClaimed, 4)
	ownTask(&value, fixture.editorDevice)
	fixture.state.tasks[testTaskID] = value
	fixture.state.addClaim(value)
	return frozenCase(event.KindTaskReleased, fixture, buildTaskProposal(
		t, fixture, event.ActorAgent, event.KindTaskReleased, 4,
		`{"release_reason":"voluntary"}`,
	))
}

func frozenTaskReassigned(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	value := testTask(task.StateClaimed, 4)
	ownTask(&value, fixture.editorDevice)
	fixture.state.tasks[testTaskID] = value
	fixture.state.addClaim(value)
	return frozenCase(event.KindTaskReassigned, fixture, buildTaskProposal(
		t, fixture, event.ActorHuman, event.KindTaskReassigned, 4,
		fmt.Sprintf(`{"to_device_id":%q}`, fixture.targetDevice),
	))
}

func frozenTaskCancelled(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
	return frozenCase(event.KindTaskCancelled, fixture, buildTaskProposal(
		t, fixture, event.ActorHuman, event.KindTaskCancelled, 4, `{}`,
	))
}

func frozenActivityRecorded(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	return frozenCase(
		event.KindActivityRecorded,
		fixture,
		signedActivityRecorded(t, fixture, map[string]any{}),
	)
}

func frozenLeaseAcquired(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	return frozenCase(event.KindLeaseAcquired, fixture, buildLeaseProposal(
		t, fixture, event.ActorAgent, event.KindLeaseAcquired, testLeaseID, 0,
		`{"path_globs":["src/**"],"scope":"path","ttl_seconds":900}`,
	))
}

func frozenLeaseRenewed(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	addReducerLease(&fixture.state, mustReducerLease(
		t, testLeaseID, fixture.editorDevice, testAgentSessionID,
		lease.ScopePath, "", 4, "src/**",
	))
	return frozenCase(event.KindLeaseRenewed, fixture, buildLeaseProposal(
		t, fixture, event.ActorAgent, event.KindLeaseRenewed, testLeaseID, 4,
		`{"ttl_seconds":1200}`,
	))
}

func frozenLeaseReleased(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	addReducerLease(&fixture.state, mustReducerLease(
		t, testLeaseID, fixture.editorDevice, testAgentSessionID,
		lease.ScopePath, "", 4, "src/**",
	))
	return frozenCase(event.KindLeaseReleased, fixture, buildLeaseProposal(
		t, fixture, event.ActorAgent, event.KindLeaseReleased, testLeaseID, 4,
		`{"release_reason":"voluntary"}`,
	))
}

func frozenAgentSessionStarted(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	return frozenCase(event.KindAgentSessionStarted, fixture, buildAgentSessionProposal(
		t, fixture, event.ActorAgent, fixture.editorDevice, testNewAgentSessionID,
		nil, event.KindAgentSessionStarted, testNewAgentSessionID, 0,
		`{"client_kind":"claude","working_root_id":"`+string(testNewWorkingRootID)+`"}`, 1,
	))
}

func frozenAgentSessionStateChanged(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	return frozenCase(
		event.KindAgentSessionStateChanged,
		fixture,
		buildAgentSessionProposal(
			t, fixture, event.ActorAgent, fixture.editorDevice, testAgentSessionID,
			nil, event.KindAgentSessionStateChanged, testAgentSessionID, 1,
			`{"to_state":"working"}`, 2,
		),
	)
}

func frozenAgentSessionEnded(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	return frozenCase(event.KindAgentSessionEnded, fixture, buildAgentSessionProposal(
		t, fixture, event.ActorAgent, fixture.editorDevice, testAgentSessionID,
		nil, event.KindAgentSessionEnded, testAgentSessionID, 1,
		`{"end_reason":"clean"}`, 2,
	))
}

func frozenPlanRevisionProposed(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	signed := buildCoordinationProposal(
		t, fixture, event.ActorAgent, fixture.editorDevice,
		event.KindPlanRevisionProposed, string(testPlanRevisionID), 0,
		`{"body":"fixture plan","title":"Iteration 1"}`, 2,
	)
	return frozenCase(event.KindPlanRevisionProposed, fixture, signed)
}

func frozenPlanCurrentSelected(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	fixture.state.planRevisions[testPlanRevisionID] = mustPlanRevision(
		t, testPlanRevisionID, "", nil, fixture.editorDevice,
	)
	signed := buildCoordinationProposal(
		t, fixture, event.ActorHuman, fixture.ownerDevice,
		event.KindPlanCurrentSelected, string(testSessionID), 1,
		`{"plan_revision_id":"`+string(testPlanRevisionID)+`"}`, 2,
	)
	return frozenCase(event.KindPlanCurrentSelected, fixture, signed)
}

func frozenMemoryAppended(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	signed := buildCoordinationProposal(
		t, fixture, event.ActorAgent, fixture.editorDevice,
		event.KindMemoryAppended, string(testMemoryID), 0,
		`{"body":"fixture memory","key":"architecture","scope":"session"}`, 2,
	)
	return frozenCase(event.KindMemoryAppended, fixture, signed)
}

func frozenMembershipDeviceAdmitted(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	member, privateKey := testDevice(t, 4, "editor")
	signed := buildMembershipProposal(
		t, fixture, fixture.ownerDevice, event.ActorHuman,
		event.KindMembershipDeviceAdmitted, string(member.ID), 0,
		admissionPayload(t, member, privateKey),
	)
	return frozenCase(event.KindMembershipDeviceAdmitted, fixture, signed)
}

func frozenMembershipVersionReported(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	signed := buildMembershipProposal(
		t, fixture, fixture.editorDevice, event.ActorDaemon,
		event.KindMembershipVersionReported, string(fixture.editorDevice), 1,
		`{"daemon_version":"0.2.0","max_apply_level":2}`,
	)
	return frozenCase(event.KindMembershipVersionReported, fixture, signed)
}

func frozenMembershipRoleChanged(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	signed := buildMembershipProposal(
		t, fixture, fixture.ownerDevice, event.ActorHuman,
		event.KindMembershipRoleChanged, string(fixture.editorDevice), 1,
		fmt.Sprintf(`{"device_id":%q,"role":"owner"}`, fixture.editorDevice),
	)
	return frozenCase(event.KindMembershipRoleChanged, fixture, signed)
}

func frozenMembershipOwnerRecovered(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	payload := ownerRecoveryPayload(
		t, fixture, fixture.editorDevice, 1, fixture.recoveryPrivateKey,
	)
	signed := buildMembershipProposal(
		t, fixture, fixture.editorDevice, event.ActorHuman,
		event.KindMembershipOwnerRecovered, string(fixture.editorDevice), 1, payload,
	)
	return frozenCase(event.KindMembershipOwnerRecovered, fixture, signed)
}

func frozenMembershipDeviceRevoked(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	payload := revocationPayload(
		t, fixture.targetDevice, fixture.state.voterSet.VoterDeviceIDs(),
		fixture.state.voterSet.VoterSetVersion,
	)
	signed := buildMembershipProposal(
		t, fixture, fixture.ownerDevice, event.ActorHuman,
		event.KindMembershipDeviceRevoked, string(fixture.targetDevice), 1, payload,
	)
	return frozenCase(event.KindMembershipDeviceRevoked, fixture, signed)
}

func frozenMembershipVoterSetChanged(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	ids := []domain.DeviceID{
		fixture.editorDevice, fixture.ownerDevice, fixture.targetDevice,
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	signed := buildMembershipProposal(
		t, fixture, fixture.ownerDevice, event.ActorHuman,
		event.KindMembershipVoterSetChanged, string(testSessionID), 1,
		mustJSON(t, map[string]any{"voter_set": ids}),
	)
	return frozenCase(event.KindMembershipVoterSetChanged, fixture, signed)
}

func frozenMembershipVoterSetActivated(t *testing.T) frozenReducerCase {
	fixture, voterIDs := activationFixture(t)
	signed := buildMembershipProposal(
		t, fixture, fixture.ownerDevice, event.ActorDaemon,
		event.KindMembershipVoterSetActivated, string(testSessionID), 0,
		activationPayload(t, fixture, voterIDs),
	)
	return frozenCase(event.KindMembershipVoterSetActivated, fixture, signed)
}

func frozenPolicyChanged(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	values := policy.DefaultValues()
	values.CheckpointEvents++
	signed := buildPolicyProposal(
		t, fixture, fixture.ownerDevice, testSessionID, 1,
		policyPayload(t, values),
	)
	return frozenCase(event.KindPolicyChanged, fixture, signed)
}

func frozenCredentialAuthorized(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	options := defaultCredentialPayloadOptions(fixture)
	payload, _ := credentialPayload(t, fixture, options)
	signed := buildCredentialProposal(
		t, fixture, fixture.ownerDevice, fixture.editorDevice, 2, payload,
	)
	return frozenCase(event.KindCredentialAuthorized, fixture, signed)
}

func frozenControlFileChangeProposed(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	digest := sha256.Sum256([]byte("content"))
	signed := signedControlFileProposal(t, fixture, "AGENTS.md", map[string]any{
		"path":           "AGENTS.md",
		"operation":      "upsert",
		"content_digest": codec.EncodeBase64URL(digest[:]),
		"content_size":   7,
		"diff":           "change",
	})
	return frozenCase(event.KindControlFileChangeProposed, fixture, signed)
}

func frozenPublicationProposed(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	addPublicationLease(t, &fixture)
	fixture.state.tasks[testTaskID] = taskForReducerState(
		fixture, task.StateInProgress, 2,
	)
	metadata := testPublicationMetadata(
		fixture, testPublicationID, testPublicationEventID, testTaskID,
		fixture.state.canonicalRef.CommitOID, testReducerGitOID(20),
		testReducerGitOID(21),
	)
	receipts := signedStagingReceipts(
		t, fixture, metadata, fixture.state.currentResultIndex,
	)
	signed := buildRepositoryProposal(
		t, fixture, event.ActorAgent, fixture.editorDevice, testAgentSessionID,
		event.KindPublicationProposed, string(testPublicationID), 0,
		publicationPayload(t, metadata, receipts), testPublicationEventID, 2,
	)
	return frozenCase(event.KindPublicationProposed, fixture, signed)
}

func frozenPublicationReviewed(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	addReviewerAgent(t, &fixture)
	fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
	fixture.state.publications[testPublicationID] = testProposedPublication(
		t, fixture, testPublicationID, testPublicationEventID, testTaskID,
	)
	signed := buildRepositoryProposal(
		t, fixture, event.ActorAgent, fixture.targetDevice, testReviewerAgentID,
		event.KindPublicationReviewed, string(testPublicationID), 1,
		mustRawJSON(t, map[string]any{"verdict": "approve"}),
		testResolutionEventID, 2,
	)
	return frozenCase(event.KindPublicationReviewed, fixture, signed)
}

func frozenPublicationApplied(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	current := testApprovedPublication(
		t, fixture, testPublicationID, testPublicationEventID, testTaskID,
	)
	fixture.state.tasks[testTaskID] = testTask(task.StateDone, 1)
	fixture.state.publications[testPublicationID] = current
	receipts := signedStagingReceipts(
		t, fixture, current.Metadata, fixture.state.currentResultIndex,
	)
	signed := buildRepositoryProposal(
		t, fixture, event.ActorAgent, fixture.editorDevice, testAgentSessionID,
		event.KindPublicationApplied, string(testPublicationID), current.EntityVersion,
		mustRawJSON(t, map[string]any{
			"expected_canonical_ref_version": fixture.state.canonicalRef.EntityVersion,
			"staging_receipts":               stagingReceiptPayloads(receipts),
		}),
		testResolutionEventID, 2,
	)
	return frozenCase(event.KindPublicationApplied, fixture, signed)
}

func frozenPublicationWithdrawn(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	current := testProposedPublication(
		t, fixture, testPublicationID, testPublicationEventID, testTaskID,
	)
	fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
	fixture.state.publications[testPublicationID] = current
	signed := buildRepositoryProposal(
		t, fixture, event.ActorAgent, fixture.editorDevice, testAgentSessionID,
		event.KindPublicationWithdrawn, string(testPublicationID), current.EntityVersion,
		mustRawJSON(t, map[string]any{"reason": "superseded"}),
		testResolutionEventID, 2,
	)
	return frozenCase(event.KindPublicationWithdrawn, fixture, signed)
}

func frozenConflictDetected(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
	candidate := testProposedPublication(
		t, fixture, testPublicationID, testPublicationEventID, testTaskID,
	)
	fixture.state.publications[testPublicationID] = candidate
	value := testConflictForPublication(
		t, fixture, candidate, fixture.state.canonicalRef.CommitOID,
	)
	signed := buildRepositoryProposal(
		t, fixture, event.ActorDaemon, fixture.editorDevice, "",
		event.KindWorkspaceConflictDetected, string(value.ID), 0,
		mustRawJSON(t, conflictDetectionPayload(value)), testResolutionEventID, 2,
	)
	return frozenCase(event.KindWorkspaceConflictDetected, fixture, signed)
}

func frozenConflictForceResolved(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
	candidate := testProposedPublication(
		t, fixture, testPublicationID, testPublicationEventID, testTaskID,
	)
	value := testConflictForPublication(
		t, fixture, candidate, fixture.state.canonicalRef.CommitOID,
	)
	fixture.state.publications[testPublicationID] = candidate
	fixture.state.mergeConflicts[value.ID] = value
	fixture.state.unresolvedConflictsByTask[testTaskID] = 1
	signed := buildRepositoryProposal(
		t, fixture, event.ActorHuman, fixture.ownerDevice, "",
		event.KindWorkspaceConflictForceResolved, string(value.ID), value.EntityVersion,
		mustRawJSON(t, map[string]any{"reason": "fixture resolution"}),
		domainEventID(91), 2,
	)
	return frozenCase(event.KindWorkspaceConflictForceResolved, fixture, signed)
}

func frozenConflictResolved(t *testing.T) frozenReducerCase {
	fixture, value, resolution := resolvedConflictFixture(t)
	signed := buildRepositoryProposal(
		t, fixture, event.ActorAgent, fixture.editorDevice, testAgentSessionID,
		event.KindWorkspaceConflictResolved, string(value.ID), value.EntityVersion,
		mustRawJSON(t, map[string]any{
			"resolution_publication_id": resolution.Metadata.PublicationID,
		}),
		domainEventID(90), 2,
	)
	return frozenCase(event.KindWorkspaceConflictResolved, fixture, signed)
}

func frozenConsensusCheckpoint(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	payload, _ := signedCheckpointProofPayload(
		t, fixture, fixture.ownerDevice, nil,
	)
	directive, ok := decodeCheckpointProof(fixture.state, payload)
	if !ok {
		t.Fatal("decode checkpoint fixture")
	}
	applyContext := checkpointApplyContext(directive)
	fixture.state.currentChainIndex = applyContext.ChainIndex
	fixture.state.currentResultIndex = applyContext.ResultIndex
	signed := signedCheckpointEvent(t, fixture, payload)
	return frozenReducerCase{
		kind:   event.KindConsensusCheckpoint,
		state:  fixture.state,
		signed: signed,
		reduce: func(state State, signed event.SignedEvent) (Outcome, error) {
			return ReduceCheckpoint(state, signed, applyContext)
		},
	}
}

func frozenAuditRecorded(t *testing.T) frozenReducerCase {
	fixture := newReducerFixture(t)
	signed := signedAuditRecorded(
		t, fixture, validAuditPayload(fixture.ownerDevice, 0),
	)
	return frozenCase(event.KindAuditRecorded, fixture, signed)
}
