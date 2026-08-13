package reducer

import (
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestPublicationProposalRejectionMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*testing.T, *reducerFixture, *publication.Metadata)
		want    Code
	}{
		{
			name: "author metadata mismatch",
			prepare: func(
				_ *testing.T,
				fixture *reducerFixture,
				metadata *publication.Metadata,
			) {
				metadata.AuthorDeviceID = fixture.ownerDevice
			},
			want: CodePublicationAuthorMismatch,
		},
		{
			name: "working root mismatch",
			prepare: func(
				_ *testing.T,
				_ *reducerFixture,
				metadata *publication.Metadata,
			) {
				metadata.WorkingRootID = testReviewerRootID
			},
			want: CodePublicationWorkingRootMismatch,
		},
		{
			name: "task absent",
			prepare: func(
				_ *testing.T,
				_ *reducerFixture,
				metadata *publication.Metadata,
			) {
				metadata.TaskID = testTaskID
			},
			want: CodePublicationTaskNotFound,
		},
		{
			name: "task not held",
			prepare: func(
				_ *testing.T,
				fixture *reducerFixture,
				metadata *publication.Metadata,
			) {
				metadata.TaskID = testTaskID
				fixture.state.tasks[testTaskID] =
					testTask(task.StateReady, 1)
			},
			want: CodePublicationTaskHolderRequired,
		},
		{
			name: "superseded publication absent",
			prepare: func(
				_ *testing.T,
				_ *reducerFixture,
				metadata *publication.Metadata,
			) {
				metadata.SupersedesPublicationID =
					testResolutionPublicationID
			},
			want: CodePublicationSupersedesNotFound,
		},
		{
			name: "superseded publication nonterminal",
			prepare: func(
				t *testing.T,
				fixture *reducerFixture,
				metadata *publication.Metadata,
			) {
				previous := testProposedPublication(
					t,
					*fixture,
					testResolutionPublicationID,
					testResolutionEventID,
					"",
				)
				fixture.state.publications[previous.Metadata.PublicationID] =
					previous
				metadata.SupersedesPublicationID =
					previous.Metadata.PublicationID
			},
			want: CodePublicationSupersedesNotTerminal,
		},
		{
			name: "declared conflict absent",
			prepare: func(
				_ *testing.T,
				_ *reducerFixture,
				metadata *publication.Metadata,
			) {
				metadata.ResolvesConflictIDs = []domain.ConflictID{
					domain.ConflictID("ccf1" + strings.Repeat("a", 64)),
				}
			},
			want: CodePublicationConflictNotFound,
		},
		{
			name: "declared conflict already resolved",
			prepare: func(
				t *testing.T,
				fixture *reducerFixture,
				metadata *publication.Metadata,
			) {
				candidate := testProposedPublication(
					t,
					*fixture,
					testResolutionPublicationID,
					testResolutionEventID,
					"",
				)
				value := testConflictForPublication(
					t,
					*fixture,
					candidate,
					fixture.state.canonicalRef.CommitOID,
				)
				value.Status = conflict.StatusResolved
				value.ResolutionKind = conflict.ResolutionKindForced
				value.ForceReason = "operator accepted loss"
				value.ResolvedByDeviceID = fixture.ownerDevice
				value.EntityVersion = 2
				fixture.state.publications[candidate.Metadata.PublicationID] =
					candidate
				fixture.state.mergeConflicts[value.ID] = value
				metadata.ResolvesConflictIDs = []domain.ConflictID{value.ID}
			},
			want: CodePublicationConflictNotUnresolved,
		},
		{
			name: "control path",
			prepare: func(
				_ *testing.T,
				_ *reducerFixture,
				metadata *publication.Metadata,
			) {
				metadata.Paths = []domain.RepositoryPath{".gitignore"}
			},
			want: CodePublicationControlPath,
		},
		{
			name: "path lease absent",
			prepare: func(
				_ *testing.T,
				fixture *reducerFixture,
				_ *publication.Metadata,
			) {
				fixture.state.removeActiveLease(
					fixture.state.leases[testPublicationLeaseID],
				)
				delete(fixture.state.leases, testPublicationLeaseID)
			},
			want: CodePublicationPathLeaseRequired,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			addPublicationLease(t, &fixture)
			metadata := testPublicationMetadata(
				fixture,
				testPublicationID,
				testPublicationEventID,
				"",
				fixture.state.canonicalRef.CommitOID,
				testReducerGitOID(60),
				testReducerGitOID(61),
			)
			test.prepare(t, &fixture, &metadata)
			receipts := signedStagingReceipts(
				t,
				fixture,
				metadata,
				fixture.state.currentResultIndex,
			)
			signed := buildRepositoryProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				testAgentSessionID,
				event.KindPublicationProposed,
				string(metadata.PublicationID),
				0,
				publicationPayload(t, metadata, receipts),
				metadata.ProposalEventID,
				2,
			)

			assertRejectedCode(t, fixture.state, signed, test.want)
		})
	}
}

func TestPublicationProposalReceiptRejectionMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		prepare  func(*testing.T, *reducerFixture, publication.Metadata) []publication.StagingReceipt
		want     Code
		accepted bool
	}{
		{
			name: "empty quorum",
			prepare: func(
				_ *testing.T,
				_ *reducerFixture,
				_ publication.Metadata,
			) []publication.StagingReceipt {
				return nil
			},
			want: CodePublicationReceiptQuorumNotMet,
		},
		{
			name: "future result",
			prepare: func(
				t *testing.T,
				fixture *reducerFixture,
				metadata publication.Metadata,
			) []publication.StagingReceipt {
				return signedStagingReceipts(
					t,
					*fixture,
					metadata,
					fixture.state.currentResultIndex+1,
				)
			},
			want: CodePublicationReceiptFromFuture,
		},
		{
			name: "one past stale window",
			prepare: func(
				t *testing.T,
				fixture *reducerFixture,
				metadata publication.Metadata,
			) []publication.StagingReceipt {
				fixture.state.currentResultIndex =
					publicationReceiptWindow + 1
				return signedStagingReceipts(t, *fixture, metadata, 0)
			},
			want: CodePublicationReceiptStale,
		},
		{
			name: "bad signature",
			prepare: func(
				t *testing.T,
				fixture *reducerFixture,
				metadata publication.Metadata,
			) []publication.StagingReceipt {
				receipts := signedStagingReceipts(
					t,
					*fixture,
					metadata,
					fixture.state.currentResultIndex,
				)
				receipts[0].Signature[0] ^= 0xff
				return receipts
			},
			want: CodeInvalidPublicationReceipts,
		},
		{
			name: "exact stale boundary",
			prepare: func(
				t *testing.T,
				fixture *reducerFixture,
				metadata publication.Metadata,
			) []publication.StagingReceipt {
				fixture.state.currentResultIndex =
					publicationReceiptWindow + 1
				return signedStagingReceipts(t, *fixture, metadata, 1)
			},
			accepted: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			addPublicationLease(t, &fixture)
			metadata := testPublicationMetadata(
				fixture,
				testPublicationID,
				testPublicationEventID,
				"",
				fixture.state.canonicalRef.CommitOID,
				testReducerGitOID(62),
				testReducerGitOID(63),
			)
			receipts := test.prepare(t, &fixture, metadata)
			signed := buildRepositoryProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				testAgentSessionID,
				event.KindPublicationProposed,
				string(metadata.PublicationID),
				0,
				publicationPayload(t, metadata, receipts),
				metadata.ProposalEventID,
				2,
			)

			if test.accepted {
				assertAccepted(t, fixture.state, signed)
			} else {
				assertRejectedCode(t, fixture.state, signed, test.want)
			}
		})
	}
}

func TestPublicationReviewApplyAndWithdrawalRejectionMatrix(t *testing.T) {
	t.Parallel()

	t.Run("same-device agent review", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		current := testProposedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			"",
		)
		fixture.state.publications[current.Metadata.PublicationID] = current
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorAgent,
			fixture.editorDevice,
			testAgentSessionID,
			event.KindPublicationReviewed,
			string(current.Metadata.PublicationID),
			current.EntityVersion,
			mustRawJSON(t, map[string]any{"verdict": "approve"}),
			domainEventID(100),
			2,
		)
		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodePublicationReviewNotIndependent,
		)
	})

	t.Run("review terminal publication", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		current := testApprovedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			"",
		)
		fixture.state.publications[current.Metadata.PublicationID] = current
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.editorDevice,
			"",
			event.KindPublicationReviewed,
			string(current.Metadata.PublicationID),
			current.EntityVersion,
			mustRawJSON(t, map[string]any{"verdict": "approve"}),
			domainEventID(101),
			2,
		)
		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodeInvalidPublicationTransition,
		)
	})

	t.Run("foreign agent withdrawal", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		addReviewerAgent(t, &fixture)
		current := testProposedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			"",
		)
		fixture.state.publications[current.Metadata.PublicationID] = current
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorAgent,
			fixture.targetDevice,
			testReviewerAgentID,
			event.KindPublicationWithdrawn,
			string(current.Metadata.PublicationID),
			current.EntityVersion,
			mustRawJSON(t, map[string]any{}),
			domainEventID(102),
			2,
		)
		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodePublicationWithdrawalNotAuthorized,
		)
	})

	t.Run("foreign editor withdrawal", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		addBootScope(&fixture, fixture.targetDevice)
		current := testProposedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			"",
		)
		fixture.state.publications[current.Metadata.PublicationID] = current
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.targetDevice,
			"",
			event.KindPublicationWithdrawn,
			string(current.Metadata.PublicationID),
			current.EntityVersion,
			mustRawJSON(t, map[string]any{}),
			domainEventID(103),
			2,
		)
		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodePublicationWithdrawalNotAuthorized,
		)
	})

	t.Run("canonical ref CAS mismatch", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		current := testApprovedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			"",
		)
		fixture.state.publications[current.Metadata.PublicationID] = current
		receipts := signedStagingReceipts(
			t,
			fixture,
			current.Metadata,
			fixture.state.currentResultIndex,
		)
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.editorDevice,
			"",
			event.KindPublicationApplied,
			string(current.Metadata.PublicationID),
			current.EntityVersion,
			mustRawJSON(t, map[string]any{
				"expected_canonical_ref_version": fixture.state.canonicalRef.EntityVersion + 1,
				"staging_receipts":               stagingReceiptPayloads(receipts),
			}),
			domainEventID(104),
			2,
		)
		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodeCanonicalRefVersionMismatch,
		)
	})

	t.Run("canonical ref exhausted", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		current := testApprovedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			"",
		)
		fixture.state.publications[current.Metadata.PublicationID] = current
		fixture.state.canonicalRef.EntityVersion = domain.MaxSafeInteger
		receipts := signedStagingReceipts(
			t,
			fixture,
			current.Metadata,
			fixture.state.currentResultIndex,
		)
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.editorDevice,
			"",
			event.KindPublicationApplied,
			string(current.Metadata.PublicationID),
			current.EntityVersion,
			mustRawJSON(t, map[string]any{
				"expected_canonical_ref_version": domain.MaxSafeInteger,
				"staging_receipts":               stagingReceiptPayloads(receipts),
			}),
			domainEventID(105),
			2,
		)
		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodeCanonicalRefVersionExhausted,
		)
	})

	t.Run("base commit stale", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		current := testApprovedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			"",
		)
		fixture.state.publications[current.Metadata.PublicationID] = current
		fixture.state.canonicalRef.CommitOID = testReducerGitOID(64)
		fixture.state.canonicalRef.EntityVersion++
		receipts := signedStagingReceipts(
			t,
			fixture,
			current.Metadata,
			fixture.state.currentResultIndex,
		)
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.editorDevice,
			"",
			event.KindPublicationApplied,
			string(current.Metadata.PublicationID),
			current.EntityVersion,
			mustRawJSON(t, map[string]any{
				"expected_canonical_ref_version": fixture.state.canonicalRef.EntityVersion,
				"staging_receipts":               stagingReceiptPayloads(receipts),
			}),
			domainEventID(106),
			2,
		)
		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodePublicationBaseCommitMismatch,
		)
	})
}

func TestPublicationApplyReceiptRejectionMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(
			*testing.T,
			*reducerFixture,
			publication.Metadata,
		) []publication.StagingReceipt
		want Code
	}{
		{
			name: "empty quorum",
			prepare: func(
				_ *testing.T,
				_ *reducerFixture,
				_ publication.Metadata,
			) []publication.StagingReceipt {
				return nil
			},
			want: CodePublicationReceiptQuorumNotMet,
		},
		{
			name: "future result",
			prepare: func(
				t *testing.T,
				fixture *reducerFixture,
				metadata publication.Metadata,
			) []publication.StagingReceipt {
				return signedStagingReceipts(
					t,
					*fixture,
					metadata,
					fixture.state.currentResultIndex+1,
				)
			},
			want: CodePublicationReceiptFromFuture,
		},
		{
			name: "stale result",
			prepare: func(
				t *testing.T,
				fixture *reducerFixture,
				metadata publication.Metadata,
			) []publication.StagingReceipt {
				fixture.state.currentResultIndex =
					publicationReceiptWindow + 1
				return signedStagingReceipts(t, *fixture, metadata, 0)
			},
			want: CodePublicationReceiptStale,
		},
		{
			name: "bad signature",
			prepare: func(
				t *testing.T,
				fixture *reducerFixture,
				metadata publication.Metadata,
			) []publication.StagingReceipt {
				receipts := signedStagingReceipts(
					t,
					*fixture,
					metadata,
					fixture.state.currentResultIndex,
				)
				receipts[0].Signature[0] ^= 0xff
				return receipts
			},
			want: CodeInvalidPublicationReceipts,
		},
		{
			name: "signer outside voter target",
			prepare: func(
				t *testing.T,
				fixture *reducerFixture,
				metadata publication.Metadata,
			) []publication.StagingReceipt {
				return signedStagingReceipts(
					t,
					*fixture,
					metadata,
					fixture.state.currentResultIndex,
					fixture.editorDevice,
				)
			},
			want: CodeInvalidPublicationReceipts,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			current := testApprovedPublication(
				t,
				fixture,
				testPublicationID,
				testPublicationEventID,
				"",
			)
			fixture.state.publications[current.Metadata.PublicationID] =
				current
			receipts := test.prepare(t, &fixture, current.Metadata)
			signed := buildRepositoryProposal(
				t,
				fixture,
				event.ActorHuman,
				fixture.editorDevice,
				"",
				event.KindPublicationApplied,
				string(current.Metadata.PublicationID),
				current.EntityVersion,
				mustRawJSON(t, map[string]any{
					"expected_canonical_ref_version": fixture.state.canonicalRef.EntityVersion,
					"staging_receipts":               stagingReceiptPayloads(receipts),
				}),
				domainEventID(120),
				2,
			)

			assertRejectedCode(t, fixture.state, signed, test.want)
		})
	}
}

func TestPublicationApplyRejectsNonApprovedTransition(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	current := testProposedPublication(
		t,
		fixture,
		testPublicationID,
		testPublicationEventID,
		"",
	)
	fixture.state.publications[current.Metadata.PublicationID] = current
	receipts := signedStagingReceipts(
		t,
		fixture,
		current.Metadata,
		fixture.state.currentResultIndex,
	)
	signed := buildRepositoryProposal(
		t,
		fixture,
		event.ActorHuman,
		fixture.editorDevice,
		"",
		event.KindPublicationApplied,
		string(current.Metadata.PublicationID),
		current.EntityVersion,
		mustRawJSON(t, map[string]any{
			"expected_canonical_ref_version": fixture.state.canonicalRef.EntityVersion,
			"staging_receipts":               stagingReceiptPayloads(receipts),
		}),
		domainEventID(121),
		2,
	)

	assertRejectedCode(
		t,
		fixture.state,
		signed,
		CodeInvalidPublicationTransition,
	)
}
