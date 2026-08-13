package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestVerifyCommitmentCutAcceptsBoundaryAndHistoricalPositions(
	t *testing.T,
) {
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initialHeads := initializeTestStore(t, value)
	first, err := value.Apply(
		context.Background(),
		acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1)),
	)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	second, err := value.Apply(
		context.Background(),
		rejectedApplyRequest(
			t,
			testSignedTaskEvent(t, testEventID2, 2),
			first.Heads,
		),
	)
	if err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	stateDigest, err := value.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(): %v", err)
	}

	for _, cut := range []CommitmentCut{
		commitmentCutForTest(initialHeads, stateDigest),
		commitmentCutForTest(first.Heads, stateDigest),
		commitmentCutForTest(second.Heads, stateDigest),
	} {
		if err := value.VerifyCommitmentCut(
			context.Background(),
			cut,
		); err != nil {
			t.Fatalf("VerifyCommitmentCut(%+v): %v", cut, err)
		}
	}
}

func TestVerifyCommitmentCutRejectsNonAncestor(t *testing.T) {
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initialHeads := initializeTestStore(t, value)
	result, err := value.Apply(
		context.Background(),
		acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1)),
	)
	if err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	stateDigest, err := value.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(): %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CommitmentCut)
	}{
		{
			name: "result hash",
			mutate: func(cut *CommitmentCut) {
				cut.ResultHash[0] ^= 0xff
			},
		},
		{
			name: "event hash",
			mutate: func(cut *CommitmentCut) {
				cut.ChainHash[0] ^= 0xff
			},
		},
		{
			name: "event head from earlier result cut",
			mutate: func(cut *CommitmentCut) {
				cut.ChainIndex = initialHeads.ChainIndex
				cut.ChainHash = initialHeads.ChainHash
			},
		},
		{
			name: "projection accumulator",
			mutate: func(cut *CommitmentCut) {
				cut.ProjectionAccumulator[0] ^= 0xff
			},
		},
		{
			name: "projection state digest",
			mutate: func(cut *CommitmentCut) {
				cut.ProjectionStateDigest[0] ^= 0xff
			},
		},
		{
			name: "future result",
			mutate: func(cut *CommitmentCut) {
				cut.ResultIndex++
			},
		},
		{
			name: "other generation",
			mutate: func(cut *CommitmentCut) {
				cut.RecoveryGeneration++
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cut := commitmentCutForTest(result.Heads, stateDigest)
			test.mutate(&cut)
			if err := value.VerifyCommitmentCut(
				context.Background(),
				cut,
			); !errors.Is(err, ErrCommitmentCutNotCovered) {
				t.Fatalf(
					"VerifyCommitmentCut() error = %v, want ErrCommitmentCutNotCovered",
					err,
				)
			}
		})
	}
}

func TestVerifyCommitmentCutRewindsProjectionMutations(t *testing.T) {
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, value)
	fixture := newProjectionFixture(t)
	firstRequest := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	firstRequest.Projections = fixture.initialWrites
	first, err := value.Apply(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	firstDigest, err := value.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(first): %v", err)
	}
	secondRequest := nextProjectionApplyRequest(t, first.Heads)
	secondRequest.Projections = fixture.updatedWrites
	second, err := value.Apply(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	secondDigest, err := value.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(second): %v", err)
	}

	for _, cut := range []CommitmentCut{
		commitmentCutForTest(first.Heads, firstDigest),
		commitmentCutForTest(second.Heads, secondDigest),
	} {
		if err := value.VerifyCommitmentCut(
			context.Background(),
			cut,
		); err != nil {
			t.Fatalf("VerifyCommitmentCut(%d): %v", cut.ResultIndex, err)
		}
	}
}

func commitmentCutForTest(
	heads ApplyHeads,
	stateDigest Digest,
) CommitmentCut {
	return CommitmentCut{
		SessionID:               domain.UUIDv7(testSessionID),
		RecoveryGeneration:      0,
		ChainIndex:              heads.ChainIndex,
		ChainHash:               heads.ChainHash,
		ResultIndex:             heads.ResultIndex,
		ResultHash:              heads.ResultHash,
		ProjectionAccumulator:   heads.ProjectionAccumulator,
		ProjectionStateDigest:   stateDigest,
		DigestVersion:           heads.DigestVersion,
		ProjectionSchemaVersion: heads.ProjectionSchemaVersion,
	}
}
