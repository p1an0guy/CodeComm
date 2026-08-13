package publication

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	testPublicationID   = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abc")
	testProposalEventID = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abd")
	testSupersedesID    = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abe")
	testTaskID          = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abf")
	testAuthorSessionID = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789ac0")
	testWorkingRootID   = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789ac1")
	testReviewerSession = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789ac2")
	testSessionID       = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789ac3")
	testWorkspaceID     = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")

	testAuthorDevice = domain.DeviceID("cc10000000000000000000000000000000000000000000000000000000000000000")
	testVoterA       = domain.DeviceID("cc11111111111111111111111111111111111111111111111111111111111111111")
	testVoterB       = domain.DeviceID("cc12222222222222222222222222222222222222222222222222222222222222222")
	testVoterC       = domain.DeviceID("cc13333333333333333333333333333333333333333333333333333333333333333")
	testVoterD       = domain.DeviceID("cc14444444444444444444444444444444444444444444444444444444444444444")
	testVoterE       = domain.DeviceID("cc15555555555555555555555555555555555555555555555555555555555555555")

	testBaseCommit = domain.GitOID("sha1:0000000000000000000000000000000000000001")
	testCommitOID  = domain.GitOID("sha1:0000000000000000000000000000000000000002")
	testTreeOID    = domain.GitOID("sha1:0000000000000000000000000000000000000003")
)

func TestMetadataValidateAcceptsExactBoundaries(t *testing.T) {
	t.Parallel()

	metadata := validMetadata()
	metadata.ParentOIDs = makeGitOIDs(MaxParentOIDs)
	metadata.ParentOIDs[0] = metadata.BaseCommit
	metadata.Paths = makePaths(MaxPaths)
	metadata.ResolvesConflictIDs = makeConflictIDs(MaxResolvedConflictIDs)

	if err := metadata.Validate(); err != nil {
		t.Fatalf("Metadata.Validate() error = %v", err)
	}
}

func TestMetadataValidateRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	sha256OID := domain.GitOID("sha256:" + strings.Repeat("a", 64))
	tests := []struct {
		name   string
		mutate func(*Metadata)
		want   error
	}{
		{"publication ID", func(value *Metadata) { value.PublicationID = "bad" }, ErrInvalidPublicationID},
		{"proposal event ID", func(value *Metadata) { value.ProposalEventID = "bad" }, ErrInvalidProposalEventID},
		{"supersedes ID", func(value *Metadata) { value.SupersedesPublicationID = "bad" }, ErrInvalidSupersedesPublicationID},
		{"supersedes self", func(value *Metadata) {
			value.SupersedesPublicationID = value.PublicationID
		}, ErrInvalidSupersedesPublicationID},
		{"task ID", func(value *Metadata) { value.TaskID = "bad" }, ErrInvalidTaskID},
		{"author device ID", func(value *Metadata) { value.AuthorDeviceID = "bad" }, ErrInvalidAuthorDeviceID},
		{"author session ID", func(value *Metadata) { value.AuthorAgentSessionID = "bad" }, ErrInvalidAuthorAgentSessionID},
		{"base commit", func(value *Metadata) { value.BaseCommit = "bad" }, ErrInvalidBaseCommit},
		{"commit OID", func(value *Metadata) { value.CommitOID = "bad" }, ErrInvalidCommitOID},
		{"tree OID", func(value *Metadata) { value.TreeOID = "bad" }, ErrInvalidTreeOID},
		{"commit object format", func(value *Metadata) { value.CommitOID = sha256OID }, ErrObjectFormatMismatch},
		{"tree object format", func(value *Metadata) { value.TreeOID = sha256OID }, ErrObjectFormatMismatch},
		{"no parents", func(value *Metadata) { value.ParentOIDs = nil }, ErrInvalidParentOIDs},
		{"too many parents", func(value *Metadata) {
			value.ParentOIDs = makeGitOIDs(MaxParentOIDs + 1)
			value.ParentOIDs[0] = value.BaseCommit
		}, ErrInvalidParentOIDs},
		{"invalid parent", func(value *Metadata) { value.ParentOIDs[1] = "bad" }, ErrInvalidParentOIDs},
		{"first parent differs from base", func(value *Metadata) {
			value.ParentOIDs[0] = testCommitOID
		}, ErrInvalidParentOIDs},
		{"parent object format", func(value *Metadata) { value.ParentOIDs[1] = sha256OID }, ErrObjectFormatMismatch},
		{"no paths", func(value *Metadata) { value.Paths = nil }, ErrInvalidPaths},
		{"too many paths", func(value *Metadata) { value.Paths = makePaths(MaxPaths + 1) }, ErrInvalidPaths},
		{"invalid path", func(value *Metadata) { value.Paths[0] = "../outside" }, ErrInvalidPaths},
		{"unsorted paths", func(value *Metadata) {
			value.Paths = []domain.RepositoryPath{"b.txt", "a.txt"}
		}, ErrInvalidPaths},
		{"duplicate paths", func(value *Metadata) {
			value.Paths = []domain.RepositoryPath{"a.txt", "a.txt"}
		}, ErrInvalidPaths},
		{"too many conflicts", func(value *Metadata) {
			value.ResolvesConflictIDs = makeConflictIDs(MaxResolvedConflictIDs + 1)
		}, ErrInvalidConflictIDs},
		{"invalid conflict", func(value *Metadata) {
			value.ResolvesConflictIDs = []domain.ConflictID{"bad"}
		}, ErrInvalidConflictIDs},
		{"unsorted conflicts", func(value *Metadata) {
			ids := makeConflictIDs(2)
			value.ResolvesConflictIDs = []domain.ConflictID{ids[1], ids[0]}
		}, ErrInvalidConflictIDs},
		{"duplicate conflicts", func(value *Metadata) {
			id := makeConflictIDs(1)[0]
			value.ResolvesConflictIDs = []domain.ConflictID{id, id}
		}, ErrInvalidConflictIDs},
		{"working root ID", func(value *Metadata) { value.WorkingRootID = "bad" }, ErrInvalidWorkingRootID},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			metadata := validMetadata()
			test.mutate(&metadata)
			if err := metadata.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Metadata.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestMetadataValidateAcceptsOptionalIDs(t *testing.T) {
	t.Parallel()

	metadata := validMetadata()
	metadata.SupersedesPublicationID = ""
	metadata.TaskID = ""
	if err := metadata.Validate(); err != nil {
		t.Fatalf("Metadata.Validate() error = %v", err)
	}
}

func TestStagingReceiptsValidateExactBoundsAndSharedContext(t *testing.T) {
	t.Parallel()

	voters := []domain.DeviceID{testVoterA, testVoterB, testVoterC, testVoterD, testVoterE}
	receipts := make([]StagingReceipt, len(voters))
	for index, voter := range voters {
		receipts[index] = validReceipt(voter)
		receipts[index].StagedResultIndex = uint64(index)
	}
	receipts[len(receipts)-1].StagedResultIndex = domain.MaxSafeInteger
	receipts[0].VoterSetVersion = domain.MaxSafeInteger
	for index := 1; index < len(receipts); index++ {
		receipts[index].VoterSetVersion = domain.MaxSafeInteger
	}

	if err := ValidateStagingReceipts(receipts); err != nil {
		t.Fatalf("ValidateStagingReceipts() error = %v", err)
	}
	if err := ValidateStagingReceipts(nil); err != nil {
		t.Fatalf("ValidateStagingReceipts(nil) error = %v", err)
	}
}

func TestStagingReceiptsRejectInvalidValues(t *testing.T) {
	t.Parallel()

	otherSession := domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789ad0")
	otherWorkspace := domain.UUIDv4("550e8400-e29b-41d4-a716-446655440001")
	tests := []struct {
		name     string
		receipts func() []StagingReceipt
		want     error
	}{
		{"too many", func() []StagingReceipt {
			result := make([]StagingReceipt, MaxStagingReceipts+1)
			for index := range result {
				result[index] = validReceipt(domain.DeviceID(fmt.Sprintf("cc1%064x", index+1)))
			}
			return result
		}, ErrInvalidStagingReceipts},
		{"session ID", func() []StagingReceipt {
			value := validReceipt(testVoterA)
			value.SessionID = "bad"
			return []StagingReceipt{value}
		}, ErrInvalidReceiptSessionID},
		{"workspace ID", func() []StagingReceipt {
			value := validReceipt(testVoterA)
			value.WorkspaceID = "bad"
			return []StagingReceipt{value}
		}, ErrInvalidReceiptWorkspaceID},
		{"voter ID", func() []StagingReceipt {
			value := validReceipt(testVoterA)
			value.VoterDeviceID = "bad"
			return []StagingReceipt{value}
		}, ErrInvalidReceiptVoterDeviceID},
		{"zero voter-set version", func() []StagingReceipt {
			value := validReceipt(testVoterA)
			value.VoterSetVersion = 0
			return []StagingReceipt{value}
		}, ErrInvalidReceiptVoterSetVersion},
		{"large voter-set version", func() []StagingReceipt {
			value := validReceipt(testVoterA)
			value.VoterSetVersion = domain.MaxSafeInteger + 1
			return []StagingReceipt{value}
		}, ErrInvalidReceiptVoterSetVersion},
		{"large result index", func() []StagingReceipt {
			value := validReceipt(testVoterA)
			value.StagedResultIndex = domain.MaxSafeInteger + 1
			return []StagingReceipt{value}
		}, ErrInvalidReceiptResultIndex},
		{"unsorted voters", func() []StagingReceipt {
			return []StagingReceipt{validReceipt(testVoterB), validReceipt(testVoterA)}
		}, ErrInvalidStagingReceipts},
		{"duplicate voters", func() []StagingReceipt {
			return []StagingReceipt{validReceipt(testVoterA), validReceipt(testVoterA)}
		}, ErrInvalidStagingReceipts},
		{"mixed sessions", func() []StagingReceipt {
			second := validReceipt(testVoterB)
			second.SessionID = otherSession
			return []StagingReceipt{validReceipt(testVoterA), second}
		}, ErrInconsistentReceiptContext},
		{"mixed workspaces", func() []StagingReceipt {
			second := validReceipt(testVoterB)
			second.WorkspaceID = otherWorkspace
			return []StagingReceipt{validReceipt(testVoterA), second}
		}, ErrInconsistentReceiptContext},
		{"mixed metadata digests", func() []StagingReceipt {
			second := validReceipt(testVoterB)
			second.PublicationMetadataDigest[0]++
			return []StagingReceipt{validReceipt(testVoterA), second}
		}, ErrInconsistentReceiptContext},
		{"mixed voter-set versions", func() []StagingReceipt {
			second := validReceipt(testVoterB)
			second.VoterSetVersion++
			return []StagingReceipt{validReceipt(testVoterA), second}
		}, ErrInconsistentReceiptContext},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateStagingReceipts(test.receipts()); !errors.Is(err, test.want) {
				t.Fatalf("ValidateStagingReceipts() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPublicationValidateAcceptsEveryConsistentLifecycle(t *testing.T) {
	t.Parallel()

	publications := []Publication{
		validProposed(),
		validApproved(ReviewActorHuman),
		validApproved(ReviewActorAgent),
		validRejected(),
		validWithdrawn(false),
		validWithdrawn(true),
		validRecoveryWithdrawn(),
		validApplied(true),
		validApplied(false),
	}
	for _, publication := range publications {
		if err := publication.Validate(); err != nil {
			t.Errorf("Publication.Validate() for state %q/source %q error = %v", publication.State, publication.TerminalSource, err)
		}
	}
}

func TestPublicationValidateRejectsInconsistentLifecycleFields(t *testing.T) {
	t.Parallel()

	reason := "withdrawn"
	tests := []struct {
		name  string
		value func() Publication
		want  error
	}{
		{"invalid state", func() Publication {
			value := validProposed()
			value.State = "unknown"
			return value
		}, ErrInvalidState},
		{"proposed terminal source", func() Publication {
			value := validProposed()
			value.TerminalSource = TerminalSourceWithdraw
			return value
		}, ErrInvalidTerminalSource},
		{"proposed lineage", func() Publication {
			value := validProposed()
			value.CanonicalLineageMember = true
			return value
		}, ErrInvalidCanonicalLineage},
		{"proposed review", func() Publication {
			value := validProposed()
			setHumanApproval(&value)
			return value
		}, ErrInvalidReview},
		{"proposed decision reason", func() Publication {
			value := validProposed()
			value.DecisionReason = &reason
			return value
		}, ErrInvalidDecisionReason},
		{"approved missing review", func() Publication {
			value := validApproved(ReviewActorHuman)
			clearReview(&value)
			return value
		}, ErrInvalidReview},
		{"approved reject verdict", func() Publication {
			value := validApproved(ReviewActorHuman)
			value.ReviewVerdict = ReviewVerdictReject
			return value
		}, ErrInvalidReview},
		{"rejected wrong source", func() Publication {
			value := validRejected()
			value.TerminalSource = TerminalSourceWithdraw
			return value
		}, ErrInvalidTerminalSource},
		{"rejected approve verdict", func() Publication {
			value := validRejected()
			value.ReviewVerdict = ReviewVerdictApprove
			return value
		}, ErrInvalidReview},
		{"withdrawn reject review", func() Publication {
			value := validWithdrawn(true)
			value.ReviewVerdict = ReviewVerdictReject
			return value
		}, ErrInvalidReview},
		{"withdrawn lineage", func() Publication {
			value := validWithdrawn(false)
			value.CanonicalLineageMember = true
			return value
		}, ErrInvalidCanonicalLineage},
		{"recovery missing reason", func() Publication {
			value := validRecoveryWithdrawn()
			value.DecisionReason = nil
			return value
		}, ErrInvalidDecisionReason},
		{"recovery noncanonical reason", func() Publication {
			value := validRecoveryWithdrawn()
			reason := "different recovery reason"
			value.DecisionReason = &reason
			return value
		}, ErrInvalidDecisionReason},
		{"applied wrong source", func() Publication {
			value := validApplied(true)
			value.TerminalSource = TerminalSourceReview
			return value
		}, ErrInvalidTerminalSource},
		{"applied reject verdict", func() Publication {
			value := validApplied(true)
			value.ReviewVerdict = ReviewVerdictReject
			return value
		}, ErrInvalidReview},
		{"zero entity version", func() Publication {
			value := validProposed()
			value.EntityVersion = 0
			return value
		}, ErrInvalidEntityVersion},
		{"large entity version", func() Publication {
			value := validProposed()
			value.EntityVersion = domain.MaxSafeInteger + 1
			return value
		}, ErrInvalidEntityVersion},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.value().Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Publication.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPublicationValidateEnforcesReviewActorFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Publication)
	}{
		{"invalid verdict", func(value *Publication) { value.ReviewVerdict = "unknown" }},
		{"missing reviewer device", func(value *Publication) { value.ReviewerDeviceID = "" }},
		{"invalid reviewer device", func(value *Publication) { value.ReviewerDeviceID = "bad" }},
		{"invalid actor type", func(value *Publication) { value.ReviewActorType = "daemon" }},
		{"agent missing session", func(value *Publication) {
			value.ReviewActorType = ReviewActorAgent
			value.ReviewerAgentSessionID = ""
		}},
		{"agent invalid session", func(value *Publication) {
			value.ReviewActorType = ReviewActorAgent
			value.ReviewerAgentSessionID = "bad"
		}},
		{"human carries session", func(value *Publication) {
			value.ReviewActorType = ReviewActorHuman
			value.ReviewerAgentSessionID = testReviewerSession
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validApproved(ReviewActorHuman)
			test.mutate(&value)
			if err := value.Validate(); !errors.Is(err, ErrInvalidReview) {
				t.Fatalf("Publication.Validate() error = %v, want ErrInvalidReview", err)
			}
		})
	}
}

func TestDecisionReasonUsesOptionalOneTo1024UTF8Bytes(t *testing.T) {
	t.Parallel()

	value := validWithdrawn(false)
	value.DecisionReason = nil
	if err := value.Validate(); err != nil {
		t.Fatalf("optional reason error = %v", err)
	}

	for _, reason := range []string{"x", strings.Repeat("é", MaxDecisionReasonBytes/2)} {
		value.DecisionReason = &reason
		if err := value.Validate(); err != nil {
			t.Errorf("valid %d-byte reason error = %v", len(reason), err)
		}
	}

	for _, reason := range []string{"", strings.Repeat("x", MaxDecisionReasonBytes+1), string([]byte{0xff})} {
		value.DecisionReason = &reason
		if err := value.Validate(); !errors.Is(err, ErrInvalidDecisionReason) {
			t.Errorf("invalid reason %q error = %v, want ErrInvalidDecisionReason", reason, err)
		}
	}
}

func TestStateEnumsAndTerminalClassification(t *testing.T) {
	t.Parallel()

	wantStates := []State{StateProposed, StateApproved, StateApplied, StateRejected, StateWithdrawn}
	if got := States(); fmt.Sprint(got) != fmt.Sprint(wantStates) {
		t.Fatalf("States() = %v, want %v", got, wantStates)
	}
	for _, state := range wantStates {
		if !state.Valid() {
			t.Errorf("%q.Valid() = false", state)
		}
		wantTerminal := state == StateApplied || state == StateRejected || state == StateWithdrawn
		if state.Terminal() != wantTerminal {
			t.Errorf("%q.Terminal() = %t, want %t", state, state.Terminal(), wantTerminal)
		}
	}
	states := States()
	states[0] = "corrupt"
	if States()[0] != StateProposed {
		t.Fatal("States() did not return a defensive copy")
	}
}

func TestCanonicalRefValidate(t *testing.T) {
	t.Parallel()

	for _, version := range []uint64{1, domain.MaxSafeInteger} {
		ref := CanonicalRef{
			RefName:       CanonicalRefName,
			CommitOID:     testBaseCommit,
			EntityVersion: version,
		}
		if err := ref.Validate(); err != nil {
			t.Errorf("CanonicalRef.Validate() at version %d error = %v", version, err)
		}
	}

	tests := []struct {
		name   string
		mutate func(*CanonicalRef)
		want   error
	}{
		{"name", func(value *CanonicalRef) { value.RefName = "refs/heads/main" }, ErrInvalidCanonicalRefName},
		{"commit", func(value *CanonicalRef) { value.CommitOID = "bad" }, ErrInvalidCanonicalCommit},
		{"zero version", func(value *CanonicalRef) { value.EntityVersion = 0 }, ErrInvalidCanonicalRefVersion},
		{"large version", func(value *CanonicalRef) {
			value.EntityVersion = domain.MaxSafeInteger + 1
		}, ErrInvalidCanonicalRefVersion},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ref := CanonicalRef{RefName: CanonicalRefName, CommitOID: testBaseCommit, EntityVersion: 1}
			test.mutate(&ref)
			if err := ref.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("CanonicalRef.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func validMetadata() Metadata {
	return Metadata{
		PublicationID:           testPublicationID,
		ProposalEventID:         testProposalEventID,
		SupersedesPublicationID: testSupersedesID,
		TaskID:                  testTaskID,
		AuthorDeviceID:          testAuthorDevice,
		AuthorAgentSessionID:    testAuthorSessionID,
		BaseCommit:              testBaseCommit,
		CommitOID:               testCommitOID,
		TreeOID:                 testTreeOID,
		ParentOIDs:              []domain.GitOID{testBaseCommit, "sha1:0000000000000000000000000000000000000004"},
		Paths:                   []domain.RepositoryPath{"cmd/main.go", "internal/domain.go"},
		ArtifactDigest:          SHA256Digest{1},
		ResolvesConflictIDs:     makeConflictIDs(2),
		WorkingRootID:           testWorkingRootID,
	}
}

func validReceipt(voter domain.DeviceID) StagingReceipt {
	return StagingReceipt{
		SessionID:                 testSessionID,
		WorkspaceID:               testWorkspaceID,
		VoterSetVersion:           3,
		PublicationMetadataDigest: SHA256Digest{2},
		VoterDeviceID:             voter,
		StagedResultIndex:         0,
		Signature:                 Signature{3},
	}
}

func validProposed() Publication {
	return Publication{
		Metadata:        validMetadata(),
		StagingReceipts: []StagingReceipt{validReceipt(testVoterA)},
		State:           StateProposed,
		EntityVersion:   1,
	}
}

func validApproved(actor ReviewActorType) Publication {
	value := validProposed()
	value.State = StateApproved
	value.EntityVersion = 2
	value.ReviewVerdict = ReviewVerdictApprove
	value.ReviewerDeviceID = testVoterB
	value.ReviewActorType = actor
	if actor == ReviewActorAgent {
		value.ReviewerAgentSessionID = testReviewerSession
	}
	return value
}

func validRejected() Publication {
	value := validProposed()
	value.State = StateRejected
	value.TerminalSource = TerminalSourceReview
	value.ReviewVerdict = ReviewVerdictReject
	value.ReviewerDeviceID = testVoterB
	value.ReviewActorType = ReviewActorHuman
	value.EntityVersion = 2
	return value
}

func validWithdrawn(reviewed bool) Publication {
	var value Publication
	if reviewed {
		value = validApproved(ReviewActorHuman)
		value.EntityVersion = 3
	} else {
		value = validProposed()
		value.EntityVersion = 2
	}
	value.State = StateWithdrawn
	value.TerminalSource = TerminalSourceWithdraw
	reason := "superseded"
	value.DecisionReason = &reason
	return value
}

func validRecoveryWithdrawn() Publication {
	value := validApproved(ReviewActorHuman)
	value.State = StateWithdrawn
	value.TerminalSource = TerminalSourceRecovery
	reason := RecoveryDecisionReason
	value.DecisionReason = &reason
	value.EntityVersion = 1
	return value
}

func validApplied(lineageMember bool) Publication {
	value := validApproved(ReviewActorHuman)
	value.State = StateApplied
	value.TerminalSource = TerminalSourceApply
	value.CanonicalLineageMember = lineageMember
	value.EntityVersion = 3
	return value
}

func setHumanApproval(value *Publication) {
	value.ReviewVerdict = ReviewVerdictApprove
	value.ReviewerDeviceID = testVoterB
	value.ReviewActorType = ReviewActorHuman
}

func clearReview(value *Publication) {
	value.ReviewVerdict = ReviewVerdictAbsent
	value.ReviewerDeviceID = ""
	value.ReviewerAgentSessionID = ""
	value.ReviewActorType = ReviewActorAbsent
}

func makeGitOIDs(count int) []domain.GitOID {
	result := make([]domain.GitOID, count)
	for index := range result {
		result[index] = domain.GitOID(fmt.Sprintf("sha1:%040x", index+1))
	}
	return result
}

func makePaths(count int) []domain.RepositoryPath {
	result := make([]domain.RepositoryPath, count)
	for index := range result {
		result[index] = domain.RepositoryPath(fmt.Sprintf("path/%04d.txt", index))
	}
	return result
}

func makeConflictIDs(count int) []domain.ConflictID {
	result := make([]domain.ConflictID, count)
	for index := range result {
		result[index] = domain.ConflictID(fmt.Sprintf("ccf1%064x", index))
	}
	return result
}
