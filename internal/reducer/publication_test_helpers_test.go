package reducer

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/event"
)

const (
	testPublicationID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000080",
	)
	testResolutionPublicationID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000081",
	)
	testPublicationEventID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000082",
	)
	testResolutionEventID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000083",
	)
	testReviewerAgentID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000084",
	)
	testReviewerRootID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000085",
	)
	testPublicationLeaseID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000086",
	)
)

const testPublicationPath = domain.RepositoryPath("src/main.go")

func domainEventID(index int) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf(
		"01890f47-3e72-7000-8004-%012x",
		0x1000+index,
	))
}

func testPublicationMetadata(
	fixture reducerFixture,
	publicationID,
	eventID domain.UUIDv7,
	taskID domain.UUIDv7,
	base,
	commit,
	tree domain.GitOID,
	resolves ...domain.ConflictID,
) publication.Metadata {
	return publication.Metadata{
		PublicationID:        publicationID,
		ProposalEventID:      eventID,
		TaskID:               taskID,
		AuthorDeviceID:       fixture.editorDevice,
		AuthorAgentSessionID: testAgentSessionID,
		BaseCommit:           base,
		CommitOID:            commit,
		TreeOID:              tree,
		ParentOIDs:           []domain.GitOID{base},
		Paths:                []domain.RepositoryPath{testPublicationPath},
		ArtifactDigest:       sha256.Sum256([]byte("publication artifact")),
		ResolvesConflictIDs:  append([]domain.ConflictID(nil), resolves...),
		WorkingRootID:        testWorkingRootID,
	}
}

func signedStagingReceipts(
	t *testing.T,
	fixture reducerFixture,
	metadata publication.Metadata,
	resultIndex uint64,
	voterIDs ...domain.DeviceID,
) []publication.StagingReceipt {
	t.Helper()
	if len(voterIDs) == 0 {
		voterIDs = fixture.state.voterSet.VoterDeviceIDs()
	}
	digest, err := publicationMetadataDigest(metadata)
	if err != nil {
		t.Fatalf("publicationMetadataDigest() error = %v", err)
	}
	receipts := make([]publication.StagingReceipt, len(voterIDs))
	for index, voterID := range voterIDs {
		receipt := publication.StagingReceipt{
			SessionID:                 fixture.state.sessionID,
			WorkspaceID:               fixture.state.workspaceID,
			VoterSetVersion:           fixture.state.voterSet.VoterSetVersion,
			PublicationMetadataDigest: digest,
			VoterDeviceID:             voterID,
			StagedResultIndex:         resultIndex,
		}
		unsigned, err := json.Marshal(stagingReceiptUnsignedWire{
			SessionID:       string(receipt.SessionID),
			WorkspaceID:     string(receipt.WorkspaceID),
			VoterSetVersion: receipt.VoterSetVersion,
			PublicationMetadataDigest: codec.EncodeBase64URL(
				receipt.PublicationMetadataDigest[:],
			),
			VoterDeviceID:     string(receipt.VoterDeviceID),
			StagedResultIndex: receipt.StagedResultIndex,
		})
		if err != nil {
			t.Fatalf("encode staging receipt: %v", err)
		}
		canonical, err := codec.CanonicalizeSignedObject(unsigned)
		if err != nil {
			t.Fatalf("canonicalize staging receipt: %v", err)
		}
		signature, err := codecommcrypto.SignEd25519(
			fixture.privateKeys[voterID],
			codec.SignatureGitStageReceipt,
			canonical,
		)
		if err != nil {
			t.Fatalf("sign staging receipt: %v", err)
		}
		copy(receipt.Signature[:], signature)
		receipts[index] = receipt
	}
	return receipts
}

func publicationPayload(
	t *testing.T,
	metadata publication.Metadata,
	receipts []publication.StagingReceipt,
) json.RawMessage {
	t.Helper()
	payload := map[string]any{
		"proposal_event_id":       metadata.ProposalEventID,
		"author_device_id":        metadata.AuthorDeviceID,
		"author_agent_session_id": metadata.AuthorAgentSessionID,
		"base_commit":             metadata.BaseCommit,
		"commit_oid":              metadata.CommitOID,
		"tree_oid":                metadata.TreeOID,
		"parent_oids":             metadata.ParentOIDs,
		"paths":                   metadata.Paths,
		"artifact_digest":         codec.EncodeBase64URL(metadata.ArtifactDigest[:]),
		"working_root_id":         metadata.WorkingRootID,
		"staging_receipts":        stagingReceiptPayloads(receipts),
	}
	if metadata.TaskID != "" {
		payload["task_id"] = metadata.TaskID
	}
	if metadata.SupersedesPublicationID != "" {
		payload["supersedes_publication_id"] =
			metadata.SupersedesPublicationID
	}
	if len(metadata.ResolvesConflictIDs) != 0 {
		payload["resolves_conflict_ids"] = metadata.ResolvesConflictIDs
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode publication payload: %v", err)
	}
	return encoded
}

func mustRawJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode JSON payload: %v", err)
	}
	return encoded
}

func stagingReceiptPayloads(
	receipts []publication.StagingReceipt,
) []map[string]any {
	result := make([]map[string]any, len(receipts))
	for index, receipt := range receipts {
		result[index] = map[string]any{
			"session_id":        receipt.SessionID,
			"workspace_id":      receipt.WorkspaceID,
			"voter_set_version": receipt.VoterSetVersion,
			"publication_metadata_digest": codec.EncodeBase64URL(
				receipt.PublicationMetadataDigest[:],
			),
			"voter_device_id":     receipt.VoterDeviceID,
			"staged_result_index": receipt.StagedResultIndex,
			"signature":           codec.EncodeBase64URL(receipt.Signature[:]),
		}
	}
	return result
}

func buildRepositoryProposal(
	t *testing.T,
	fixture reducerFixture,
	actor event.ActorType,
	deviceID domain.DeviceID,
	agentSessionID domain.UUIDv7,
	kind event.Kind,
	entityID string,
	expectedVersion uint64,
	payload json.RawMessage,
	eventID domain.UUIDv7,
	sequence uint64,
) event.SignedEvent {
	t.Helper()
	var binding event.Binding
	var err error
	switch actor {
	case event.ActorAgent:
		if deviceID == "" {
			deviceID = fixture.editorDevice
		}
		if agentSessionID == "" {
			agentSessionID = testAgentSessionID
		}
		binding, err = event.NewMCPBinding(deviceID, agentSessionID, nil)
	case event.ActorHuman, event.ActorDaemon:
		if deviceID == "" {
			deviceID = fixture.editorDevice
		}
		var authority event.LocalAuthority
		authority, err = event.NewLocalAuthority(deviceID, testBootID)
		if err == nil && actor == event.ActorHuman {
			binding, err = authority.OperatorBinding()
		}
		if err == nil && actor == event.ActorDaemon {
			binding, err = authority.DaemonBinding()
		}
	default:
		t.Fatalf("unsupported repository actor %q", actor)
	}
	if err != nil {
		t.Fatalf("construct repository binding: %v", err)
	}
	command := event.Command{
		Kind:             kind,
		EntityID:         event.StringEntityID(entityID),
		RationaleSummary: "",
		Actions:          []event.Action{},
		Payload:          payload,
		Redaction: event.Redaction{
			Policy:        event.RedactionDefault,
			FieldsRemoved: []event.RedactionField{},
		},
	}
	if expectedVersion != 0 {
		command.ExpectedEntityVersion = &expectedVersion
	}
	proposal, err := event.BuildProposal(command, binding, event.BuildContext{
		EventID:        eventID,
		SessionID:      fixture.state.sessionID,
		WorkspaceID:    fixture.state.workspaceID,
		CreatedAt:      testTimestamp,
		OriginSequence: sequence,
	})
	if err != nil {
		t.Fatalf("event.BuildProposal() error = %v", err)
	}
	signed, err := event.Sign(proposal, fixture.privateKeys[deviceID])
	if err != nil {
		t.Fatalf("event.Sign() error = %v", err)
	}
	return signed
}

func addPublicationLease(t *testing.T, fixture *reducerFixture) {
	t.Helper()
	value := mustReducerLease(
		t,
		testPublicationLeaseID,
		fixture.editorDevice,
		testAgentSessionID,
		lease.ScopePath,
		"",
		1,
		"src/**",
	)
	addReducerLease(&fixture.state, value)
}

func addReviewerAgent(t *testing.T, fixture *reducerFixture) {
	t.Helper()
	session := agentsession.Session{
		ID:            testReviewerAgentID,
		DeviceID:      fixture.targetDevice,
		ClientKind:    agentsession.ClientKindClaude,
		State:         agentsession.StateIdle,
		WorkingRootID: testReviewerRootID,
		EntityVersion: 1,
	}
	if err := session.Validate(); err != nil {
		t.Fatalf("reviewer session: %v", err)
	}
	fixture.state.agentSessions[session.ID] = session
	key := OriginScopeKey{
		DeviceID: fixture.targetDevice,
		Kind:     ScopeAgent,
		ScopeID:  session.ID,
	}
	fixture.state.originScopes[key] = OriginScope{
		OriginScopeKey: key,
		LastSequence:   1,
	}
	fixture.state.agentScopeDevices[session.ID] = fixture.targetDevice
	fixture.state.activeAgentSessionCount++
}

func addBootScope(fixture *reducerFixture, deviceID domain.DeviceID) {
	key := OriginScopeKey{
		DeviceID: deviceID,
		Kind:     ScopeBoot,
		ScopeID:  testBootID,
	}
	fixture.state.originScopes[key] = OriginScope{
		OriginScopeKey: key,
		LastSequence:   1,
	}
}

func testProposedPublication(
	t *testing.T,
	fixture reducerFixture,
	publicationID,
	eventID domain.UUIDv7,
	taskID domain.UUIDv7,
) publication.Publication {
	t.Helper()
	metadata := testPublicationMetadata(
		fixture,
		publicationID,
		eventID,
		taskID,
		fixture.state.canonicalRef.CommitOID,
		testReducerGitOID(20),
		testReducerGitOID(21),
	)
	return publication.Publication{
		Metadata: metadata,
		StagingReceipts: signedStagingReceipts(
			t,
			fixture,
			metadata,
			fixture.state.currentResultIndex,
		),
		State:         publication.StateProposed,
		EntityVersion: 1,
	}
}

func testApprovedPublication(
	t *testing.T,
	fixture reducerFixture,
	publicationID,
	eventID domain.UUIDv7,
	taskID domain.UUIDv7,
) publication.Publication {
	t.Helper()
	value := testProposedPublication(
		t,
		fixture,
		publicationID,
		eventID,
		taskID,
	)
	value.State = publication.StateApproved
	value.ReviewVerdict = publication.ReviewVerdictApprove
	value.ReviewerDeviceID = fixture.ownerDevice
	value.ReviewActorType = publication.ReviewActorHuman
	value.EntityVersion = 2
	return value
}

func testConflictForPublication(
	t *testing.T,
	fixture reducerFixture,
	candidate publication.Publication,
	canonicalCommit domain.GitOID,
) conflict.Conflict {
	t.Helper()
	detection := conflict.Detection{
		ID:              domain.ConflictID("ccf1" + strings.Repeat("0", 64)),
		PublicationID:   candidate.Metadata.PublicationID,
		MergeKind:       conflict.MergeKindMerge,
		MergeBaseOIDs:   []domain.GitOID{candidate.Metadata.BaseCommit},
		CanonicalCommit: canonicalCommit,
		CandidateCommit: candidate.Metadata.CommitOID,
		Paths:           []domain.RepositoryPath{testPublicationPath},
	}
	id, err := deriveConflictID(fixture.state.workspaceID, detection)
	if err != nil {
		t.Fatalf("deriveConflictID() error = %v", err)
	}
	detection.ID = id
	return conflict.Conflict{
		ID:              detection.ID,
		PublicationID:   detection.PublicationID,
		MergeKind:       detection.MergeKind,
		MergeBaseOIDs:   append([]domain.GitOID(nil), detection.MergeBaseOIDs...),
		CanonicalCommit: detection.CanonicalCommit,
		CandidateCommit: detection.CandidateCommit,
		Paths:           append([]domain.RepositoryPath(nil), detection.Paths...),
		Status:          conflict.StatusUnresolved,
		EntityVersion:   1,
	}
}

func rederiveConflictID(
	t *testing.T,
	fixture reducerFixture,
	value *conflict.Conflict,
) {
	t.Helper()
	value.ID = domain.ConflictID("ccf1" + strings.Repeat("0", 64))
	id, err := deriveConflictID(fixture.state.workspaceID, value.Detection())
	if err != nil {
		t.Fatalf("deriveConflictID() error = %v", err)
	}
	value.ID = id
}

func conflictDetectionPayload(value conflict.Conflict) map[string]any {
	payload := map[string]any{
		"publication_id":   value.PublicationID,
		"merge_kind":       value.MergeKind,
		"merge_base_oids":  value.MergeBaseOIDs,
		"canonical_commit": value.CanonicalCommit,
		"candidate_commit": value.CandidateCommit,
		"paths":            value.Paths,
	}
	if value.ReplayCommitOID != "" {
		payload["replay_commit_oid"] = value.ReplayCommitOID
	}
	return payload
}
