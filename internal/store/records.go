package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
)

type Digest = chain.Digest
type Signature [ed25519.SignatureSize]byte

type OutcomeStatus string

const (
	OutcomeAccepted OutcomeStatus = "accepted"
	OutcomeRejected OutcomeStatus = "rejected"
)

func (status OutcomeStatus) valid() bool {
	return status == OutcomeAccepted || status == OutcomeRejected
}

type CommandOutcome struct {
	Status OutcomeStatus
	Code   string
	JSON   []byte
}

func (outcome CommandOutcome) validate() error {
	if !outcome.Status.valid() {
		return fmt.Errorf("%w: outcome status %q", ErrInvalidApply, outcome.Status)
	}
	if !validCode(outcome.Code, false) {
		return fmt.Errorf("%w: outcome code %q", ErrInvalidApply, outcome.Code)
	}
	canonical, err := codec.CanonicalizeSignedObject(outcome.JSON)
	if err != nil || !bytes.Equal(canonical, outcome.JSON) {
		return fmt.Errorf("%w: outcome JSON is not a canonical object: %v", ErrInvalidApply, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(outcome.JSON, &members); err != nil {
		return fmt.Errorf("%w: decode outcome JSON: %v", ErrInvalidApply, err)
	}
	var encodedStatus, encodedCode string
	if raw, exists := members["status"]; !exists ||
		json.Unmarshal(raw, &encodedStatus) != nil ||
		OutcomeStatus(encodedStatus) != outcome.Status {
		return fmt.Errorf("%w: outcome status does not match JSON", ErrInvalidApply)
	}
	if raw, exists := members["code"]; !exists ||
		json.Unmarshal(raw, &encodedCode) != nil ||
		encodedCode != outcome.Code {
		return fmt.Errorf("%w: outcome code does not match JSON", ErrInvalidApply)
	}
	return nil
}

type ApplyHeads struct {
	ChainIndex              uint64
	ChainHash               Digest
	ResultIndex             uint64
	PreviousResultHash      Digest
	ResultHash              Digest
	ProjectionAccumulator   Digest
	DigestVersion           uint64
	ProjectionSchemaVersion uint64
}

func (heads ApplyHeads) validate() error {
	for name, value := range map[string]uint64{
		"chain_index":               heads.ChainIndex,
		"result_index":              heads.ResultIndex,
		"digest_version":            heads.DigestVersion,
		"projection_schema_version": heads.ProjectionSchemaVersion,
	} {
		minimum := uint64(0)
		if name != "chain_index" {
			minimum = 1
		}
		if value < minimum || !domain.ValidUnsignedInteger(value) {
			return fmt.Errorf("%w: %s %d", ErrInvalidApply, name, value)
		}
	}
	return nil
}

type ApplyRequest struct {
	Term               uint64
	LogIndex           uint64
	AppliedAt          domain.Timestamp
	RecoveryGeneration uint64
	Proposal           event.SignedEvent
	Outcome            CommandOutcome
	Projections        ProjectionWrites

	RecordActivity bool
	ActivityTaskID domain.UUIDv7
	Audit          []AuditRecord
	Checkpoint     *CheckpointRecord

	LeaseDeadlines       []LeaseDeadlineRecord
	DeleteLeaseDeadlines []LeaseDeadlineKey
}

func (request ApplyRequest) validate() error {
	if err := request.validateApplyIdentity(); err != nil {
		return err
	}
	proposal := request.Proposal.Proposal()
	if err := request.Outcome.validate(); err != nil {
		return err
	}
	expectedActivity := request.Outcome.Status == OutcomeAccepted &&
		(proposal.RationaleSummary != "" || len(proposal.Actions) != 0)
	if request.RecordActivity != expectedActivity {
		return fmt.Errorf(
			"%w: activity directive does not match accepted proposal",
			ErrInvalidApply,
		)
	}
	if request.RecordActivity {
		if request.ActivityTaskID != "" && !request.ActivityTaskID.Valid() {
			return fmt.Errorf("%w: invalid activity task ID", ErrInvalidApply)
		}
		if proposal.Kind == event.KindActivityRecorded {
			expectedTaskID, err := activityTaskID(proposal)
			if err != nil || request.ActivityTaskID != expectedTaskID {
				return fmt.Errorf(
					"%w: activity task binding mismatch",
					ErrInvalidApply,
				)
			}
		}
	} else if request.ActivityTaskID != "" {
		return fmt.Errorf("%w: activity task ID without activity", ErrInvalidApply)
	}
	for index := range request.Audit {
		if err := request.Audit[index].Validate(); err != nil {
			return fmt.Errorf("%w: audit[%d]: %v", ErrInvalidApply, index, err)
		}
	}
	if err := request.validateAuditBinding(proposal, 0); err != nil {
		return err
	}
	isCheckpointEvent := proposal.Kind == event.KindConsensusCheckpoint
	if isCheckpointEvent &&
		request.Outcome.Status == OutcomeAccepted &&
		request.Checkpoint == nil {
		return fmt.Errorf("%w: accepted checkpoint event requires a checkpoint row", ErrInvalidApply)
	}
	if request.Checkpoint != nil {
		if err := request.Checkpoint.Validate(); err != nil {
			return fmt.Errorf("%w: checkpoint: %v", ErrInvalidApply, err)
		}
		if request.Outcome.Status != OutcomeAccepted ||
			!isCheckpointEvent ||
			request.Checkpoint.CheckpointEventID != proposal.EventID {
			return fmt.Errorf("%w: checkpoint does not name an accepted checkpoint event", ErrInvalidApply)
		}
		if request.Checkpoint.SessionID != proposal.SessionID ||
			request.Checkpoint.WorkspaceID != proposal.WorkspaceID ||
			request.Checkpoint.RecoveryGeneration != request.RecoveryGeneration {
			return fmt.Errorf("%w: checkpoint lineage binding mismatch", ErrInvalidApply)
		}
		if !request.Checkpoint.matchesPayload(proposal.Payload) {
			return fmt.Errorf(
				"%w: checkpoint row does not match proposal payload",
				ErrInvalidApply,
			)
		}
	}
	for index := range request.LeaseDeadlines {
		if err := request.LeaseDeadlines[index].Validate(); err != nil {
			return fmt.Errorf("%w: lease deadline[%d]: %v", ErrInvalidApply, index, err)
		}
	}
	for index := range request.DeleteLeaseDeadlines {
		if err := request.DeleteLeaseDeadlines[index].Validate(); err != nil {
			return fmt.Errorf("%w: lease deadline delete[%d]: %v", ErrInvalidApply, index, err)
		}
	}
	return nil
}

func (request ApplyRequest) validateApplyIdentity() error {
	if request.Term < 1 || request.LogIndex < 1 ||
		request.Term > uint64(^uint64(0)>>1) ||
		request.LogIndex > uint64(^uint64(0)>>1) {
		return fmt.Errorf("%w: invalid Raft term/index", ErrInvalidApply)
	}
	if !request.AppliedAt.Valid() ||
		!domain.ValidUnsignedInteger(request.RecoveryGeneration) {
		return fmt.Errorf("%w: invalid apply time or recovery generation", ErrInvalidApply)
	}
	proposal := request.Proposal.Proposal()
	if err := proposal.ValidateEnvelope(); err != nil {
		return fmt.Errorf("%w: proposal: %v", ErrInvalidApply, err)
	}
	canonical := request.Proposal.CanonicalBytes()
	reencoded, err := codec.CanonicalizeSignedObject(canonical)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return fmt.Errorf("%w: proposal bytes are not canonical: %v", ErrInvalidApply, err)
	}
	if len(request.Proposal.OriginSignature()) != ed25519.SignatureSize {
		return fmt.Errorf("%w: proposal signature length", ErrInvalidApply)
	}
	return nil
}

func activityTaskID(proposal event.Proposal) (domain.UUIDv7, error) {
	if proposal.Kind != event.KindActivityRecorded {
		return "", nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(proposal.Payload, &members); err != nil {
		return "", err
	}
	if len(members) == 0 {
		return "", nil
	}
	raw, exists := members["task_id"]
	if !exists || len(members) != 1 {
		return "", errors.New("invalid activity payload")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return "", err
	}
	taskID := domain.UUIDv7(text)
	if !taskID.Valid() {
		return "", errors.New("invalid activity task ID")
	}
	return taskID, nil
}

type auditRecordedPayload struct {
	Action                 string `json:"action"`
	Outcome                string `json:"outcome"`
	Subject                string `json:"subject"`
	SubjectDeviceID        string `json:"subject_device_id"`
	SubjectCredentialEpoch uint64 `json:"subject_credential_epoch"`
}

func (request ApplyRequest) validateAuditBinding(
	proposal event.Proposal,
	expectedResultIndex uint64,
) error {
	localAlarmCount := 0
	for _, record := range request.Audit {
		if record.SourceKind != AuditLocalAggregate {
			continue
		}
		localAlarmCount++
		if localAlarmCount > 1 ||
			record.EventID != proposal.EventID {
			return fmt.Errorf(
				"%w: command result has invalid local alarm cardinality or binding",
				ErrInvalidApply,
			)
		}
	}
	if expectedResultIndex != 0 {
		for _, record := range request.Audit {
			if record.ResultIndex != expectedResultIndex {
				return fmt.Errorf(
					"%w: audit row does not name the committed result",
					ErrInvalidApply,
				)
			}
		}
	}
	acceptedAuditEvent := request.Outcome.Status == OutcomeAccepted &&
		proposal.Kind == event.KindAuditRecorded
	if !acceptedAuditEvent {
		for _, record := range request.Audit {
			if record.SourceKind == AuditEvent {
				return fmt.Errorf(
					"%w: audit_event row requires an accepted audit.recorded proposal",
					ErrInvalidApply,
				)
			}
		}
		return nil
	}
	if len(request.Audit) != 1 {
		return fmt.Errorf(
			"%w: accepted audit.recorded requires exactly one audit_event row",
			ErrInvalidApply,
		)
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(proposal.Payload, &members); err != nil ||
		len(members) != 5 {
		return fmt.Errorf(
			"%w: invalid accepted audit.recorded payload",
			ErrInvalidApply,
		)
	}
	for _, name := range []string{
		"action",
		"outcome",
		"subject",
		"subject_device_id",
		"subject_credential_epoch",
	} {
		if _, exists := members[name]; !exists {
			return fmt.Errorf(
				"%w: invalid accepted audit.recorded payload",
				ErrInvalidApply,
			)
		}
	}
	var payload auditRecordedPayload
	if err := json.Unmarshal(proposal.Payload, &payload); err != nil {
		return fmt.Errorf(
			"%w: invalid accepted audit.recorded payload",
			ErrInvalidApply,
		)
	}

	record := request.Audit[0]
	if record.SubjectCredentialEpoch == nil ||
		*record.SubjectCredentialEpoch != payload.SubjectCredentialEpoch ||
		record.SessionID != proposal.SessionID ||
		record.SourceKind != AuditEvent ||
		record.EventID != proposal.EventID ||
		expectedResultIndex != 0 && record.ResultIndex != expectedResultIndex ||
		record.ReporterDeviceID != proposal.Origin.DeviceID() ||
		record.SubjectDeviceID != domain.DeviceID(payload.SubjectDeviceID) ||
		record.ActorType != proposal.Origin.ActorType() ||
		record.ActionCode != payload.Action ||
		record.OutcomeCode != payload.Outcome ||
		record.Subject != payload.Subject ||
		record.FirstSeenAt != request.AppliedAt ||
		record.LastSeenAt != request.AppliedAt ||
		record.ObservationCount != 1 {
		return fmt.Errorf(
			"%w: audit_event row does not match audit.recorded proposal",
			ErrInvalidApply,
		)
	}
	return nil
}

type AuditSourceKind string

const (
	AuditAcceptedEvent      AuditSourceKind = "accepted_event"
	AuditCommittedRejection AuditSourceKind = "committed_rejection"
	AuditEvent              AuditSourceKind = "audit_event"
	AuditLocalAggregate     AuditSourceKind = "local_aggregate"
)

func (kind AuditSourceKind) valid() bool {
	switch kind {
	case AuditAcceptedEvent, AuditCommittedRejection, AuditEvent, AuditLocalAggregate:
		return true
	default:
		return false
	}
}

type AuditRecord struct {
	SessionID              domain.UUIDv7
	SourceKind             AuditSourceKind
	EventID                domain.UUIDv7
	ResultIndex            uint64
	ReporterDeviceID       domain.DeviceID
	SubjectDeviceID        domain.DeviceID
	SubjectCredentialEpoch *uint64
	ActorType              event.ActorType
	IPCChannel             string
	ActionCode             string
	OutcomeCode            string
	Subject                string
	DetailsJSON            []byte
	FirstSeenAt            domain.Timestamp
	LastSeenAt             domain.Timestamp
	ObservationCount       uint64
}

func (record AuditRecord) Validate() error {
	if !record.SessionID.Valid() || !record.SourceKind.valid() {
		return errors.New("invalid session or source")
	}
	if record.EventID != "" && !record.EventID.Valid() {
		return errors.New("invalid event ID")
	}
	if record.ResultIndex != 0 && !domain.ValidUnsignedInteger(record.ResultIndex) {
		return errors.New("invalid result index")
	}
	if record.ReporterDeviceID != "" && !record.ReporterDeviceID.Valid() ||
		record.SubjectDeviceID != "" && !record.SubjectDeviceID.Valid() {
		return errors.New("invalid device ID")
	}
	if record.SubjectCredentialEpoch != nil &&
		!domain.ValidUnsignedInteger(*record.SubjectCredentialEpoch) {
		return errors.New("invalid credential epoch")
	}
	if record.ActorType != "" && !record.ActorType.Valid() {
		return errors.New("invalid actor type")
	}
	switch record.IPCChannel {
	case "", "agent", "operator", "daemon", "peer":
	default:
		return errors.New("invalid IPC channel")
	}
	if !validCode(record.ActionCode, true) || !validCode(record.OutcomeCode, true) {
		return errors.New("invalid action or outcome code")
	}
	if len(record.Subject) > 256 || !utf8.ValidString(record.Subject) {
		return errors.New("invalid subject")
	}
	canonical, err := codec.CanonicalizeSignedObject(record.DetailsJSON)
	if err != nil || !bytes.Equal(canonical, record.DetailsJSON) {
		return errors.New("details JSON is not a canonical object")
	}
	if !record.FirstSeenAt.Valid() || !record.LastSeenAt.Valid() ||
		record.ObservationCount < 1 ||
		!domain.ValidUnsignedInteger(record.ObservationCount) {
		return errors.New("invalid audit time or observation count")
	}
	return nil
}

type CheckpointRecord struct {
	CheckpointEventID        domain.UUIDv7
	SessionID                domain.UUIDv7
	WorkspaceID              domain.UUIDv4
	RecoveryGeneration       uint64
	AuthorityVoterSetVersion uint64
	SignerDeviceID           domain.DeviceID
	Term                     uint64
	CoveredAppliedLogIndex   uint64
	CoveredChainIndex        uint64
	CoveredChainHash         Digest
	CoveredResultIndex       uint64
	CoveredResultHash        Digest
	ProjectionAccumulator    Digest
	DigestVersion            uint64
	ProjectionSchemaVersion  uint64
	CheckpointJSON           []byte
	AuthoritySignature       Signature
}

func (record CheckpointRecord) Validate() error {
	if !record.CheckpointEventID.Valid() || !record.SessionID.Valid() ||
		!record.WorkspaceID.Valid() || !record.SignerDeviceID.Valid() {
		return errors.New("invalid checkpoint identity")
	}
	values := []uint64{
		record.RecoveryGeneration,
		record.AuthorityVoterSetVersion,
		record.Term,
		record.CoveredAppliedLogIndex,
		record.CoveredChainIndex,
		record.CoveredResultIndex,
		record.DigestVersion,
		record.ProjectionSchemaVersion,
	}
	for index, value := range values {
		if !domain.ValidUnsignedInteger(value) {
			return fmt.Errorf("numeric field %d exceeds safe range", index)
		}
	}
	if record.AuthorityVoterSetVersion < 1 || record.Term < 1 ||
		record.CoveredAppliedLogIndex < 1 ||
		record.DigestVersion < 1 || record.ProjectionSchemaVersion < 1 {
		return errors.New("required checkpoint number is zero")
	}
	if record.CoveredChainIndex > record.CoveredResultIndex {
		return errors.New("checkpoint chain index exceeds result index")
	}
	canonical, err := codec.CanonicalizeSignedObject(record.CheckpointJSON)
	if err != nil || !bytes.Equal(canonical, record.CheckpointJSON) {
		return errors.New("checkpoint JSON is not a canonical object")
	}
	expected, err := event.EncodeCheckpoint(record.checkpoint())
	if err != nil || !bytes.Equal(expected, record.CheckpointJSON) {
		return errors.New("checkpoint JSON does not match typed fields")
	}
	return nil
}

func (record CheckpointRecord) checkpoint() domain.Checkpoint {
	return domain.Checkpoint{
		SessionID:                record.SessionID,
		WorkspaceID:              record.WorkspaceID,
		RecoveryGeneration:       record.RecoveryGeneration,
		AuthorityVoterSetVersion: record.AuthorityVoterSetVersion,
		SignerDeviceID:           record.SignerDeviceID,
		Term:                     record.Term,
		CoveredAppliedLogIndex:   record.CoveredAppliedLogIndex,
		CoveredChainIndex:        record.CoveredChainIndex,
		CoveredChainHash:         record.CoveredChainHash,
		CoveredResultIndex:       record.CoveredResultIndex,
		CoveredResultHash:        record.CoveredResultHash,
		ProjectionAccumulator:    record.ProjectionAccumulator,
		DigestVersion:            record.DigestVersion,
		ProjectionSchemaVersion:  record.ProjectionSchemaVersion,
	}
}

func (record CheckpointRecord) canonicalJSON(
	includeSignature bool,
) ([]byte, error) {
	unsigned, err := event.EncodeCheckpoint(record.checkpoint())
	if err != nil || !includeSignature {
		return unsigned, err
	}
	return event.EncodeCheckpointPayload(
		record.checkpoint(),
		[ed25519.SignatureSize]byte(record.AuthoritySignature),
	)
}

func (record CheckpointRecord) matchesPayload(payload []byte) bool {
	expected, err := record.canonicalJSON(true)
	return err == nil && bytes.Equal(expected, payload)
}

type LeaseDeadlineRecord struct {
	LeaseID             domain.UUIDv7
	EntityVersion       uint64
	OriginBootID        domain.UUIDv7
	MonotonicDeadlineNS int64
	DisplayDeadlineAt   domain.Timestamp
}

func (record LeaseDeadlineRecord) Validate() error {
	if !record.LeaseID.Valid() || !record.OriginBootID.Valid() ||
		record.EntityVersion < 1 ||
		!domain.ValidUnsignedInteger(record.EntityVersion) ||
		record.MonotonicDeadlineNS < 0 ||
		!record.DisplayDeadlineAt.Valid() {
		return errors.New("invalid lease deadline")
	}
	return nil
}

type LeaseDeadlineKey struct {
	LeaseID       domain.UUIDv7
	EntityVersion uint64
}

func (key LeaseDeadlineKey) Validate() error {
	if !key.LeaseID.Valid() || key.EntityVersion < 1 ||
		!domain.ValidUnsignedInteger(key.EntityVersion) {
		return errors.New("invalid lease deadline key")
	}
	return nil
}

func validCode(value string, extended bool) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '_' {
			continue
		}
		if extended && (character >= 'A' && character <= 'Z' ||
			character == '.' || character == ':' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func proposalDigest(signed event.SignedEvent) Digest {
	return Digest(sha256.Sum256(signed.CanonicalBytes()))
}

func proposalScope(proposal event.Proposal) (OriginScopeKind, string) {
	if proposal.Origin.ActorType() == event.ActorAgent {
		return OriginScopeKindAgent, string(proposal.Origin.AgentSessionID())
	}
	return OriginScopeKindBoot, string(proposal.Origin.OriginBootID())
}
