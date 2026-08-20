// Package consensus adapts the maintained Raft implementation to CodeComm's
// deterministic reducer and durable SQLite apply transaction.
package consensus

import (
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

var ErrInvalidApplyMapping = errors.New("consensus: invalid apply mapping")

// ApplyContext contains local provenance and side-effect inputs for one
// already-committed Raft command. None of these values are reducer inputs.
type ApplyContext struct {
	Term               uint64
	LogIndex           uint64
	RecoveryGeneration uint64
	AppliedAt          domain.Timestamp
	OriginBootID       domain.UUIDv7
	MonotonicNowNS     int64
	PriorHeads         store.ApplyHeads
}

// BuildApplyRequest converts a pure reducer outcome into the complete SQLite
// write set for one committed Raft command.
func BuildApplyRequest(
	signed event.SignedEvent,
	outcome reducer.Outcome,
	context ApplyContext,
) (store.ApplyRequest, error) {
	if context.Term < 1 ||
		context.LogIndex < 1 ||
		!domain.ValidUnsignedInteger(context.Term) ||
		!domain.ValidUnsignedInteger(context.LogIndex) {
		return store.ApplyRequest{}, ErrInvalidApplyMapping
	}
	request, err := buildApplyRequest(
		signed,
		outcome,
		localApplyContext{
			RecoveryGeneration: context.RecoveryGeneration,
			AppliedAt:          context.AppliedAt,
			OriginBootID:       context.OriginBootID,
			MonotonicNowNS:     context.MonotonicNowNS,
			PriorHeads:         context.PriorHeads,
		},
	)
	if err != nil {
		return store.ApplyRequest{}, err
	}
	request.Term = context.Term
	request.LogIndex = context.LogIndex
	return request, nil
}

type localApplyContext struct {
	RecoveryGeneration uint64
	AppliedAt          domain.Timestamp
	OriginBootID       domain.UUIDv7
	MonotonicNowNS     int64
	PriorHeads         store.ApplyHeads
}

func buildApplyRequest(
	signed event.SignedEvent,
	outcome reducer.Outcome,
	context localApplyContext,
) (store.ApplyRequest, error) {
	if !domain.ValidUnsignedInteger(context.RecoveryGeneration) ||
		!context.AppliedAt.Valid() ||
		!context.OriginBootID.Valid() ||
		context.MonotonicNowNS < 0 ||
		context.PriorHeads.ResultIndex >= domain.MaxSafeInteger {
		return store.ApplyRequest{}, ErrInvalidApplyMapping
	}
	if outcome.Status != reducer.StatusAccepted &&
		outcome.Status != reducer.StatusRejected {
		return store.ApplyRequest{}, ErrInvalidApplyMapping
	}
	if outcome.Accepted() != outcome.Changes.AdvancesEventChain {
		return store.ApplyRequest{}, fmt.Errorf(
			"%w: event-chain marker disagrees with outcome",
			ErrInvalidApplyMapping,
		)
	}
	if err := validateOutcomeDirectives(signed.Proposal(), outcome); err != nil {
		return store.ApplyRequest{}, err
	}
	outcomeJSON, err := outcome.ResultJSON()
	if err != nil {
		return store.ApplyRequest{}, fmt.Errorf(
			"%w: encode outcome: %v",
			ErrInvalidApplyMapping,
			err,
		)
	}

	request := store.ApplyRequest{
		AppliedAt:          context.AppliedAt,
		RecoveryGeneration: context.RecoveryGeneration,
		Proposal:           signed,
		Outcome: store.CommandOutcome{
			Status: store.OutcomeStatus(outcome.Status),
			Code:   string(outcome.Code),
			JSON:   outcomeJSON,
		},
		Projections:    projectionWrites(outcome.Changes),
		RecordActivity: outcome.RecordActivity,
	}
	if outcome.RecordActivity {
		request.ActivityTaskID = outcome.ActivityTaskID
	}
	request.Audit, err = auditRecords(
		signed.Proposal(),
		outcome,
		context.AppliedAt,
		context.PriorHeads.ResultIndex+1,
	)
	if err != nil {
		return store.ApplyRequest{}, err
	}
	if outcome.Checkpoint != nil {
		request.Checkpoint = checkpointRecord(
			signed.Proposal().EventID,
			*outcome.Checkpoint,
		)
	}
	request.LeaseDeadlines, request.DeleteLeaseDeadlines, err =
		leaseDeadlineChanges(outcome.Changes, context)
	if err != nil {
		return store.ApplyRequest{}, err
	}
	return request, nil
}

func validateOutcomeDirectives(
	proposal event.Proposal,
	outcome reducer.Outcome,
) error {
	if !outcome.Accepted() &&
		(outcome.RecordActivity ||
			outcome.Audit != nil ||
			outcome.RecordedAudit != nil ||
			outcome.Checkpoint != nil) {
		return fmt.Errorf(
			"%w: rejected outcome carries an accepted-only directive",
			ErrInvalidApplyMapping,
		)
	}
	if outcome.RecordedAudit != nil &&
		proposal.Kind != event.KindAuditRecorded ||
		outcome.Accepted() &&
			proposal.Kind == event.KindAuditRecorded &&
			outcome.RecordedAudit == nil {
		return fmt.Errorf(
			"%w: explicit audit directive has the wrong event kind",
			ErrInvalidApplyMapping,
		)
	}
	if outcome.Checkpoint != nil &&
		proposal.Kind != event.KindConsensusCheckpoint ||
		outcome.Accepted() &&
			proposal.Kind == event.KindConsensusCheckpoint &&
			outcome.Checkpoint == nil {
		return fmt.Errorf(
			"%w: checkpoint directive has the wrong event kind",
			ErrInvalidApplyMapping,
		)
	}
	if outcome.Accepted() && outcome.Alarm != nil {
		return fmt.Errorf(
			"%w: accepted outcome carries a rejection alarm",
			ErrInvalidApplyMapping,
		)
	}
	if outcome.Alarm != nil &&
		proposal.Kind != event.KindWorkspaceConflictDetected {
		return fmt.Errorf(
			"%w: alarm directive has the wrong event kind",
			ErrInvalidApplyMapping,
		)
	}
	return nil
}

func projectionWrites(changes reducer.Changes) store.ProjectionWrites {
	writes := store.ProjectionWrites{
		AuditCounters:       changes.AuditCounters,
		Tasks:               changes.Tasks,
		PlanRevisions:       changes.PlanRevisions,
		PlanCurrent:         changes.PlanCurrent,
		MemoryRecords:       changes.MemoryRecords,
		Leases:              changes.Leases,
		Devices:             changes.Devices,
		VoterSet:            changes.VoterSet,
		AgentSessions:       changes.AgentSessions,
		CanonicalRefs:       changes.CanonicalRefs,
		Publications:        changes.Publications,
		MergeConflicts:      changes.MergeConflicts,
		SessionPolicy:       changes.SessionPolicy,
		OriginScopes:        make([]store.OriginScopeRow, len(changes.OriginScopes)),
		CredentialAuthority: make([]store.CredentialAuthorityRow, len(changes.CredentialAuthority)),
		CredentialAuthorizations: make(
			[]store.CredentialAuthorizationRow,
			len(changes.CredentialAuthorizations),
		),
		ControlFileProposals: make(
			[]store.ControlFileProposalRow,
			len(changes.ControlFileProposals),
		),
	}
	for index, scope := range changes.OriginScopes {
		writes.OriginScopes[index] = store.OriginScopeRow{
			DeviceID:     scope.DeviceID,
			ScopeKind:    string(scope.Kind),
			ScopeID:      scope.ScopeID,
			LastSequence: scope.LastSequence,
		}
	}
	for index, authority := range changes.CredentialAuthority {
		writes.CredentialAuthority[index] =
			store.CredentialAuthorityRow(authority)
	}
	for index, authorization := range changes.CredentialAuthorizations {
		endorsements := make(
			[]store.ClockEndorsement,
			len(authorization.ClockEndorsements),
		)
		for endorsementIndex, endorsement := range authorization.ClockEndorsements {
			endorsements[endorsementIndex] = store.ClockEndorsement{
				DeviceID:  endorsement.DeviceID,
				Signature: endorsement.Signature,
			}
		}
		writes.CredentialAuthorizations[index] =
			store.CredentialAuthorizationRow{
				SessionID:                authorization.SessionID,
				DeviceID:                 authorization.DeviceID,
				Epoch:                    authorization.Epoch,
				EpochPublicKey:           authorization.EpochPublicKey,
				KeyDigest:                authorization.KeyDigest,
				Role:                     credentialRole(authorization.Role),
				IssuedAt:                 authorization.IssuedAt,
				NotBefore:                authorization.NotBefore,
				ValiditySeconds:          authorization.ValiditySeconds,
				AuthorityVoterSetVersion: authorization.AuthorityVoterSetVersion,
				ClockEndorsements:        endorsements,
				BindingSignature:         authorization.BindingSignature,
				AuthorizationChainIndex:  authorization.AuthorizationChainIndex,
			}
	}
	for index, proposal := range changes.ControlFileProposals {
		var digest *[32]byte
		if proposal.ContentDigest != nil {
			value := [32]byte(*proposal.ContentDigest)
			digest = &value
		}
		writes.ControlFileProposals[index] = store.ControlFileProposalRow{
			ProposalEventID:    proposal.ProposalEventID,
			SessionID:          proposal.SessionID,
			Path:               proposal.Path,
			Operation:          store.ControlFileOperation(proposal.Operation),
			ContentDigest:      digest,
			ContentSize:        proposal.ContentSize,
			Diff:               proposal.Diff,
			ProposedByDeviceID: proposal.ProposedByDeviceID,
			ChainIndex:         proposal.ChainIndex,
		}
	}
	return writes
}

func credentialRole(role credentialauthorization.Role) device.Role {
	return device.Role(role)
}

func auditRecords(
	proposal event.Proposal,
	outcome reducer.Outcome,
	appliedAt domain.Timestamp,
	resultIndex uint64,
) ([]store.AuditRecord, error) {
	if outcome.Accepted() && outcome.RecordedAudit != nil {
		directive := outcome.RecordedAudit
		epoch := directive.SubjectCredentialEpoch
		return []store.AuditRecord{{
			SessionID:              proposal.SessionID,
			SourceKind:             store.AuditEvent,
			EventID:                proposal.EventID,
			ResultIndex:            resultIndex,
			ReporterDeviceID:       directive.ReporterDeviceID,
			SubjectDeviceID:        directive.SubjectDeviceID,
			SubjectCredentialEpoch: &epoch,
			ActorType:              proposal.Origin.ActorType(),
			IPCChannel:             ipcChannel(proposal.Origin.ActorType()),
			ActionCode:             directive.ActionCode,
			OutcomeCode:            directive.OutcomeCode,
			Subject:                directive.Subject,
			DetailsJSON:            []byte(`{}`),
			FirstSeenAt:            appliedAt,
			LastSeenAt:             appliedAt,
			ObservationCount:       1,
		}}, nil
	}

	source := store.AuditCommittedRejection
	if outcome.Accepted() {
		source = store.AuditAcceptedEvent
	}
	subject := auditSubject(proposal, outcome.Audit)
	details := []byte(`{}`)
	if outcome.Audit != nil {
		if outcome.Audit.Class != reducer.AuditOperatorOverride {
			return nil, fmt.Errorf(
				"%w: unknown audit class %q",
				ErrInvalidApplyMapping,
				outcome.Audit.Class,
			)
		}
		details = []byte(`{"class":"operator_override"}`)
	}
	records := []store.AuditRecord{{
		SessionID:        proposal.SessionID,
		SourceKind:       source,
		EventID:          proposal.EventID,
		ResultIndex:      resultIndex,
		ReporterDeviceID: proposal.Origin.DeviceID(),
		SubjectDeviceID:  proposal.Origin.DeviceID(),
		ActorType:        proposal.Origin.ActorType(),
		IPCChannel:       ipcChannel(proposal.Origin.ActorType()),
		ActionCode:       string(proposal.Kind),
		OutcomeCode:      string(outcome.Code),
		Subject:          subject,
		DetailsJSON:      details,
		FirstSeenAt:      appliedAt,
		LastSeenAt:       appliedAt,
		ObservationCount: 1,
	}}
	if outcome.Alarm != nil {
		alarm, err := alarmRecord(
			proposal,
			outcome,
			appliedAt,
			resultIndex,
		)
		if err != nil {
			return nil, err
		}
		records = append(records, alarm)
	}
	return records, nil
}

func alarmRecord(
	proposal event.Proposal,
	outcome reducer.Outcome,
	appliedAt domain.Timestamp,
	resultIndex uint64,
) (store.AuditRecord, error) {
	directive := outcome.Alarm
	if directive == nil {
		return store.AuditRecord{}, fmt.Errorf(
			"%w: missing alarm directive",
			ErrInvalidApplyMapping,
		)
	}
	var details []byte
	switch directive.Class {
	case reducer.AlarmConflictIntegrity:
		details = []byte(`{"class":"conflict_integrity"}`)
	case reducer.AlarmConflictDetectorCompatibility:
		details = []byte(
			`{"class":"conflict_detector_compatibility"}`,
		)
	default:
		return store.AuditRecord{}, fmt.Errorf(
			"%w: unknown alarm class %q",
			ErrInvalidApplyMapping,
			directive.Class,
		)
	}
	if len(directive.Subject) > 256 ||
		!utf8.ValidString(directive.Subject) {
		return store.AuditRecord{}, fmt.Errorf(
			"%w: invalid alarm subject",
			ErrInvalidApplyMapping,
		)
	}
	return store.AuditRecord{
		SessionID:        proposal.SessionID,
		SourceKind:       store.AuditLocalAggregate,
		EventID:          proposal.EventID,
		ResultIndex:      resultIndex,
		ReporterDeviceID: proposal.Origin.DeviceID(),
		ActorType:        proposal.Origin.ActorType(),
		IPCChannel:       ipcChannel(proposal.Origin.ActorType()),
		ActionCode:       "alarm." + string(directive.Class),
		OutcomeCode:      string(outcome.Code),
		Subject:          directive.Subject,
		DetailsJSON:      details,
		FirstSeenAt:      appliedAt,
		LastSeenAt:       appliedAt,
		ObservationCount: 1,
	}, nil
}

func auditSubject(
	proposal event.Proposal,
	directive *reducer.AuditDirective,
) string {
	if directive != nil && len(directive.Subject) <= 256 {
		return directive.Subject
	}
	if entityID, present := proposal.EntityID.Value(); present &&
		len(entityID) <= 256 {
		return entityID
	}
	return "session:" + string(proposal.SessionID)
}

func ipcChannel(actor event.ActorType) string {
	switch actor {
	case event.ActorAgent:
		return "agent"
	case event.ActorHuman:
		return "operator"
	case event.ActorDaemon:
		return "daemon"
	default:
		return ""
	}
}

func checkpointRecord(
	eventID domain.UUIDv7,
	directive reducer.CheckpointDirective,
) *store.CheckpointRecord {
	checkpoint := directive.Checkpoint
	record := &store.CheckpointRecord{
		CheckpointEventID:        eventID,
		SessionID:                checkpoint.SessionID,
		WorkspaceID:              checkpoint.WorkspaceID,
		RecoveryGeneration:       checkpoint.RecoveryGeneration,
		AuthorityVoterSetVersion: checkpoint.AuthorityVoterSetVersion,
		SignerDeviceID:           checkpoint.SignerDeviceID,
		Term:                     checkpoint.Term,
		CoveredAppliedLogIndex:   checkpoint.CoveredAppliedLogIndex,
		CoveredChainIndex:        checkpoint.CoveredChainIndex,
		CoveredChainHash:         checkpoint.CoveredChainHash,
		CoveredResultIndex:       checkpoint.CoveredResultIndex,
		CoveredResultHash:        checkpoint.CoveredResultHash,
		ProjectionAccumulator:    checkpoint.ProjectionAccumulator,
		DigestVersion:            checkpoint.DigestVersion,
		ProjectionSchemaVersion:  checkpoint.ProjectionSchemaVersion,
		CheckpointJSON:           append([]byte(nil), directive.CanonicalUnsignedJSON...),
		AuthoritySignature:       directive.AuthoritySignature,
	}
	return record
}

func leaseDeadlineChanges(
	changes reducer.Changes,
	context localApplyContext,
) ([]store.LeaseDeadlineRecord, []store.LeaseDeadlineKey, error) {
	var (
		upserts []store.LeaseDeadlineRecord
		deletes []store.LeaseDeadlineKey
	)
	appliedAt, err := context.AppliedAt.Time()
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%w: invalid apply timestamp",
			ErrInvalidApplyMapping,
		)
	}
	for _, value := range changes.Leases {
		if value.EntityVersion > 1 {
			deletes = append(deletes, store.LeaseDeadlineKey{
				LeaseID:       value.ID,
				EntityVersion: value.EntityVersion - 1,
			})
		}
		if value.Status != lease.StatusActive {
			continue
		}
		ttlNS := value.TTLSeconds * int64(time.Second)
		if ttlNS < 0 || context.MonotonicNowNS > math.MaxInt64-ttlNS {
			return nil, nil, fmt.Errorf(
				"%w: lease deadline overflows monotonic range",
				ErrInvalidApplyMapping,
			)
		}
		display := domain.Timestamp(
			appliedAt.Add(
				time.Duration(value.TTLSeconds) * time.Second,
			).UTC().Format(time.RFC3339Nano),
		)
		upserts = append(upserts, store.LeaseDeadlineRecord{
			LeaseID:             value.ID,
			EntityVersion:       value.EntityVersion,
			OriginBootID:        context.OriginBootID,
			MonotonicDeadlineNS: context.MonotonicNowNS + ttlNS,
			DisplayDeadlineAt:   display,
		})
	}
	return upserts, deletes, nil
}
