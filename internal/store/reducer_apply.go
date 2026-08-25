package store

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
)

var ErrInvalidReducerApplyMapping = errors.New(
	"store: invalid reducer apply mapping",
)

type reducerApplyContext struct {
	recoveryGeneration uint64
	appliedAt          domain.Timestamp
	originBootID       domain.UUIDv7
	monotonicNowNS     int64
	priorHeads         ApplyHeads
}

func buildReducerApplyRequest(
	signed event.SignedEvent,
	outcome reducer.Outcome,
	context reducerApplyContext,
) (ApplyRequest, error) {
	if !domain.ValidUnsignedInteger(context.recoveryGeneration) ||
		!context.appliedAt.Valid() ||
		!context.originBootID.Valid() ||
		context.monotonicNowNS < 0 ||
		context.priorHeads.ResultIndex >= domain.MaxSafeInteger {
		return ApplyRequest{}, ErrInvalidReducerApplyMapping
	}
	if outcome.Status != reducer.StatusAccepted &&
		outcome.Status != reducer.StatusRejected {
		return ApplyRequest{}, ErrInvalidReducerApplyMapping
	}
	if outcome.Accepted() != outcome.Changes.AdvancesEventChain {
		return ApplyRequest{}, fmt.Errorf(
			"%w: event-chain marker disagrees with outcome",
			ErrInvalidReducerApplyMapping,
		)
	}
	if err := validateReducerOutcomeDirectives(
		signed.Proposal(),
		outcome,
	); err != nil {
		return ApplyRequest{}, err
	}
	outcomeJSON, err := outcome.ResultJSON()
	if err != nil {
		return ApplyRequest{}, fmt.Errorf(
			"%w: encode outcome: %v",
			ErrInvalidReducerApplyMapping,
			err,
		)
	}

	request := ApplyRequest{
		AppliedAt:          context.appliedAt,
		RecoveryGeneration: context.recoveryGeneration,
		Proposal:           signed,
		Outcome: CommandOutcome{
			Status: OutcomeStatus(outcome.Status),
			Code:   string(outcome.Code),
			JSON:   outcomeJSON,
		},
		Projections:    projectionWritesFromReducer(outcome.Changes),
		RecordActivity: outcome.RecordActivity,
	}
	if outcome.RecordActivity {
		request.ActivityTaskID = outcome.ActivityTaskID
	}
	request.Audit, err = reducerAuditRecords(
		signed.Proposal(),
		outcome,
		context.appliedAt,
		context.priorHeads.ResultIndex+1,
	)
	if err != nil {
		return ApplyRequest{}, err
	}
	if outcome.Checkpoint != nil {
		request.Checkpoint = reducerCheckpointRecord(
			signed.Proposal().EventID,
			*outcome.Checkpoint,
		)
	}
	request.LeaseDeadlines, request.DeleteLeaseDeadlines, err =
		reducerLeaseDeadlineChanges(outcome.Changes, context)
	if err != nil {
		return ApplyRequest{}, err
	}
	return request, nil
}

func validateReducerOutcomeDirectives(
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
			ErrInvalidReducerApplyMapping,
		)
	}
	if outcome.RecordedAudit != nil &&
		proposal.Kind != event.KindAuditRecorded ||
		outcome.Accepted() &&
			proposal.Kind == event.KindAuditRecorded &&
			outcome.RecordedAudit == nil {
		return fmt.Errorf(
			"%w: explicit audit directive has the wrong event kind",
			ErrInvalidReducerApplyMapping,
		)
	}
	if outcome.Checkpoint != nil &&
		proposal.Kind != event.KindConsensusCheckpoint ||
		outcome.Accepted() &&
			proposal.Kind == event.KindConsensusCheckpoint &&
			outcome.Checkpoint == nil {
		return fmt.Errorf(
			"%w: checkpoint directive has the wrong event kind",
			ErrInvalidReducerApplyMapping,
		)
	}
	if outcome.Accepted() && outcome.Alarm != nil {
		return fmt.Errorf(
			"%w: accepted outcome carries a rejection alarm",
			ErrInvalidReducerApplyMapping,
		)
	}
	if outcome.Alarm != nil &&
		proposal.Kind != event.KindWorkspaceConflictDetected {
		return fmt.Errorf(
			"%w: alarm directive has the wrong event kind",
			ErrInvalidReducerApplyMapping,
		)
	}
	return nil
}

func projectionWritesFromReducer(changes reducer.Changes) ProjectionWrites {
	writes := ProjectionWrites{
		AuditCounters:  changes.AuditCounters,
		Tasks:          changes.Tasks,
		PlanRevisions:  changes.PlanRevisions,
		PlanCurrent:    changes.PlanCurrent,
		MemoryRecords:  changes.MemoryRecords,
		Leases:         changes.Leases,
		Devices:        changes.Devices,
		VoterSet:       changes.VoterSet,
		AgentSessions:  changes.AgentSessions,
		CanonicalRefs:  changes.CanonicalRefs,
		Publications:   changes.Publications,
		MergeConflicts: changes.MergeConflicts,
		SessionPolicy:  changes.SessionPolicy,
		OriginScopes:   make([]OriginScopeRow, len(changes.OriginScopes)),
		CredentialAuthority: make(
			[]CredentialAuthorityRow,
			len(changes.CredentialAuthority),
		),
		CredentialAuthorizations: make(
			[]CredentialAuthorizationRow,
			len(changes.CredentialAuthorizations),
		),
		ControlFileProposals: make(
			[]ControlFileProposalRow,
			len(changes.ControlFileProposals),
		),
	}
	for index, scope := range changes.OriginScopes {
		writes.OriginScopes[index] = OriginScopeRow{
			DeviceID:     scope.DeviceID,
			ScopeKind:    string(scope.Kind),
			ScopeID:      scope.ScopeID,
			LastSequence: scope.LastSequence,
		}
	}
	for index, authority := range changes.CredentialAuthority {
		writes.CredentialAuthority[index] =
			CredentialAuthorityRow(authority)
	}
	for index, authorization := range changes.CredentialAuthorizations {
		endorsements := make(
			[]ClockEndorsement,
			len(authorization.ClockEndorsements),
		)
		for endorsementIndex, endorsement := range authorization.ClockEndorsements {
			endorsements[endorsementIndex] = ClockEndorsement{
				DeviceID:  endorsement.DeviceID,
				Signature: endorsement.Signature,
			}
		}
		writes.CredentialAuthorizations[index] =
			CredentialAuthorizationRow{
				SessionID:                authorization.SessionID,
				DeviceID:                 authorization.DeviceID,
				Epoch:                    authorization.Epoch,
				EpochPublicKey:           authorization.EpochPublicKey,
				KeyDigest:                authorization.KeyDigest,
				Role:                     device.Role(authorization.Role),
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
		writes.ControlFileProposals[index] = ControlFileProposalRow{
			ProposalEventID:    proposal.ProposalEventID,
			SessionID:          proposal.SessionID,
			Path:               proposal.Path,
			Operation:          ControlFileOperation(proposal.Operation),
			ContentDigest:      digest,
			ContentSize:        proposal.ContentSize,
			Diff:               proposal.Diff,
			ProposedByDeviceID: proposal.ProposedByDeviceID,
			ChainIndex:         proposal.ChainIndex,
		}
	}
	return writes
}

func reducerAuditRecords(
	proposal event.Proposal,
	outcome reducer.Outcome,
	appliedAt domain.Timestamp,
	resultIndex uint64,
) ([]AuditRecord, error) {
	if outcome.Accepted() && outcome.RecordedAudit != nil {
		directive := outcome.RecordedAudit
		epoch := directive.SubjectCredentialEpoch
		return []AuditRecord{{
			SessionID:              proposal.SessionID,
			SourceKind:             AuditEvent,
			EventID:                proposal.EventID,
			ResultIndex:            resultIndex,
			ReporterDeviceID:       directive.ReporterDeviceID,
			SubjectDeviceID:        directive.SubjectDeviceID,
			SubjectCredentialEpoch: &epoch,
			ActorType:              proposal.Origin.ActorType(),
			IPCChannel:             reducerIPCChannel(proposal.Origin.ActorType()),
			ActionCode:             directive.ActionCode,
			OutcomeCode:            directive.OutcomeCode,
			Subject:                directive.Subject,
			DetailsJSON:            []byte(`{}`),
			FirstSeenAt:            appliedAt,
			LastSeenAt:             appliedAt,
			ObservationCount:       1,
		}}, nil
	}

	source := AuditCommittedRejection
	if outcome.Accepted() {
		source = AuditAcceptedEvent
	}
	subject := reducerAuditSubject(proposal, outcome.Audit)
	details := []byte(`{}`)
	if outcome.Audit != nil {
		if outcome.Audit.Class != reducer.AuditOperatorOverride {
			return nil, fmt.Errorf(
				"%w: unknown audit class %q",
				ErrInvalidReducerApplyMapping,
				outcome.Audit.Class,
			)
		}
		details = []byte(`{"class":"operator_override"}`)
	}
	records := []AuditRecord{{
		SessionID:        proposal.SessionID,
		SourceKind:       source,
		EventID:          proposal.EventID,
		ResultIndex:      resultIndex,
		ReporterDeviceID: proposal.Origin.DeviceID(),
		SubjectDeviceID:  proposal.Origin.DeviceID(),
		ActorType:        proposal.Origin.ActorType(),
		IPCChannel:       reducerIPCChannel(proposal.Origin.ActorType()),
		ActionCode:       string(proposal.Kind),
		OutcomeCode:      string(outcome.Code),
		Subject:          subject,
		DetailsJSON:      details,
		FirstSeenAt:      appliedAt,
		LastSeenAt:       appliedAt,
		ObservationCount: 1,
	}}
	if outcome.Alarm != nil {
		alarm, err := reducerAlarmRecord(
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

func reducerAlarmRecord(
	proposal event.Proposal,
	outcome reducer.Outcome,
	appliedAt domain.Timestamp,
	resultIndex uint64,
) (AuditRecord, error) {
	directive := outcome.Alarm
	if directive == nil {
		return AuditRecord{}, fmt.Errorf(
			"%w: missing alarm directive",
			ErrInvalidReducerApplyMapping,
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
		return AuditRecord{}, fmt.Errorf(
			"%w: unknown alarm class %q",
			ErrInvalidReducerApplyMapping,
			directive.Class,
		)
	}
	if len(directive.Subject) > 256 ||
		!utf8.ValidString(directive.Subject) {
		return AuditRecord{}, fmt.Errorf(
			"%w: invalid alarm subject",
			ErrInvalidReducerApplyMapping,
		)
	}
	return AuditRecord{
		SessionID:        proposal.SessionID,
		SourceKind:       AuditLocalAggregate,
		EventID:          proposal.EventID,
		ResultIndex:      resultIndex,
		ReporterDeviceID: proposal.Origin.DeviceID(),
		ActorType:        proposal.Origin.ActorType(),
		IPCChannel:       reducerIPCChannel(proposal.Origin.ActorType()),
		ActionCode:       "alarm." + string(directive.Class),
		OutcomeCode:      string(outcome.Code),
		Subject:          directive.Subject,
		DetailsJSON:      details,
		FirstSeenAt:      appliedAt,
		LastSeenAt:       appliedAt,
		ObservationCount: 1,
	}, nil
}

func reducerAuditSubject(
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

func reducerIPCChannel(actor event.ActorType) string {
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

func reducerCheckpointRecord(
	eventID domain.UUIDv7,
	directive reducer.CheckpointDirective,
) *CheckpointRecord {
	checkpoint := directive.Checkpoint
	return &CheckpointRecord{
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
		CheckpointJSON: append(
			[]byte(nil),
			directive.CanonicalUnsignedJSON...,
		),
		AuthoritySignature: directive.AuthoritySignature,
	}
}

func reducerLeaseDeadlineChanges(
	changes reducer.Changes,
	context reducerApplyContext,
) ([]LeaseDeadlineRecord, []LeaseDeadlineKey, error) {
	var (
		upserts []LeaseDeadlineRecord
		deletes []LeaseDeadlineKey
	)
	appliedAt, err := context.appliedAt.Time()
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%w: invalid apply timestamp",
			ErrInvalidReducerApplyMapping,
		)
	}
	for _, value := range changes.Leases {
		if value.EntityVersion > 1 {
			deletes = append(deletes, LeaseDeadlineKey{
				LeaseID:       value.ID,
				EntityVersion: value.EntityVersion - 1,
			})
		}
		if value.Status != lease.StatusActive {
			continue
		}
		ttlNS := value.TTLSeconds * int64(time.Second)
		if ttlNS < 0 ||
			context.monotonicNowNS > math.MaxInt64-ttlNS {
			return nil, nil, fmt.Errorf(
				"%w: lease deadline overflows monotonic range",
				ErrInvalidReducerApplyMapping,
			)
		}
		display := domain.Timestamp(
			appliedAt.Add(
				time.Duration(value.TTLSeconds) * time.Second,
			).UTC().Format(time.RFC3339Nano),
		)
		upserts = append(upserts, LeaseDeadlineRecord{
			LeaseID:             value.ID,
			EntityVersion:       value.EntityVersion,
			OriginBootID:        context.originBootID,
			MonotonicDeadlineNS: context.monotonicNowNS + ttlNS,
			DisplayDeadlineAt:   display,
		})
	}
	return upserts, deletes, nil
}

var _ credentialauthorization.Role = credentialauthorization.RoleOwner
