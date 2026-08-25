package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"zombiezen.com/go/sqlite"
)

func verifyDerivedViews(conn *sqlite.Conn) error {
	resolver, err := newActivityTaskResolver(conn)
	if err != nil {
		return derivedViewIntegrity("load activity associations", err)
	}
	if err := verifyActivityView(conn, resolver); err != nil {
		return derivedViewIntegrity("activity", err)
	}
	if err := verifyCommandAuditView(conn); err != nil {
		return derivedViewIntegrity("command audit", err)
	}
	if err := verifyReducerAlarmAuditView(conn); err != nil {
		return derivedViewIntegrity("reducer alarm audit", err)
	}
	if err := verifyRecoveryBoundaryAuditView(conn); err != nil {
		return derivedViewIntegrity("recovery audit", err)
	}
	return nil
}

type activityTaskResolver struct {
	leases       map[domain.UUIDv7]domain.UUIDv7
	publications map[domain.UUIDv7]domain.UUIDv7
	conflicts    map[domain.ConflictID]domain.UUIDv7
}

func newActivityTaskResolver(
	conn *sqlite.Conn,
) (*activityTaskResolver, error) {
	resolver := &activityTaskResolver{
		leases:       make(map[domain.UUIDv7]domain.UUIDv7),
		publications: make(map[domain.UUIDv7]domain.UUIDv7),
		conflicts:    make(map[domain.ConflictID]domain.UUIDv7),
	}
	var rowErr error
	if err := query(
		conn,
		"SELECT lease_id, task_id FROM leases ORDER BY lease_id;",
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			id := domain.UUIDv7(stmt.ColumnText(0))
			taskID, err := optionalUUIDv7Column(stmt, 1)
			if !id.Valid() || err != nil {
				rowErr = errors.New("invalid current lease activity association")
				return
			}
			resolver.leases[id] = taskID
		},
	); err != nil {
		return nil, err
	}
	if rowErr != nil {
		return nil, rowErr
	}
	if err := query(
		conn,
		`SELECT publication_id, task_id
		   FROM publications ORDER BY publication_id;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			id := domain.UUIDv7(stmt.ColumnText(0))
			taskID, err := optionalUUIDv7Column(stmt, 1)
			if !id.Valid() || err != nil {
				rowErr = errors.New(
					"invalid current publication activity association",
				)
				return
			}
			resolver.publications[id] = taskID
		},
	); err != nil {
		return nil, err
	}
	if rowErr != nil {
		return nil, rowErr
	}
	if err := query(
		conn,
		`SELECT conflict_id, publication_id
		   FROM merge_conflicts ORDER BY conflict_id;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			id := domain.ConflictID(stmt.ColumnText(0))
			publicationID := domain.UUIDv7(stmt.ColumnText(1))
			if !id.Valid() || !publicationID.Valid() {
				rowErr = errors.New(
					"invalid current conflict activity association",
				)
				return
			}
			resolver.conflicts[id] = publicationID
		},
	); err != nil {
		return nil, err
	}
	if rowErr != nil {
		return nil, rowErr
	}
	return resolver, nil
}

func (resolver *activityTaskResolver) observeAccepted(
	proposal event.Proposal,
) error {
	entity, hasEntity := proposal.EntityID.Value()
	switch proposal.Kind {
	case event.KindLeaseAcquired:
		id := domain.UUIDv7(entity)
		taskID, _, err := optionalPayloadUUIDv7(proposal.Payload, "task_id")
		if !hasEntity || !id.Valid() || err != nil {
			return errors.New("invalid accepted lease association")
		}
		return retainActivityAssociation(resolver.leases, id, taskID)
	case event.KindPublicationProposed:
		id := domain.UUIDv7(entity)
		taskID, _, err := optionalPayloadUUIDv7(proposal.Payload, "task_id")
		if !hasEntity || !id.Valid() || err != nil {
			return errors.New("invalid accepted publication association")
		}
		return retainActivityAssociation(
			resolver.publications,
			id,
			taskID,
		)
	case event.KindWorkspaceConflictDetected:
		id := domain.ConflictID(entity)
		publicationID, present, err := optionalPayloadUUIDv7(
			proposal.Payload,
			"publication_id",
		)
		if !hasEntity || !id.Valid() || err != nil || !present {
			return errors.New("invalid accepted conflict association")
		}
		return retainActivityAssociation(
			resolver.conflicts,
			id,
			publicationID,
		)
	default:
		return nil
	}
}

func (resolver *activityTaskResolver) taskID(
	proposal event.Proposal,
) (domain.UUIDv7, error) {
	entity, hasEntity := proposal.EntityID.Value()
	switch proposal.Kind {
	case event.KindTaskCreated,
		event.KindTaskUpdated,
		event.KindTaskStateChanged,
		event.KindTaskClaimed,
		event.KindTaskReleased,
		event.KindTaskReassigned,
		event.KindTaskCancelled:
		taskID := domain.UUIDv7(entity)
		if !hasEntity || !taskID.Valid() {
			return "", errors.New("invalid task activity association")
		}
		return taskID, nil
	case event.KindLeaseAcquired,
		event.KindLeaseRenewed,
		event.KindLeaseReleased:
		id := domain.UUIDv7(entity)
		taskID, found := resolver.leases[id]
		if !hasEntity || !id.Valid() || !found {
			return "", errors.New("missing lease activity association")
		}
		return taskID, nil
	case event.KindMemoryAppended:
		taskID, _, err := optionalPayloadUUIDv7(
			proposal.Payload,
			"task_id",
		)
		return taskID, err
	case event.KindActivityRecorded:
		return activityTaskID(proposal)
	case event.KindPublicationProposed,
		event.KindPublicationReviewed,
		event.KindPublicationApplied,
		event.KindPublicationWithdrawn:
		id := domain.UUIDv7(entity)
		taskID, found := resolver.publications[id]
		if !hasEntity || !id.Valid() || !found {
			return "", errors.New(
				"missing publication activity association",
			)
		}
		return taskID, nil
	case event.KindWorkspaceConflictDetected,
		event.KindWorkspaceConflictForceResolved,
		event.KindWorkspaceConflictResolved:
		id := domain.ConflictID(entity)
		publicationID, found := resolver.conflicts[id]
		if !hasEntity || !id.Valid() || !found {
			return "", errors.New("missing conflict activity association")
		}
		taskID, found := resolver.publications[publicationID]
		if !found {
			return "", errors.New(
				"conflict activity publication is missing",
			)
		}
		return taskID, nil
	default:
		return "", nil
	}
}

func retainActivityAssociation[K comparable](
	values map[K]domain.UUIDv7,
	key K,
	taskID domain.UUIDv7,
) error {
	if previous, exists := values[key]; exists && previous != taskID {
		return errors.New("activity association changed")
	}
	values[key] = taskID
	return nil
}

func verifyActivityView(
	conn *sqlite.Conn,
	resolver *activityTaskResolver,
) error {
	var (
		rowErr error
		rows   int64
	)
	err := query(
		conn,
		`SELECT r.result_index, r.outcome_status, r.proposal_json,
		        a.event_id, a.session_id, a.device_id, a.actor_type,
		        a.agent_session_id, a.event_kind, a.task_id,
		        a.rationale_summary, a.capture_level, a.actions_json,
		        a.redaction_json, a.created_at
		   FROM command_results AS r
		   LEFT JOIN activity AS a ON a.event_id = r.event_id
		  ORDER BY r.result_index;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			rows++
			proposal, err := event.InspectUnverifiedProposal(
				[]byte(stmt.ColumnText(2)),
			)
			if err != nil {
				rowErr = fmt.Errorf("decode result proposal: %w", err)
				return
			}
			accepted := stmt.ColumnText(1) == string(OutcomeAccepted)
			if accepted {
				if err := resolver.observeAccepted(proposal); err != nil {
					rowErr = err
					return
				}
			}
			expected := accepted &&
				(proposal.RationaleSummary != "" ||
					len(proposal.Actions) != 0)
			present := stmt.ColumnType(3) != sqlite.TypeNull
			if present != expected {
				rowErr = errors.New(
					"activity cardinality differs from accepted proposal",
				)
				return
			}
			if !present {
				return
			}
			taskID, err := resolver.taskID(proposal)
			if err != nil {
				rowErr = err
				return
			}
			storedTaskID, err := optionalUUIDv7Column(stmt, 9)
			if err != nil {
				rowErr = err
				return
			}
			var members map[string]json.RawMessage
			if err := json.Unmarshal(
				[]byte(stmt.ColumnText(2)),
				&members,
			); err != nil {
				rowErr = err
				return
			}
			var agentSessionID string
			if proposal.Origin.ActorType() == event.ActorAgent {
				agentSessionID = string(
					proposal.Origin.AgentSessionID(),
				)
			}
			storedAgentSessionID, _ := optionalTextColumn(stmt, 7)
			if stmt.ColumnText(3) != string(proposal.EventID) ||
				stmt.ColumnText(4) != string(proposal.SessionID) ||
				stmt.ColumnText(5) !=
					string(proposal.Origin.DeviceID()) ||
				stmt.ColumnText(6) !=
					string(proposal.Origin.ActorType()) ||
				storedAgentSessionID != agentSessionID ||
				stmt.ColumnText(8) != string(proposal.Kind) ||
				storedTaskID != taskID ||
				stmt.ColumnText(10) != proposal.RationaleSummary ||
				stmt.ColumnText(11) !=
					string(proposal.CaptureLevel) ||
				stmt.ColumnText(12) != string(members["actions"]) ||
				stmt.ColumnText(13) != string(members["redaction"]) ||
				stmt.ColumnText(14) != string(proposal.CreatedAt) {
				rowErr = errors.New(
					"activity row differs from accepted proposal",
				)
			}
		},
	)
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	var resultCount int64
	if err := queryOne(
		conn,
		"SELECT count(*) FROM command_results;",
		func(stmt *sqlite.Stmt) {
			resultCount = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if rows != resultCount {
		return errors.New("activity verification skipped a command result")
	}
	var orphans int64
	if err := queryOne(
		conn,
		`SELECT count(*) FROM activity AS a
		  WHERE NOT EXISTS (
		        SELECT 1 FROM command_results AS r
		         WHERE r.event_id = a.event_id
		  );`,
		func(stmt *sqlite.Stmt) {
			orphans = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if orphans != 0 {
		return errors.New("activity contains an orphan row")
	}
	return nil
}

func verifyCommandAuditView(conn *sqlite.Conn) error {
	var (
		rowErr       error
		previous     uint64
		havePrevious bool
		rows         int64
	)
	err := query(
		conn,
		`SELECT r.result_index, r.outcome_status, r.outcome_code,
		        r.proposal_json, a.audit_id, a.session_id, a.source_kind,
		        a.event_id, a.result_index, a.reporter_device_id,
		        a.subject_device_id, a.subject_credential_epoch,
		        a.actor_type, a.ipc_channel, a.action_code,
		        a.outcome_code, a.subject, a.details_json,
		        a.first_seen_at, a.last_seen_at, a.observation_count
		   FROM command_results AS r
		   LEFT JOIN audit_events AS a
		     ON a.event_id = r.event_id
		    AND a.result_index = r.result_index
		    AND a.source_kind IN (
		            'accepted_event', 'committed_rejection', 'audit_event'
		        )
		  ORDER BY r.result_index, a.audit_id;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			resultIndex := stmt.ColumnInt64(0)
			if resultIndex < 1 {
				rowErr = errors.New("invalid command audit result index")
				return
			}
			index := uint64(resultIndex)
			if havePrevious && index == previous {
				rowErr = errors.New(
					"multiple authoritative audits name one command result",
				)
				return
			}
			havePrevious = true
			previous = index
			rows++
			if stmt.ColumnType(4) == sqlite.TypeNull {
				rowErr = errors.New(
					"command result lacks its authoritative audit",
				)
				return
			}
			proposal, err := event.InspectUnverifiedProposal(
				[]byte(stmt.ColumnText(3)),
			)
			if err != nil {
				rowErr = fmt.Errorf("decode audit proposal: %w", err)
				return
			}
			expected, err := expectedCommandAudit(
				proposal,
				OutcomeStatus(stmt.ColumnText(1)),
				stmt.ColumnText(2),
				index,
			)
			if err != nil {
				rowErr = err
				return
			}
			actual, err := auditRecordFromColumns(stmt, 5)
			if err != nil {
				rowErr = err
				return
			}
			if err := compareDerivedAudit(actual, expected); err != nil {
				rowErr = err
			}
		},
	)
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	var resultCount int64
	if err := queryOne(
		conn,
		"SELECT count(*) FROM command_results;",
		func(stmt *sqlite.Stmt) {
			resultCount = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if rows != resultCount {
		return errors.New(
			"authoritative audit verification skipped a command result",
		)
	}
	var orphans int64
	if err := queryOne(
		conn,
		`SELECT count(*) FROM audit_events AS a
		  WHERE a.source_kind IN (
		            'accepted_event', 'committed_rejection', 'audit_event'
		        )
		    AND NOT EXISTS (
		        SELECT 1 FROM command_results AS r
		         WHERE r.event_id = a.event_id
		           AND r.result_index = a.result_index
		    );`,
		func(stmt *sqlite.Stmt) {
			orphans = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if orphans != 0 {
		return errors.New(
			"authoritative audit contains an orphan row",
		)
	}
	return nil
}

func verifyReducerAlarmAuditView(conn *sqlite.Conn) error {
	var (
		rowErr       error
		previous     uint64
		havePrevious bool
		rows         int64
	)
	err := query(
		conn,
		`SELECT r.result_index, r.outcome_status, r.outcome_code,
		        r.proposal_json, a.audit_id, a.session_id, a.source_kind,
		        a.event_id, a.result_index, a.reporter_device_id,
		        a.subject_device_id, a.subject_credential_epoch,
		        a.actor_type, a.ipc_channel, a.action_code,
		        a.outcome_code, a.subject, a.details_json,
		        a.first_seen_at, a.last_seen_at, a.observation_count
		   FROM command_results AS r
		   LEFT JOIN audit_events AS a
		     ON a.event_id = r.event_id
		    AND a.result_index = r.result_index
		    AND a.source_kind = 'local_aggregate'
		  ORDER BY r.result_index, a.audit_id;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			rawIndex := stmt.ColumnInt64(0)
			if rawIndex < 1 {
				rowErr = errors.New("invalid reducer alarm result index")
				return
			}
			index := uint64(rawIndex)
			if havePrevious && index == previous {
				rowErr = errors.New(
					"multiple reducer alarms name one command result",
				)
				return
			}
			havePrevious = true
			previous = index
			rows++

			proposal, err := event.InspectUnverifiedProposal(
				[]byte(stmt.ColumnText(3)),
			)
			if err != nil {
				rowErr = fmt.Errorf("decode reducer alarm proposal: %w", err)
				return
			}
			expected, required, err := expectedReducerAlarmAudit(
				proposal,
				OutcomeStatus(stmt.ColumnText(1)),
				stmt.ColumnText(2),
				index,
			)
			if err != nil {
				rowErr = err
				return
			}
			present := stmt.ColumnType(4) != sqlite.TypeNull
			if present != required {
				rowErr = errors.New(
					"reducer alarm cardinality differs from committed outcome",
				)
				return
			}
			if !present {
				return
			}
			actual, err := auditRecordFromColumns(stmt, 5)
			if err != nil {
				rowErr = err
				return
			}
			if err := compareDerivedAudit(actual, expected); err != nil {
				rowErr = err
			}
		},
	)
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	var resultCount int64
	if err := queryOne(
		conn,
		"SELECT count(*) FROM command_results;",
		func(stmt *sqlite.Stmt) {
			resultCount = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if rows != resultCount {
		return errors.New(
			"reducer alarm verification skipped a command result",
		)
	}
	var invalidBindings int64
	if err := queryOne(
		conn,
		`SELECT count(*) FROM audit_events AS a
		  WHERE a.source_kind = 'local_aggregate'
		    AND (
		        (a.event_id IS NULL) <> (a.result_index IS NULL)
		        OR (
		            a.event_id IS NOT NULL
		            AND NOT EXISTS (
		                SELECT 1 FROM command_results AS r
		                 WHERE r.event_id = a.event_id
		                   AND r.result_index = a.result_index
		            )
		        )
		    );`,
		func(stmt *sqlite.Stmt) {
			invalidBindings = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if invalidBindings != 0 {
		return errors.New("local aggregate audit has an invalid result binding")
	}
	return nil
}

func expectedReducerAlarmAudit(
	proposal event.Proposal,
	status OutcomeStatus,
	outcomeCode string,
	resultIndex uint64,
) (AuditRecord, bool, error) {
	if status != OutcomeRejected ||
		proposal.Kind != event.KindWorkspaceConflictDetected {
		return AuditRecord{}, false, nil
	}
	var class reducer.AlarmClass
	switch reducer.Code(outcomeCode) {
	case reducer.CodeConflictIDMismatch,
		reducer.CodeConflictImmutableTupleMismatch:
		class = reducer.AlarmConflictIntegrity
	case reducer.CodeConflictDetectorPathsMismatch:
		class = reducer.AlarmConflictDetectorCompatibility
	default:
		return AuditRecord{}, false, nil
	}
	entityID, present := proposal.EntityID.Value()
	if !present {
		return AuditRecord{}, false, errors.New(
			"reducer alarm proposal has no conflict identity",
		)
	}
	details, err := codec.CanonicalizeSignedObject(
		[]byte(`{"class":"` + string(class) + `"}`),
	)
	if err != nil {
		return AuditRecord{}, false, err
	}
	return AuditRecord{
		SessionID:        proposal.SessionID,
		SourceKind:       AuditLocalAggregate,
		EventID:          proposal.EventID,
		ResultIndex:      resultIndex,
		ReporterDeviceID: proposal.Origin.DeviceID(),
		ActorType:        proposal.Origin.ActorType(),
		IPCChannel:       reducerIPCChannel(proposal.Origin.ActorType()),
		ActionCode:       "alarm." + string(class),
		OutcomeCode:      outcomeCode,
		Subject:          "conflict:" + entityID,
		DetailsJSON:      details,
		ObservationCount: 1,
	}, true, nil
}

func expectedCommandAudit(
	proposal event.Proposal,
	status OutcomeStatus,
	outcomeCode string,
	resultIndex uint64,
) (AuditRecord, error) {
	record := AuditRecord{
		SessionID:        proposal.SessionID,
		EventID:          proposal.EventID,
		ResultIndex:      resultIndex,
		ReporterDeviceID: proposal.Origin.DeviceID(),
		ActorType:        proposal.Origin.ActorType(),
		IPCChannel:       reducerIPCChannel(proposal.Origin.ActorType()),
		ObservationCount: 1,
	}
	if status == OutcomeAccepted &&
		proposal.Kind == event.KindAuditRecorded {
		var payload auditRecordedPayload
		if err := json.Unmarshal(proposal.Payload, &payload); err != nil {
			return AuditRecord{}, err
		}
		subjectID := domain.DeviceID(payload.SubjectDeviceID)
		if !subjectID.Valid() ||
			!domain.ValidUnsignedInteger(
				payload.SubjectCredentialEpoch,
			) {
			return AuditRecord{}, errors.New(
				"invalid accepted explicit-audit payload",
			)
		}
		epoch := payload.SubjectCredentialEpoch
		record.SourceKind = AuditEvent
		record.SubjectDeviceID = subjectID
		record.SubjectCredentialEpoch = &epoch
		record.ActionCode = payload.Action
		record.OutcomeCode = payload.Outcome
		record.Subject = payload.Subject
		record.DetailsJSON = []byte(`{}`)
		return record, nil
	}

	record.SourceKind = AuditCommittedRejection
	if status == OutcomeAccepted {
		record.SourceKind = AuditAcceptedEvent
	} else if status != OutcomeRejected {
		return AuditRecord{}, errors.New("invalid command audit outcome")
	}
	record.SubjectDeviceID = proposal.Origin.DeviceID()
	record.ActionCode = string(proposal.Kind)
	record.OutcomeCode = outcomeCode
	record.Subject = "session:" + string(proposal.SessionID)
	if entityID, present := proposal.EntityID.Value(); present &&
		len(entityID) <= 256 {
		record.Subject = entityID
	}
	record.DetailsJSON = []byte(`{}`)
	if status == OutcomeAccepted {
		subject, overridden, err := operatorOverrideAuditSubject(
			proposal,
		)
		if err != nil {
			return AuditRecord{}, err
		}
		if overridden {
			record.Subject = subject
			record.DetailsJSON = []byte(
				`{"class":"operator_override"}`,
			)
		}
	}
	return record, nil
}

func operatorOverrideAuditSubject(
	proposal event.Proposal,
) (string, bool, error) {
	entity, hasEntity := proposal.EntityID.Value()
	switch proposal.Kind {
	case event.KindTaskReleased:
		reason, present, err := optionalPayloadString(
			proposal.Payload,
			"release_reason",
		)
		if err != nil {
			return "", false, err
		}
		if !present || reason != "forced" {
			return "", false, nil
		}
		return "task:" + entity, hasEntity, nil
	case event.KindTaskReassigned, event.KindTaskCancelled:
		return "task:" + entity, hasEntity, nil
	case event.KindLeaseReleased:
		reason, present, err := optionalPayloadString(
			proposal.Payload,
			"release_reason",
		)
		if err != nil {
			return "", false, err
		}
		if !present || reason != "forced" {
			return "", false, nil
		}
		return "lease:" + entity, hasEntity, nil
	case event.KindPlanCurrentSelected:
		return "plan_current:" + string(proposal.SessionID), true, nil
	case event.KindPolicyChanged:
		return "session_policy:" + string(proposal.SessionID), true, nil
	case event.KindMembershipDeviceAdmitted,
		event.KindMembershipRoleChanged,
		event.KindMembershipOwnerRecovered,
		event.KindMembershipDeviceRevoked:
		return "device_membership:" + entity, hasEntity, nil
	case event.KindMembershipVoterSetChanged:
		return "voter_set:" + string(proposal.SessionID), true, nil
	case event.KindWorkspaceConflictForceResolved:
		return "conflict:" + entity, hasEntity, nil
	default:
		return "", false, nil
	}
}

func verifyRecoveryBoundaryAuditView(conn *sqlite.Conn) error {
	var (
		rowErr error
		rows   int64
	)
	err := query(
		conn,
		`SELECT g.recovery_generation, g.session_id, g.genesis_digest,
		        a.audit_id, a.session_id, a.source_kind, a.event_id,
		        a.result_index, a.reporter_device_id,
		        a.subject_device_id, a.subject_credential_epoch,
		        a.actor_type, a.ipc_channel, a.action_code,
		        a.outcome_code, a.subject, a.details_json,
		        a.first_seen_at, a.last_seen_at, a.observation_count
		   FROM genesis_records AS g
		   LEFT JOIN audit_events AS a
		     ON a.session_id = g.session_id
		    AND a.source_kind = 'recovery_boundary'
		  WHERE g.recovery_generation > 0
		  ORDER BY g.recovery_generation;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			rows++
			generation := stmt.ColumnInt64(0)
			sessionID := domain.UUIDv7(stmt.ColumnText(1))
			var genesisDigest Digest
			if generation < 1 ||
				!sessionID.Valid() ||
				copyDigestColumn(&genesisDigest, stmt, 2) != nil ||
				stmt.ColumnType(3) == sqlite.TypeNull {
				rowErr = errors.New(
					"successor genesis lacks a recovery audit",
				)
				return
			}
			actual, err := auditRecordFromColumns(stmt, 4)
			if err != nil {
				rowErr = err
				return
			}
			expected := AuditRecord{
				SessionID:   sessionID,
				SourceKind:  AuditRecoveryBoundary,
				ActorType:   event.ActorHuman,
				IPCChannel:  "operator",
				ActionCode:  "cluster.quorum_recovered",
				OutcomeCode: "accepted",
				Subject:     "session:" + string(sessionID),
				DetailsJSON: recoveryBoundaryAuditDetails(
					uint64(generation),
					genesisDigest,
				),
				ObservationCount: 1,
			}
			if err := compareDerivedAudit(actual, expected); err != nil {
				rowErr = err
			}
		},
	)
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	var successorCount int64
	if err := queryOne(
		conn,
		`SELECT count(*) FROM genesis_records
		  WHERE recovery_generation > 0;`,
		func(stmt *sqlite.Stmt) {
			successorCount = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if rows != successorCount {
		return errors.New(
			"recovery audit verification skipped a successor",
		)
	}
	var orphans int64
	if err := queryOne(
		conn,
		`SELECT count(*) FROM audit_events AS a
		  WHERE a.source_kind = 'recovery_boundary'
		    AND NOT EXISTS (
		        SELECT 1 FROM genesis_records AS g
		         WHERE g.session_id = a.session_id
		           AND g.recovery_generation > 0
		           AND g.genesis_kind = 'successor'
		    );`,
		func(stmt *sqlite.Stmt) {
			orphans = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if orphans != 0 {
		return errors.New("recovery audit contains an orphan row")
	}
	return nil
}

func recoveryBoundaryAuditDetails(
	generation uint64,
	genesisDigest Digest,
) []byte {
	raw, _ := json.Marshal(struct {
		GenesisDigest      string `json:"genesis_digest"`
		RecoveryGeneration uint64 `json:"recovery_generation"`
	}{
		GenesisDigest:      hex.EncodeToString(genesisDigest[:]),
		RecoveryGeneration: generation,
	})
	canonical, _ := codec.CanonicalizeSignedObject(raw)
	return canonical
}

func auditRecordFromColumns(
	stmt *sqlite.Stmt,
	offset int,
) (AuditRecord, error) {
	eventID, _ := optionalTextColumn(stmt, offset+2)
	resultIndex, resultPresent, err := optionalUint64Column(
		stmt,
		offset+3,
	)
	if err != nil {
		return AuditRecord{}, err
	}
	reporter, _ := optionalTextColumn(stmt, offset+4)
	subjectDevice, _ := optionalTextColumn(stmt, offset+5)
	epoch, epochPresent, err := optionalUint64Column(stmt, offset+6)
	if err != nil {
		return AuditRecord{}, err
	}
	actor, _ := optionalTextColumn(stmt, offset+7)
	channel, _ := optionalTextColumn(stmt, offset+8)
	record := AuditRecord{
		SessionID:        domain.UUIDv7(stmt.ColumnText(offset)),
		SourceKind:       AuditSourceKind(stmt.ColumnText(offset + 1)),
		EventID:          domain.UUIDv7(eventID),
		ReporterDeviceID: domain.DeviceID(reporter),
		SubjectDeviceID:  domain.DeviceID(subjectDevice),
		ActorType:        event.ActorType(actor),
		IPCChannel:       channel,
		ActionCode:       stmt.ColumnText(offset + 9),
		OutcomeCode:      stmt.ColumnText(offset + 10),
		Subject:          stmt.ColumnText(offset + 11),
		DetailsJSON:      []byte(stmt.ColumnText(offset + 12)),
		FirstSeenAt:      domain.Timestamp(stmt.ColumnText(offset + 13)),
		LastSeenAt:       domain.Timestamp(stmt.ColumnText(offset + 14)),
		ObservationCount: uint64(stmt.ColumnInt64(offset + 15)),
	}
	if resultPresent {
		record.ResultIndex = resultIndex
	}
	if epochPresent {
		record.SubjectCredentialEpoch = &epoch
	}
	if err := record.Validate(); err != nil {
		return AuditRecord{}, err
	}
	return record, nil
}

func compareDerivedAudit(actual, expected AuditRecord) error {
	if actual.SessionID != expected.SessionID ||
		actual.SourceKind != expected.SourceKind ||
		actual.EventID != expected.EventID ||
		actual.ResultIndex != expected.ResultIndex ||
		actual.ReporterDeviceID != expected.ReporterDeviceID ||
		actual.SubjectDeviceID != expected.SubjectDeviceID ||
		!equalOptionalUint64(
			actual.SubjectCredentialEpoch,
			expected.SubjectCredentialEpoch,
		) ||
		actual.ActorType != expected.ActorType ||
		actual.IPCChannel != expected.IPCChannel ||
		actual.ActionCode != expected.ActionCode ||
		actual.OutcomeCode != expected.OutcomeCode ||
		actual.Subject != expected.Subject ||
		!bytes.Equal(actual.DetailsJSON, expected.DetailsJSON) ||
		actual.FirstSeenAt != actual.LastSeenAt ||
		actual.ObservationCount != expected.ObservationCount {
		return fmt.Errorf(
			"audit row differs from its authoritative source: got %+v, want %+v",
			actual,
			expected,
		)
	}
	return nil
}

func equalOptionalUint64(left, right *uint64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func optionalPayloadUUIDv7(
	payload []byte,
	name string,
) (domain.UUIDv7, bool, error) {
	value, present, err := optionalPayloadString(payload, name)
	if err != nil || !present {
		return "", present, err
	}
	id := domain.UUIDv7(value)
	if !id.Valid() {
		return "", true, errors.New("payload contains an invalid UUIDv7")
	}
	return id, true, nil
}

func optionalPayloadString(
	payload []byte,
	name string,
) (string, bool, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return "", false, err
	}
	raw, present := members[name]
	if !present {
		return "", false, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, err
	}
	return value, true, nil
}

func optionalUUIDv7Column(
	stmt *sqlite.Stmt,
	column int,
) (domain.UUIDv7, error) {
	value, present := optionalTextColumn(stmt, column)
	if !present {
		return "", nil
	}
	id := domain.UUIDv7(value)
	if !id.Valid() {
		return "", errors.New("invalid nullable UUIDv7 column")
	}
	return id, nil
}

func optionalTextColumn(
	stmt *sqlite.Stmt,
	column int,
) (string, bool) {
	if stmt.ColumnType(column) == sqlite.TypeNull {
		return "", false
	}
	return stmt.ColumnText(column), true
}

func optionalUint64Column(
	stmt *sqlite.Stmt,
	column int,
) (uint64, bool, error) {
	if stmt.ColumnType(column) == sqlite.TypeNull {
		return 0, false, nil
	}
	value := stmt.ColumnInt64(column)
	if value < 0 || !domain.ValidUnsignedInteger(uint64(value)) {
		return 0, true, errors.New("invalid nullable unsigned integer")
	}
	return uint64(value), true, nil
}

func derivedViewIntegrity(detail string, cause error) error {
	return historyIntegrityError("derived view "+detail, cause)
}
