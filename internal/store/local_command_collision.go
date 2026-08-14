package store

import (
	"context"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

// AbandonCommandCollision durably removes one exact poisoned outbox command.
// A resolved command is returned unchanged when commitment won the race.
func (state LocalState) AbandonCommandCollision(
	ctx context.Context,
	input LocalCommandCollisionInput,
) (LocalCommandRecord, bool, error) {
	if !input.ClientInstanceID.Valid() ||
		!input.RequestID.Valid() ||
		!input.SessionID.Valid() ||
		!domain.ValidUnsignedInteger(input.RecoveryGeneration) ||
		!input.EventID.Valid() {
		return LocalCommandRecord{}, false, ErrInvalidLocalState
	}
	var (
		result    LocalCommandRecord
		duplicate bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if lineage.sessionID != input.SessionID ||
			lineage.recoveryGeneration != input.RecoveryGeneration {
			return ErrLocalLineageMismatch
		}
		record, found, err := readLocalRequestByKey(
			conn,
			input.ClientInstanceID,
			input.RequestID,
		)
		if err != nil {
			return err
		}
		if !found ||
			record.SessionID != input.SessionID ||
			record.RecoveryGeneration != input.RecoveryGeneration ||
			record.EventID != input.EventID ||
			record.ProposalDigest != input.ProposalDigest {
			return ErrLocalStateIntegrity
		}
		switch record.State {
		case LocalRequestResolved:
			result = record
			duplicate = true
			return nil
		case LocalRequestAbandoned:
			if record.TerminalCode != LocalEventIDCollisionCode {
				return ErrLocalStateIntegrity
			}
			result = record
			duplicate = true
			return nil
		case LocalRequestSigned, LocalRequestPending:
			// Continue below.
		default:
			return ErrLocalStateIntegrity
		}
		if err := execute(
			conn,
			`DELETE FROM outbox
			  WHERE event_id = ?1
			    AND recovery_generation = ?2
			    AND proposal_digest = ?3;`,
			string(input.EventID),
			input.RecoveryGeneration,
			input.ProposalDigest[:],
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE local_requests
			    SET state = 'abandoned',
			        publication_metadata_json = NULL,
			        publication_metadata_digest = NULL,
			        artifact_digest = NULL,
			        signed_proposal_json = NULL,
			        terminal_code = ?4
			  WHERE client_instance_id = ?1
			    AND request_id = ?2
			    AND event_id = ?3
			    AND state IN ('signed', 'pending');`,
			string(input.ClientInstanceID),
			string(input.RequestID),
			string(input.EventID),
			LocalEventIDCollisionCode,
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		result, found, err = readLocalRequestByKey(
			conn,
			input.ClientInstanceID,
			input.RequestID,
		)
		if err != nil {
			return err
		}
		if !found ||
			result.State != LocalRequestAbandoned ||
			result.TerminalCode != LocalEventIDCollisionCode {
			return ErrLocalStateIntegrity
		}
		return nil
	})
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	return result, duplicate, nil
}
