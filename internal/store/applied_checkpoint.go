package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrAppliedCheckpointIntegrity = errors.New(
	"store: applied checkpoint integrity failure",
)

// AppliedCheckpointLookup is one exact persisted checkpoint and the Raft
// command position whose SQLite transaction made it visible.
type AppliedCheckpointLookup struct {
	Record          CheckpointRecord
	AppliedLogIndex uint64
}

// AppliedCheckpoint returns an integrity-verified checkpoint from the active
// generation. A missing event is not an error; incomplete evidence for a
// present checkpoint is.
func (store *Store) AppliedCheckpoint(
	ctx context.Context,
	eventID domain.UUIDv7,
) (AppliedCheckpointLookup, bool, error) {
	if ctx == nil {
		return AppliedCheckpointLookup{}, false, fmt.Errorf(
			"%w: nil context",
			ErrInvalidOptions,
		)
	}
	if err := ctx.Err(); err != nil {
		return AppliedCheckpointLookup{}, false, err
	}
	if !eventID.Valid() {
		return AppliedCheckpointLookup{}, false, fmt.Errorf(
			"%w: invalid checkpoint event ID",
			ErrInvalidOptions,
		)
	}

	var (
		lookup AppliedCheckpointLookup
		found  bool
	)
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)

		end := sqlitex.Transaction(conn)
		defer end(&err)

		record, exists, err := readCheckpointRecord(conn, eventID)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if err := record.Validate(); err != nil {
			return appliedCheckpointIntegrity(
				"stored checkpoint is malformed",
				err,
			)
		}
		if record.CoveredAppliedLogIndex >= domain.MaxSafeInteger ||
			record.CoveredChainIndex >= domain.MaxSafeInteger ||
			record.CoveredResultIndex >= domain.MaxSafeInteger {
			return appliedCheckpointIntegrity(
				"checkpoint successor position is exhausted",
				nil,
			)
		}
		appliedLogIndex := record.CoveredAppliedLogIndex + 1

		state, hasState, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !hasState ||
			state.sessionID != record.SessionID ||
			state.recoveryGeneration != record.RecoveryGeneration ||
			state.lastAppliedLogIndex < appliedLogIndex ||
			state.chainIndex < record.CoveredChainIndex+1 ||
			state.resultIndex < record.CoveredResultIndex+1 {
			return appliedCheckpointIntegrity(
				"active consensus state does not cover checkpoint",
				nil,
			)
		}

		var bindingCount int64
		if err := queryOneArgs(
			conn,
			`SELECT count(*)
			   FROM command_results AS r
			   JOIN raft_command_applications AS a
			     ON a.recovery_generation = r.recovery_generation
			    AND a.event_id = r.event_id
			    AND a.proposal_digest = r.proposal_digest
			  WHERE r.event_id = ?1
			    AND r.session_id = ?2
			    AND r.workspace_id = ?3
			    AND r.recovery_generation = ?4
			    AND r.kind = 'consensus.checkpoint'
			    AND r.outcome_status = 'accepted'
			    AND r.chain_index = ?5
			    AND r.result_index = ?6
			    AND a.log_index = ?7
			    AND a.term = ?8;`,
			[]any{
				string(record.CheckpointEventID),
				string(record.SessionID),
				string(record.WorkspaceID),
				record.RecoveryGeneration,
				record.CoveredChainIndex + 1,
				record.CoveredResultIndex + 1,
				appliedLogIndex,
				record.Term,
			},
			func(stmt *sqlite.Stmt) {
				bindingCount = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if bindingCount != 1 {
			return appliedCheckpointIntegrity(
				"checkpoint lacks its exact accepted Raft command binding",
				nil,
			)
		}

		lookup = AppliedCheckpointLookup{
			Record:          cloneCheckpointRecord(record),
			AppliedLogIndex: appliedLogIndex,
		}
		found = true
		return nil
	})
	if err != nil {
		return AppliedCheckpointLookup{}, false, err
	}
	return lookup, found, nil
}

func readCheckpointRecord(
	conn *sqlite.Conn,
	eventID domain.UUIDv7,
) (CheckpointRecord, bool, error) {
	var (
		record CheckpointRecord
		count  int
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT checkpoint_event_id, session_id, workspace_id,
		        recovery_generation, authority_voter_set_version,
		        signer_device_id, term, covered_applied_log_index,
		        covered_chain_index, covered_chain_hash,
		        covered_result_index, covered_result_hash,
		        projection_accumulator, digest_version,
		        projection_schema_version, checkpoint_json,
		        authority_signature
		   FROM chain_checkpoints
		  WHERE checkpoint_event_id = ?1;`,
		[]any{string(eventID)},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 || rowErr != nil {
				return
			}
			record.CheckpointEventID = domain.UUIDv7(stmt.ColumnText(0))
			record.SessionID = domain.UUIDv7(stmt.ColumnText(1))
			record.WorkspaceID = domain.UUIDv4(stmt.ColumnText(2))
			numbers := []*uint64{
				&record.RecoveryGeneration,
				&record.AuthorityVoterSetVersion,
				&record.Term,
				&record.CoveredAppliedLogIndex,
				&record.CoveredChainIndex,
				&record.CoveredResultIndex,
				&record.DigestVersion,
				&record.ProjectionSchemaVersion,
			}
			for index, column := range [...]int{
				3, 4, 6, 7, 8, 10, 13, 14,
			} {
				*numbers[index], rowErr = checkpointUint64Column(
					stmt,
					column,
				)
				if rowErr != nil {
					return
				}
			}
			record.SignerDeviceID = domain.DeviceID(stmt.ColumnText(5))
			if rowErr = copyDigestColumn(
				&record.CoveredChainHash,
				stmt,
				9,
			); rowErr != nil {
				return
			}
			if rowErr = copyDigestColumn(
				&record.CoveredResultHash,
				stmt,
				11,
			); rowErr != nil {
				return
			}
			if rowErr = copyDigestColumn(
				&record.ProjectionAccumulator,
				stmt,
				12,
			); rowErr != nil {
				return
			}
			if stmt.ColumnType(15) != sqlite.TypeText {
				rowErr = errors.New("checkpoint JSON is not text")
				return
			}
			record.CheckpointJSON = []byte(stmt.ColumnText(15))
			if stmt.ColumnType(16) != sqlite.TypeBlob ||
				stmt.ColumnLen(16) != len(record.AuthoritySignature) {
				rowErr = errors.New(
					"checkpoint signature is not 64 bytes",
				)
				return
			}
			copy(
				record.AuthoritySignature[:],
				columnBytes(stmt, 16),
			)
		},
	)
	if err != nil {
		return CheckpointRecord{}, false, err
	}
	if rowErr != nil {
		return CheckpointRecord{}, false,
			appliedCheckpointIntegrity("read checkpoint row", rowErr)
	}
	if count > 1 {
		return CheckpointRecord{}, false,
			appliedCheckpointIntegrity("duplicate checkpoint rows", nil)
	}
	return record, count == 1, nil
}

func checkpointUint64Column(
	stmt *sqlite.Stmt,
	column int,
) (uint64, error) {
	if stmt.ColumnType(column) != sqlite.TypeInteger {
		return 0, fmt.Errorf("column %d is not an integer", column)
	}
	value := stmt.ColumnInt64(column)
	if value < 0 || uint64(value) > domain.MaxSafeInteger {
		return 0, fmt.Errorf(
			"column %d is outside the safe unsigned range",
			column,
		)
	}
	return uint64(value), nil
}

func cloneCheckpointRecord(record CheckpointRecord) CheckpointRecord {
	record.CheckpointJSON = bytes.Clone(record.CheckpointJSON)
	return record
}

func appliedCheckpointIntegrity(
	message string,
	cause error,
) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrAppliedCheckpointIntegrity, message)
	}
	return fmt.Errorf(
		"%w: %s: %v",
		ErrAppliedCheckpointIntegrity,
		message,
		cause,
	)
}
