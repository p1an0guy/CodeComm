package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
)

var ErrCheckpointCadenceIntegrity = errors.New(
	"store: checkpoint cadence integrity failure",
)

// CheckpointCadence is one transactionally consistent scheduling cut. The
// baseline names the active generation boundary or its latest accepted
// checkpoint event. BaselineObservedAt is receiver-local support state.
type CheckpointCadence struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64

	HeadChainIndex      uint64
	HeadResultIndex     uint64
	CheckpointEventID   domain.UUIDv7
	BaselineChainIndex  uint64
	BaselineResultIndex uint64
	BaselineObservedAt  domain.Timestamp

	CheckpointEvents          int64
	CheckpointIntervalSeconds int64
}

type checkpointCadenceRow struct {
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
	checkpointEventID  domain.UUIDv7
	chainIndex         uint64
	resultIndex        uint64
	observedAt         domain.Timestamp
}

type checkpointCadenceCheckpoint struct {
	eventID     domain.UUIDv7
	chainIndex  uint64
	resultIndex uint64
}

// CheckpointCadence returns the current heads, committed policy, and durable
// receiver-local cadence baseline from one SQLite transaction.
func (state LocalState) CheckpointCadence(
	ctx context.Context,
) (CheckpointCadence, error) {
	var result CheckpointCadence
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var err error
		result, err = readVerifiedCheckpointCadence(conn)
		return err
	})
	if err != nil {
		return CheckpointCadence{}, err
	}
	return result, nil
}

func readVerifiedCheckpointCadence(
	conn *sqlite.Conn,
) (CheckpointCadence, error) {
	committed, workspaceID, row, err :=
		verifyCheckpointCadenceBinding(conn)
	if err != nil {
		return CheckpointCadence{}, err
	}
	values, err := readCheckpointCadencePolicy(conn, committed.sessionID)
	if err != nil {
		return CheckpointCadence{}, err
	}
	return CheckpointCadence{
		SessionID:                 committed.sessionID,
		WorkspaceID:               workspaceID,
		RecoveryGeneration:        committed.recoveryGeneration,
		HeadChainIndex:            committed.chainIndex,
		HeadResultIndex:           committed.resultIndex,
		CheckpointEventID:         row.checkpointEventID,
		BaselineChainIndex:        row.chainIndex,
		BaselineResultIndex:       row.resultIndex,
		BaselineObservedAt:        row.observedAt,
		CheckpointEvents:          values.CheckpointEvents,
		CheckpointIntervalSeconds: values.CheckpointIntervalSeconds,
	}, nil
}

func verifyCheckpointCadenceBinding(
	conn *sqlite.Conn,
) (
	consensusState,
	domain.UUIDv4,
	checkpointCadenceRow,
	error,
) {
	committed, found, err := readConsensusState(conn)
	if err != nil {
		return consensusState{}, "", checkpointCadenceRow{}, err
	}
	row, rowFound, err := readCheckpointCadenceRow(conn)
	if err != nil {
		return consensusState{}, "", checkpointCadenceRow{}, err
	}
	if !found {
		if rowFound {
			return consensusState{}, "", checkpointCadenceRow{},
				checkpointCadenceError(
					"baseline exists without an active generation",
					nil,
				)
		}
		return consensusState{}, "", checkpointCadenceRow{},
			fmt.Errorf(
				"%w: store has no active generation",
				ErrApplyConflict,
			)
	}
	if !rowFound {
		return consensusState{}, "", checkpointCadenceRow{},
			checkpointCadenceError(
				"active generation lacks a baseline",
				nil,
			)
	}
	workspaceID, err := activeWorkspaceID(conn, committed)
	if err != nil {
		return consensusState{}, "", checkpointCadenceRow{},
			checkpointCadenceError(
				"read active workspace",
				err,
			)
	}
	if row.sessionID != committed.sessionID ||
		row.workspaceID != workspaceID ||
		row.recoveryGeneration != committed.recoveryGeneration ||
		row.chainIndex > committed.chainIndex ||
		row.resultIndex > committed.resultIndex {
		return consensusState{}, "", checkpointCadenceRow{},
			checkpointCadenceError(
				"baseline differs from the active lineage or heads",
				nil,
			)
	}
	if _, err := row.observedAt.Time(); err != nil {
		return consensusState{}, "", checkpointCadenceRow{},
			checkpointCadenceError(
				"baseline observation time is invalid",
				err,
			)
	}

	latest, checkpointFound, err := latestCheckpointCadence(
		conn,
		committed,
		workspaceID,
	)
	if err != nil {
		return consensusState{}, "", checkpointCadenceRow{}, err
	}
	if checkpointFound {
		if row.checkpointEventID != latest.eventID ||
			row.chainIndex != latest.chainIndex ||
			row.resultIndex != latest.resultIndex {
			return consensusState{}, "", checkpointCadenceRow{},
				checkpointCadenceError(
					"baseline is not the latest accepted checkpoint",
					nil,
				)
		}
	} else {
		genesis, err := readGenesisBoundary(
			conn,
			committed.recoveryGeneration,
			committed.sessionID,
		)
		if err != nil {
			return consensusState{}, "", checkpointCadenceRow{},
				checkpointCadenceError(
					"read active generation boundary",
					err,
				)
		}
		if row.checkpointEventID != "" ||
			row.chainIndex != genesis.predecessorChainIndex ||
			row.resultIndex != genesis.predecessorResultIndex {
			return consensusState{}, "", checkpointCadenceRow{},
				checkpointCadenceError(
					"non-checkpoint baseline differs from the generation boundary",
					nil,
				)
		}
	}
	return committed, workspaceID, row, nil
}

func readCheckpointCadenceRow(
	conn *sqlite.Conn,
) (checkpointCadenceRow, bool, error) {
	var (
		result checkpointCadenceRow
		count  int
		rowErr error
	)
	err := query(
		conn,
		`SELECT session_id, workspace_id, recovery_generation,
		        checkpoint_event_id, baseline_chain_index,
		        baseline_result_index, observed_at
		   FROM checkpoint_cadence_state
		  ORDER BY singleton;`,
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 || rowErr != nil {
				return
			}
			result.sessionID = domain.UUIDv7(stmt.ColumnText(0))
			result.workspaceID = domain.UUIDv4(stmt.ColumnText(1))
			if stmt.ColumnType(3) != sqlite.TypeNull {
				result.checkpointEventID =
					domain.UUIDv7(stmt.ColumnText(3))
			}
			result.observedAt = domain.Timestamp(stmt.ColumnText(6))
			generation := stmt.ColumnInt64(2)
			chainIndex := stmt.ColumnInt64(4)
			resultIndex := stmt.ColumnInt64(5)
			if generation < 0 || chainIndex < 0 || resultIndex < 0 {
				rowErr = errors.New("negative cadence position")
				return
			}
			result.recoveryGeneration = uint64(generation)
			result.chainIndex = uint64(chainIndex)
			result.resultIndex = uint64(resultIndex)
		},
	)
	if err != nil {
		return checkpointCadenceRow{}, false, err
	}
	if count == 0 {
		return checkpointCadenceRow{}, false, nil
	}
	if count != 1 || rowErr != nil ||
		!result.sessionID.Valid() ||
		!result.workspaceID.Valid() ||
		!domain.ValidUnsignedInteger(result.recoveryGeneration) ||
		!domain.ValidUnsignedInteger(result.chainIndex) ||
		!domain.ValidUnsignedInteger(result.resultIndex) ||
		result.chainIndex > result.resultIndex ||
		result.checkpointEventID != "" &&
			!result.checkpointEventID.Valid() ||
		!result.observedAt.Valid() {
		return checkpointCadenceRow{}, false, checkpointCadenceError(
			"stored baseline is malformed",
			rowErr,
		)
	}
	return result, true, nil
}

func latestCheckpointCadence(
	conn *sqlite.Conn,
	committed consensusState,
	workspaceID domain.UUIDv4,
) (checkpointCadenceCheckpoint, bool, error) {
	var (
		result checkpointCadenceCheckpoint
		found  bool
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT checkpoints.checkpoint_event_id,
		        checkpoints.covered_chain_index,
		        checkpoints.covered_result_index,
		        results.chain_index, results.result_index,
		        results.kind, results.outcome_status
		   FROM chain_checkpoints AS checkpoints
		   LEFT JOIN command_results AS results
		     ON results.event_id = checkpoints.checkpoint_event_id
		  WHERE checkpoints.session_id = ?1
		    AND checkpoints.workspace_id = ?2
		    AND checkpoints.recovery_generation = ?3
		  ORDER BY checkpoints.covered_result_index DESC
		  LIMIT 1;`,
		[]any{
			string(committed.sessionID),
			string(workspaceID),
			committed.recoveryGeneration,
		},
		func(stmt *sqlite.Stmt) {
			found = true
			result.eventID = domain.UUIDv7(stmt.ColumnText(0))
			if stmt.ColumnType(3) == sqlite.TypeNull ||
				stmt.ColumnType(4) == sqlite.TypeNull {
				rowErr = errors.New("checkpoint command result is missing")
				return
			}
			coveredChain := stmt.ColumnInt64(1)
			coveredResult := stmt.ColumnInt64(2)
			chainIndex := stmt.ColumnInt64(3)
			resultIndex := stmt.ColumnInt64(4)
			if coveredChain < 0 || coveredResult < 0 ||
				chainIndex < 1 || resultIndex < 1 ||
				coveredChain >= int64(domain.MaxSafeInteger) ||
				coveredResult >= int64(domain.MaxSafeInteger) ||
				chainIndex != coveredChain+1 ||
				resultIndex != coveredResult+1 ||
				stmt.ColumnText(5) != string(event.KindConsensusCheckpoint) ||
				stmt.ColumnText(6) != string(OutcomeAccepted) {
				rowErr = errors.New(
					"checkpoint and command-result positions differ",
				)
				return
			}
			result.chainIndex = uint64(chainIndex)
			result.resultIndex = uint64(resultIndex)
		},
	)
	if err != nil {
		return checkpointCadenceCheckpoint{}, false, err
	}
	if !found {
		return checkpointCadenceCheckpoint{}, false, nil
	}
	if rowErr != nil || !result.eventID.Valid() ||
		result.chainIndex > committed.chainIndex ||
		result.resultIndex > committed.resultIndex {
		return checkpointCadenceCheckpoint{}, false,
			checkpointCadenceError(
				"latest checkpoint binding is malformed",
				rowErr,
			)
	}
	return result, true, nil
}

func readCheckpointCadencePolicy(
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
) (policy.Values, error) {
	var (
		encoded string
		count   int
	)
	if err := queryArgs(
		conn,
		`SELECT values_json
		   FROM session_policy
		  WHERE session_id = ?1;`,
		[]any{string(sessionID)},
		func(stmt *sqlite.Stmt) {
			count++
			encoded = stmt.ColumnText(0)
		},
	); err != nil {
		return policy.Values{}, err
	}
	canonical, err := codec.CanonicalizeSignedObject([]byte(encoded))
	if count != 1 || err != nil ||
		!bytes.Equal(canonical, []byte(encoded)) {
		return policy.Values{}, checkpointCadenceError(
			"committed policy is missing or noncanonical",
			err,
		)
	}
	var wire policyValuesJSON
	if err := decodeClosedPeerEndpointJSON(canonical, &wire); err != nil {
		return policy.Values{}, checkpointCadenceError(
			"decode committed policy",
			err,
		)
	}
	values := policy.Values{
		CheckpointEvents:             wire.CheckpointEvents,
		CheckpointIntervalSeconds:    wire.CheckpointIntervalSeconds,
		LeaseMinTTLSeconds:           wire.LeaseMinTTLSeconds,
		LeaseDefaultTTLSeconds:       wire.LeaseDefaultTTLSeconds,
		LeaseMaxTTLSeconds:           wire.LeaseMaxTTLSeconds,
		AgentClaimLimit:              wire.AgentClaimLimit,
		AgentLeaseLimit:              wire.AgentLeaseLimit,
		DeviceClaimLimit:             wire.DeviceClaimLimit,
		DeviceLeaseLimit:             wire.DeviceLeaseLimit,
		AdvertisementIntervalSeconds: wire.AdvertisementIntervalSeconds,
		AuditDepthPerDevicePerEpoch:  wire.AuditDepthPerDevicePerEpoch,
		MaxMemberDevices:             wire.MaxMemberDevices,
		MaxActiveAgentSessions:       wire.MaxActiveAgentSessions,
		ClusterMinApplyLevel:         wire.ClusterMinApplyLevel,
	}
	if err := values.Validate(); err != nil {
		return policy.Values{}, checkpointCadenceError(
			"committed policy is invalid",
			err,
		)
	}
	return values, nil
}

func checkpointCadenceMigrationObservedAt(
	conn *sqlite.Conn,
) (domain.Timestamp, error) {
	var result domain.Timestamp
	if err := queryOneArgs(
		conn,
		`SELECT applied_at
		   FROM schema_migrations
		  WHERE version = 10 AND name = 'checkpoint_cadence';`,
		nil,
		func(stmt *sqlite.Stmt) {
			result = domain.Timestamp(stmt.ColumnText(0))
		},
	); err != nil {
		return "", checkpointCadenceError(
			"read initialization observation time",
			err,
		)
	}
	if !result.Valid() {
		return "", checkpointCadenceError(
			"initialization observation time is invalid",
			nil,
		)
	}
	return result, nil
}

func writeCheckpointCadenceBoundary(
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	recoveryGeneration uint64,
	heads ApplyHeads,
	observedAt domain.Timestamp,
) error {
	return writeCheckpointCadenceRow(
		conn,
		checkpointCadenceRow{
			sessionID:          sessionID,
			workspaceID:        workspaceID,
			recoveryGeneration: recoveryGeneration,
			chainIndex:         heads.ChainIndex,
			resultIndex:        heads.ResultIndex,
			observedAt:         observedAt,
		},
	)
}

func writeCheckpointCadenceCheckpoint(
	conn *sqlite.Conn,
	request ApplyRequest,
	heads ApplyHeads,
) error {
	if request.Checkpoint == nil {
		return nil
	}
	record := *request.Checkpoint
	if request.Outcome.Status != OutcomeAccepted ||
		record.CheckpointEventID != request.Proposal.Proposal().EventID {
		return checkpointCadenceError(
			"checkpoint baseline input is inconsistent",
			nil,
		)
	}
	return writeCheckpointCadenceRow(
		conn,
		checkpointCadenceRow{
			sessionID:          record.SessionID,
			workspaceID:        record.WorkspaceID,
			recoveryGeneration: record.RecoveryGeneration,
			checkpointEventID:  record.CheckpointEventID,
			chainIndex:         heads.ChainIndex,
			resultIndex:        heads.ResultIndex,
			observedAt:         request.AppliedAt,
		},
	)
}

func writeCheckpointCadenceSnapshot(
	conn *sqlite.Conn,
	cut LogicalSnapshotCut,
	observedAt domain.Timestamp,
) error {
	if !cut.CheckpointEventID.Valid() {
		return checkpointCadenceError(
			"snapshot cut has no checkpoint event",
			nil,
		)
	}
	return writeCheckpointCadenceRow(
		conn,
		checkpointCadenceRow{
			sessionID:          cut.SessionID,
			workspaceID:        cut.WorkspaceID,
			recoveryGeneration: cut.RecoveryGeneration,
			checkpointEventID:  cut.CheckpointEventID,
			chainIndex:         cut.ChainIndex,
			resultIndex:        cut.ResultIndex,
			observedAt:         observedAt,
		},
	)
}

func writeCheckpointCadenceRow(
	conn *sqlite.Conn,
	row checkpointCadenceRow,
) error {
	if !row.sessionID.Valid() ||
		!row.workspaceID.Valid() ||
		!domain.ValidUnsignedInteger(row.recoveryGeneration) ||
		!domain.ValidUnsignedInteger(row.chainIndex) ||
		!domain.ValidUnsignedInteger(row.resultIndex) ||
		row.chainIndex > row.resultIndex ||
		row.checkpointEventID != "" && !row.checkpointEventID.Valid() ||
		!row.observedAt.Valid() {
		return checkpointCadenceError("invalid baseline write", nil)
	}
	var checkpointEventID any
	if row.checkpointEventID.Valid() {
		checkpointEventID = string(row.checkpointEventID)
	}
	if err := execute(
		conn,
		`INSERT INTO checkpoint_cadence_state(
		    singleton, session_id, workspace_id, recovery_generation,
		    checkpoint_event_id, baseline_chain_index,
		    baseline_result_index, observed_at
		) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
		ON CONFLICT(singleton) DO UPDATE SET
		    session_id = excluded.session_id,
		    workspace_id = excluded.workspace_id,
		    recovery_generation = excluded.recovery_generation,
		    checkpoint_event_id = excluded.checkpoint_event_id,
		    baseline_chain_index = excluded.baseline_chain_index,
		    baseline_result_index = excluded.baseline_result_index,
		    observed_at = excluded.observed_at;`,
		string(row.sessionID),
		string(row.workspaceID),
		row.recoveryGeneration,
		checkpointEventID,
		row.chainIndex,
		row.resultIndex,
		string(row.observedAt),
	); err != nil {
		return checkpointCadenceError("write durable baseline", err)
	}
	return nil
}

func checkpointCadenceError(message string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrCheckpointCadenceIntegrity, message)
	}
	return fmt.Errorf(
		"%w: %s: %v",
		ErrCheckpointCadenceIntegrity,
		message,
		cause,
	)
}
