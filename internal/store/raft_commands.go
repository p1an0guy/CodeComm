package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrRaftCommandBinding = errors.New(
	"store: Raft command binding integrity failure",
)

// VerifyRaftCommand proves that one retained/replayed Raft command occupies
// the same term and log position that was atomically applied to SQLite.
func (store *Store) VerifyRaftCommand(
	ctx context.Context,
	term uint64,
	logIndex uint64,
	signed event.SignedEvent,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if term < 1 ||
		logIndex < 1 ||
		!signed.Proposal().EventID.Valid() ||
		len(signed.CanonicalBytes()) == 0 {
		return fmt.Errorf("%w: invalid command identity", ErrInvalidOptions)
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	return store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)

		end := sqlitex.Transaction(conn)
		defer end(&err)

		state, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf(
				"%w: active generation is missing",
				ErrRaftCommandBinding,
			)
		}
		digest := proposalDigest(signed)
		var (
			count   int
			matches bool
		)
		err = queryArgs(
			conn,
			`SELECT a.term = ?3
			        AND a.event_id = ?4
			        AND a.proposal_digest = ?5
			        AND r.proposal_digest = ?5
			   FROM raft_command_applications AS a
			   JOIN command_results AS r ON r.event_id = a.event_id
			  WHERE a.recovery_generation = ?1
			    AND a.log_index = ?2;`,
			[]any{
				state.recoveryGeneration,
				logIndex,
				term,
				string(signed.Proposal().EventID),
				digest[:],
			},
			func(stmt *sqlite.Stmt) {
				count++
				matches = stmt.ColumnBool(0)
			},
		)
		if err != nil {
			return err
		}
		if count != 1 || !matches {
			return fmt.Errorf(
				"%w: term=%d log_index=%d event_id=%s",
				ErrRaftCommandBinding,
				term,
				logIndex,
				signed.Proposal().EventID,
			)
		}
		stored, found, err := readStoredCommandResult(
			conn,
			signed.Proposal().EventID,
		)
		if err != nil {
			return err
		}
		if !found ||
			stored.proposalDigest != digest ||
			!bytes.Equal(stored.proposalJSON, signed.CanonicalBytes()) {
			return fmt.Errorf(
				"%w: term=%d log_index=%d event_id=%s",
				ErrRaftCommandBinding,
				term,
				logIndex,
				signed.Proposal().EventID,
			)
		}
		return nil
	})
}

func verifyRaftCommandLedger(
	conn *sqlite.Conn,
	state consensusState,
) error {
	return verifyRaftCommandLedgerThrough(conn, state, state.resultIndex)
}

func verifyRaftCommandLedgerThrough(
	conn *sqlite.Conn,
	state consensusState,
	resultCut uint64,
) error {
	if resultCut > state.resultIndex {
		return raftCommandLedgerError(
			"result cut follows the active result head",
			nil,
		)
	}
	baseline, hasBaseline, err := validateRaftSnapshotInstallBinding(
		conn,
		state,
	)
	if err != nil {
		return raftCommandLedgerError(
			"verify installed snapshot baseline",
			err,
		)
	}
	baselineResultIndex := uint64(0)
	baselineLogIndex := uint64(0)
	baselineTerm := uint64(0)
	if hasBaseline {
		baselineResultIndex = baseline.heads.ResultIndex
		if resultCut < baselineResultIndex {
			return raftCommandLedgerError(
				"result cut precedes the installed snapshot baseline",
				nil,
			)
		}
		if baseline.hasBaselineCommand {
			baselineLogIndex = baseline.baselineCommandLogIndex
			baselineTerm = baseline.baselineCommandTerm
		}
	}
	var (
		count    int64
		maxIndex int64
		maxTerm  int64
		minTerm  int64
		missing  int64
	)
	if err := queryOneArgs(
		conn,
		`SELECT count(*), coalesce(max(log_index), 0),
		        coalesce(min(term), 0)
		   FROM raft_command_applications
		  WHERE recovery_generation = ?1;`,
		[]any{state.recoveryGeneration},
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
			maxIndex = stmt.ColumnInt64(1)
			minTerm = stmt.ColumnInt64(2)
		},
	); err != nil {
		return err
	}
	switch {
	case count == 0 && hasBaseline && baseline.hasBaselineCommand:
		if state.lastAppliedLogIndex != baselineLogIndex ||
			state.currentTerm != baselineTerm {
			return raftCommandLedgerError(
				"installed baseline differs from applied watermark",
				nil,
			)
		}
	case count == 0:
		if state.lastAppliedLogIndex != 0 || state.currentTerm != 0 {
			return raftCommandLedgerError(
				"unbound state has a Raft command watermark",
				nil,
			)
		}
	case count > 0:
		if maxIndex != int64(state.lastAppliedLogIndex) {
			return raftCommandLedgerError(
				"latest command binding differs from applied watermark",
				nil,
			)
		}
		if hasBaseline &&
			(uint64(maxIndex) <= baseline.snapshotIndex ||
				minTerm < int64(baselineTerm)) {
			return raftCommandLedgerError(
				"post-snapshot command binding precedes its baseline",
				nil,
			)
		}
		if err := queryOneArgs(
			conn,
			`SELECT term
			   FROM raft_command_applications
			  WHERE recovery_generation = ?1 AND log_index = ?2;`,
			[]any{state.recoveryGeneration, state.lastAppliedLogIndex},
			func(stmt *sqlite.Stmt) {
				maxTerm = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if maxTerm < 1 || uint64(maxTerm) != state.currentTerm {
			return raftCommandLedgerError(
				"latest command term differs from applied watermark",
				nil,
			)
		}
	default:
		return raftCommandLedgerError(
			"invalid command binding count",
			nil,
		)
	}
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
			   FROM command_results AS r
			  WHERE r.recovery_generation = ?1
			    AND r.result_index > ?2
			    AND r.result_index <= ?3
			    AND NOT EXISTS (
		        SELECT 1
		          FROM raft_command_applications AS a
		         WHERE a.recovery_generation = ?1
		           AND a.event_id = r.event_id
		           AND a.proposal_digest = r.proposal_digest
		  );`,
		[]any{
			state.recoveryGeneration,
			baselineResultIndex,
			resultCut,
		},
		func(stmt *sqlite.Stmt) {
			missing = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if missing != 0 {
		return raftCommandLedgerError(
			"command result lacks an exact first-seen Raft binding",
			nil,
		)
	}
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
			   FROM raft_command_applications AS a
			   LEFT JOIN command_results AS r
		     ON r.event_id = a.event_id
		    AND r.proposal_digest = a.proposal_digest
			  WHERE a.recovery_generation = ?1
			    AND (r.event_id IS NULL OR r.result_index > ?2);`,
		[]any{state.recoveryGeneration, resultCut},
		func(stmt *sqlite.Stmt) {
			missing = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if missing != 0 {
		return raftCommandLedgerError(
			"Raft binding lacks an exact command result",
			nil,
		)
	}
	if hasBaseline && count != 0 {
		if err := queryOneArgs(
			conn,
			`SELECT count(*)
			   FROM raft_command_applications
			  WHERE recovery_generation = ?1
			    AND log_index <= ?2;`,
			[]any{state.recoveryGeneration, baseline.snapshotIndex},
			func(stmt *sqlite.Stmt) {
				missing = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if missing != 0 {
			return raftCommandLedgerError(
				"retained command binding is covered by the snapshot",
				nil,
			)
		}
	}
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM (
		        SELECT term,
		               lag(term) OVER (ORDER BY log_index) AS prior_term
		          FROM raft_command_applications
		         WHERE recovery_generation = ?1
		   )
		  WHERE prior_term IS NOT NULL AND term < prior_term;`,
		[]any{state.recoveryGeneration},
		func(stmt *sqlite.Stmt) {
			missing = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if missing != 0 {
		return raftCommandLedgerError(
			"Raft command terms regress",
			nil,
		)
	}
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM (
		        SELECT first_log_index,
		               lag(first_log_index) OVER (
		                   ORDER BY result_index
		               ) AS prior_first_log_index
		          FROM (
		               SELECT r.result_index,
		                      min(a.log_index) AS first_log_index
		                 FROM command_results AS r
		                 JOIN raft_command_applications AS a
		                   ON a.recovery_generation = r.recovery_generation
		                  AND a.event_id = r.event_id
		                  AND a.proposal_digest = r.proposal_digest
			                 WHERE r.recovery_generation = ?1
			                   AND r.result_index > ?2
			                   AND r.result_index <= ?3
			                GROUP BY r.event_id, r.result_index
		          )
		   )
		  WHERE prior_first_log_index IS NOT NULL
		    AND first_log_index <= prior_first_log_index;`,
		[]any{
			state.recoveryGeneration,
			baselineResultIndex,
			resultCut,
		},
		func(stmt *sqlite.Stmt) {
			missing = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if missing != 0 {
		return raftCommandLedgerError(
			"first-seen Raft bindings reorder command results",
			nil,
		)
	}
	return nil
}

func raftCommandLedgerError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrRaftCommandBinding, detail)
	}
	return fmt.Errorf("%w: %s: %w", ErrRaftCommandBinding, detail, cause)
}
