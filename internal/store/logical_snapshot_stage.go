package store

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var (
	ErrInvalidLogicalSnapshotStage = errors.New(
		"store: invalid logical snapshot stage",
	)
	ErrLogicalSnapshotStageFinalized = errors.New(
		"store: logical snapshot stage is finalized",
	)
)

// LogicalSnapshotStage owns a new file-backed SQLite database used to rebuild
// one logical snapshot. Every command commits independently, bounding rollback
// journal and Go memory use; no staged state is authoritative until Verify
// succeeds and a later replacement transaction installs it.
type LogicalSnapshotStage struct {
	mu       sync.Mutex
	store    *Store
	path     string
	closed   bool
	verified bool
	closeErr error
}

// OpenLogicalSnapshotStage exclusively creates a quarantine database. An
// existing path is never reused because its contents may belong to an earlier
// failed or attacker-influenced import.
func OpenLogicalSnapshotStage(
	ctx context.Context,
	path string,
) (*LogicalSnapshotStage, error) {
	database, err := Open(ctx, Options{
		Path:       path,
		RequireNew: true,
	})
	if err != nil {
		return nil, err
	}
	return &LogicalSnapshotStage{
		store: database,
		path:  database.Path(),
	}, nil
}

// Path returns the cleaned quarantine database path.
func (stage *LogicalSnapshotStage) Path() string {
	if stage == nil {
		return ""
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	return stage.path
}

// Initialize installs the independently verified generation-zero boundary.
func (stage *LogicalSnapshotStage) Initialize(
	ctx context.Context,
	initial InitialState,
) (ApplyHeads, error) {
	if stage == nil {
		return ApplyHeads{}, ErrInvalidLogicalSnapshotStage
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if err := stage.mutable(); err != nil {
		return ApplyHeads{}, err
	}
	return stage.store.Initialize(ctx, initial)
}

// InstallSuccessor installs one independently verified deterministic recovery
// transform at the exact predecessor cut.
func (stage *LogicalSnapshotStage) InstallSuccessor(
	ctx context.Context,
	successor SuccessorState,
) (ApplyHeads, error) {
	if stage == nil {
		return ApplyHeads{}, ErrInvalidLogicalSnapshotStage
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if err := stage.mutable(); err != nil {
		return ApplyHeads{}, err
	}
	return stage.store.InstallSuccessor(ctx, successor)
}

// ImportCommand writes one independently verified command without creating
// foreign event/Raft provenance or advancing a Raft watermark.
func (stage *LogicalSnapshotStage) ImportCommand(
	ctx context.Context,
	command VerifiedCommandImport,
) (ApplyHeads, error) {
	if stage == nil {
		return ApplyHeads{}, ErrInvalidLogicalSnapshotStage
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if err := stage.mutable(); err != nil {
		return ApplyHeads{}, err
	}
	return stage.store.importLogicalSnapshotCommand(ctx, command)
}

// View returns the current staged cut. It is intended for bounded reducer
// reconstruction at generation boundaries and remains non-authoritative.
func (stage *LogicalSnapshotStage) View(
	ctx context.Context,
) (StateView, error) {
	if stage == nil {
		return StateView{}, ErrInvalidLogicalSnapshotStage
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if err := stage.open(); err != nil {
		return StateView{}, err
	}
	return stage.store.View(ctx)
}

// Verify replays every retained generation, verifies the terminal checkpoint
// and signer authority, and compares the exact signed root cut. Success
// permanently freezes the stage.
func (stage *LogicalSnapshotStage) Verify(
	ctx context.Context,
	expected LogicalSnapshotCut,
) error {
	if stage == nil {
		return ErrInvalidLogicalSnapshotStage
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if err := stage.mutable(); err != nil {
		return err
	}
	if err := stage.store.verifyLogicalSnapshotStage(ctx, expected); err != nil {
		return err
	}
	stage.verified = true
	return nil
}

// Close closes the quarantine database without deleting it. The installer or
// caller owns eventual replacement or secure cleanup of the closed file.
func (stage *LogicalSnapshotStage) Close() error {
	if stage == nil {
		return ErrInvalidLogicalSnapshotStage
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed {
		return stage.closeErr
	}
	stage.closed = true
	stage.closeErr = stage.store.Close()
	return stage.closeErr
}

func (stage *LogicalSnapshotStage) open() error {
	if stage == nil || stage.store == nil || stage.path == "" || stage.closed {
		return ErrInvalidLogicalSnapshotStage
	}
	return nil
}

func (stage *LogicalSnapshotStage) mutable() error {
	if err := stage.open(); err != nil {
		return err
	}
	if stage.verified {
		return ErrLogicalSnapshotStageFinalized
	}
	return nil
}

func (store *Store) importLogicalSnapshotCommand(
	ctx context.Context,
	command VerifiedCommandImport,
) (ApplyHeads, error) {
	if ctx == nil {
		return ApplyHeads{}, fmt.Errorf(
			"%w: nil context",
			ErrInvalidLogicalSnapshotStage,
		)
	}
	if err := ctx.Err(); err != nil {
		return ApplyHeads{}, err
	}
	if len(command.EncodedResult) == 0 {
		return ApplyHeads{}, fmt.Errorf(
			"%w: command result is empty",
			ErrInvalidLogicalSnapshotStage,
		)
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()

	var heads ApplyHeads
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end, err := sqlitex.ImmediateTransaction(conn)
		if err != nil {
			return err
		}
		defer end(&err)

		prior, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf(
				"%w: generation is not initialized",
				ErrInvalidLogicalSnapshotStage,
			)
		}
		if prior.currentTerm != 0 || prior.lastAppliedLogIndex != 0 {
			return fmt.Errorf(
				"%w: staged state carries a Raft watermark",
				ErrInvalidLogicalSnapshotStage,
			)
		}
		if err := requireLogicalSnapshotStageEvidenceEmpty(conn); err != nil {
			return err
		}
		workspaceID, err := activeWorkspaceID(conn, prior)
		if err != nil {
			return logicalSnapshotStageError(
				"read active workspace",
				err,
			)
		}
		heads, err = store.importVerifiedCommand(
			conn,
			prior,
			workspaceID,
			command,
		)
		if err != nil {
			return fmt.Errorf(
				"%w: import command: %w",
				ErrInvalidLogicalSnapshotStage,
				err,
			)
		}
		if err := writeImportedConsensusHeads(conn, prior, heads); err != nil {
			return err
		}
		return store.reachApplyStage(applyAfterConsensus)
	})
	if err != nil {
		return ApplyHeads{}, err
	}
	store.advanceAdmissionRevision()
	return heads, nil
}

func (store *Store) verifyLogicalSnapshotStage(
	ctx context.Context,
	expected LogicalSnapshotCut,
) error {
	if ctx == nil {
		return fmt.Errorf(
			"%w: nil context",
			ErrInvalidLogicalSnapshotStage,
		)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateLogicalSnapshotCut(expected); err != nil {
		return err
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	return store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end := sqlitex.Transaction(conn)
		defer end(&err)

		if err := checkIntegrity(conn); err != nil {
			return err
		}
		state, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return logicalSnapshotStageError("active generation is missing", nil)
		}
		workspaceID, err := activeWorkspaceID(conn, state)
		if err != nil {
			return logicalSnapshotStageError(
				"read active workspace",
				err,
			)
		}
		if state.sessionID != expected.SessionID ||
			workspaceID != expected.WorkspaceID ||
			state.recoveryGeneration != expected.RecoveryGeneration ||
			state.chainIndex != expected.ChainIndex ||
			state.chainHash != expected.ChainHash ||
			state.resultIndex != expected.ResultIndex ||
			state.resultHash != expected.ResultHash ||
			state.projectionAccumulator !=
				expected.ProjectionAccumulator ||
			state.digestVersion != expected.DigestVersion ||
			state.projectionSchemaVersion !=
				expected.ProjectionSchemaVersion {
			return logicalSnapshotStageError(
				"durable cut differs from signed root",
				nil,
			)
		}
		if state.currentTerm != 0 || state.lastAppliedLogIndex != 0 {
			return logicalSnapshotStageError(
				"staged state carries a Raft watermark",
				nil,
			)
		}
		if err := requireLogicalSnapshotStageEvidenceEmpty(conn); err != nil {
			return err
		}
		if err := verifyCompleteLogicalSnapshotHistory(conn, state); err != nil {
			return logicalSnapshotStageError(
				"verify complete commitment history",
				err,
			)
		}

		digest, err := projectionStateDigest(conn, chain.Versions{
			Digest:           state.digestVersion,
			ProjectionSchema: state.projectionSchemaVersion,
		})
		if err != nil {
			return err
		}
		if digest != expected.ProjectionStateDigest {
			return logicalSnapshotStageError(
				"projection-state digest differs from signed root",
				nil,
			)
		}

		checkpoint, err := verifyLogicalSnapshotCheckpoint(
			conn,
			state,
			expected.CheckpointEventID,
			false,
		)
		if err != nil {
			return logicalSnapshotStageError(
				"verify terminal checkpoint",
				err,
			)
		}
		if checkpoint.AuthorityVoterSetVersion !=
			expected.AuthorityVersion {
			return logicalSnapshotStageError(
				"checkpoint authority differs from signed root",
				nil,
			)
		}
		if err := verifyLogicalSnapshotCheckpointKeepsAuthority(
			conn,
			checkpoint.CheckpointEventID,
		); err != nil {
			return logicalSnapshotStageError(
				"terminal checkpoint changes authority",
				err,
			)
		}
		authority, err := readStatusCredentialAuthority(
			conn,
			state.sessionID,
		)
		if err != nil {
			return err
		}
		if authority.VoterSetVersion != expected.AuthorityVersion {
			return logicalSnapshotStageError(
				"terminal authority differs from signed root",
				nil,
			)
		}
		if _, err := requireLogicalSnapshotSigner(
			conn,
			authority,
			expected.SignerDeviceID,
		); err != nil {
			return logicalSnapshotStageError(
				"snapshot signer authorization",
				err,
			)
		}
		checkpointSigner, err := requireLogicalSnapshotSigner(
			conn,
			authority,
			checkpoint.SignerDeviceID,
		)
		if err != nil {
			return logicalSnapshotStageError(
				"checkpoint signer authorization",
				err,
			)
		}
		if err := codecommcrypto.VerifyEd25519(
			checkpointSigner.IdentityPublicKey,
			codec.SignatureCheckpoint,
			checkpoint.CheckpointJSON,
			checkpoint.AuthoritySignature[:],
		); err != nil {
			return logicalSnapshotStageError(
				"checkpoint signature",
				err,
			)
		}
		return nil
	})
}

func validateLogicalSnapshotCut(cut LogicalSnapshotCut) error {
	if !cut.SessionID.Valid() ||
		!cut.WorkspaceID.Valid() ||
		!cut.CheckpointEventID.Valid() ||
		!cut.SignerDeviceID.Valid() ||
		cut.ChainIndex < 1 ||
		cut.ChainIndex > cut.ResultIndex ||
		cut.AuthorityVersion < 1 ||
		cut.DigestVersion != logicalsnapshot.SupportedDigestVersion ||
		cut.ProjectionSchemaVersion !=
			logicalsnapshot.SupportedProjectionSchemaVersion ||
		cut.RecordCount < 1 {
		return logicalSnapshotStageError("invalid signed cut", nil)
	}
	for _, value := range []uint64{
		cut.RecoveryGeneration,
		cut.ChainIndex,
		cut.ResultIndex,
		cut.AuthorityVersion,
		cut.DigestVersion,
		cut.ProjectionSchemaVersion,
		cut.RecordCount,
	} {
		if !domain.ValidUnsignedInteger(value) {
			return logicalSnapshotStageError(
				"signed cut exceeds exact integer range",
				nil,
			)
		}
	}
	return nil
}

func requireLogicalSnapshotStageEvidenceEmpty(conn *sqlite.Conn) error {
	var count int64
	if err := queryOne(
		conn,
		`SELECT
		    (SELECT count(*) FROM event_provenance) +
		    (SELECT count(*) FROM raft_command_applications) +
		    (SELECT count(*) FROM raft_snapshot_installs) +
		    (SELECT count(*) FROM replication_attestations) +
		    (SELECT count(*) FROM settled_nonvoter_state);`,
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if count != 0 {
		return logicalSnapshotStageError(
			"quarantine contains foreign provenance or attestations",
			nil,
		)
	}
	return nil
}

func verifyCompleteLogicalSnapshotHistory(
	conn *sqlite.Conn,
	active consensusState,
) error {
	var (
		expectedGeneration uint64
		previous           consensusState
		havePrevious       bool
		rowErr             error
	)
	err := query(
		conn,
		`SELECT recovery_generation, session_id,
		        predecessor_chain_index, predecessor_chain_hash,
		        predecessor_result_index, predecessor_result_hash,
		        predecessor_projection_accumulator
		   FROM genesis_records
		  ORDER BY recovery_generation;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			generation := stmt.ColumnInt64(0)
			sessionID := domain.UUIDv7(stmt.ColumnText(1))
			if generation < 0 ||
				uint64(generation) != expectedGeneration ||
				!sessionID.Valid() {
				rowErr = errors.New("genesis lineage is not dense")
				return
			}
			if havePrevious {
				if stmt.ColumnType(2) == sqlite.TypeNull ||
					stmt.ColumnType(3) == sqlite.TypeNull ||
					stmt.ColumnType(4) == sqlite.TypeNull ||
					stmt.ColumnType(5) == sqlite.TypeNull ||
					stmt.ColumnType(6) == sqlite.TypeNull ||
					stmt.ColumnInt64(2) < 0 ||
					stmt.ColumnInt64(4) < 0 {
					rowErr = errors.New(
						"successor predecessor cut is incomplete",
					)
					return
				}
				previous.chainIndex = uint64(stmt.ColumnInt64(2))
				if rowErr = copyDigestColumn(
					&previous.chainHash,
					stmt,
					3,
				); rowErr != nil {
					return
				}
				previous.resultIndex = uint64(stmt.ColumnInt64(4))
				if rowErr = copyDigestColumn(
					&previous.resultHash,
					stmt,
					5,
				); rowErr != nil {
					return
				}
				if rowErr = copyDigestColumn(
					&previous.projectionAccumulator,
					stmt,
					6,
				); rowErr != nil {
					return
				}
				if rowErr = verifyHistoricalGenerationCommitments(
					conn,
					previous,
				); rowErr != nil {
					return
				}
			} else if stmt.ColumnType(2) != sqlite.TypeNull ||
				stmt.ColumnType(3) != sqlite.TypeNull ||
				stmt.ColumnType(4) != sqlite.TypeNull ||
				stmt.ColumnType(5) != sqlite.TypeNull ||
				stmt.ColumnType(6) != sqlite.TypeNull {
				rowErr = errors.New(
					"initial genesis carries a predecessor cut",
				)
				return
			}
			previous = consensusState{
				sessionID:               sessionID,
				recoveryGeneration:      uint64(generation),
				digestVersion:           active.digestVersion,
				projectionSchemaVersion: active.projectionSchemaVersion,
			}
			havePrevious = true
			expectedGeneration++
		},
	)
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	if !havePrevious ||
		expectedGeneration != active.recoveryGeneration+1 ||
		previous.sessionID != active.sessionID ||
		previous.recoveryGeneration != active.recoveryGeneration {
		return errors.New("genesis lineage does not reach active generation")
	}
	if err := verifyCommitmentHistory(conn, active); err != nil {
		return err
	}
	var (
		resultCount    int64
		maxResultIndex int64
		eventCount     int64
		maxChainIndex  int64
	)
	if err := queryOne(
		conn,
		`SELECT count(*), coalesce(max(result_index), 0)
		   FROM command_results;`,
		func(stmt *sqlite.Stmt) {
			resultCount = stmt.ColumnInt64(0)
			maxResultIndex = stmt.ColumnInt64(1)
		},
	); err != nil {
		return err
	}
	if err := queryOne(
		conn,
		`SELECT count(*), coalesce(max(chain_index), 0)
		   FROM events
		   JOIN command_results USING (event_id);`,
		func(stmt *sqlite.Stmt) {
			eventCount = stmt.ColumnInt64(0)
			maxChainIndex = stmt.ColumnInt64(1)
		},
	); err != nil {
		return err
	}
	if resultCount < 0 ||
		maxResultIndex < 0 ||
		eventCount < 0 ||
		maxChainIndex < 0 ||
		uint64(resultCount) != active.resultIndex ||
		uint64(maxResultIndex) != active.resultIndex ||
		uint64(eventCount) != active.chainIndex ||
		uint64(maxChainIndex) != active.chainIndex {
		return errors.New(
			"retained history contains a gap or an out-of-lineage row",
		)
	}
	return nil
}

func logicalSnapshotStageError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrInvalidLogicalSnapshotStage, detail)
	}
	return fmt.Errorf(
		"%w: %s: %w",
		ErrInvalidLogicalSnapshotStage,
		detail,
		cause,
	)
}
