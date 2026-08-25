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
	"github.com/ijonahch/codecomm/internal/reducer"
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
	ErrLogicalSnapshotStageConsumed = errors.New(
		"store: logical snapshot stage is consumed",
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
	consumed bool
	root     logicalsnapshot.Root
	artifact logicalsnapshot.VerifiedExpandedArtifact
	hasRoot  bool
	closeErr error

	reducerState       reducer.State
	projections        *ProjectionScratch
	heads              ApplyHeads
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	generation         uint64
	derivedViewsDigest Digest
	reducerReady       bool
	hasDerivedDigest   bool
	failed             error
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
	heads, err := stage.store.Initialize(ctx, initial)
	if err != nil {
		return ApplyHeads{}, err
	}
	if err := stage.installReducerBoundary(
		initial.SessionID,
		initial.WorkspaceID,
		0,
		initial.GenesisJSON,
		heads,
		initial.Projections,
	); err != nil {
		stage.failed = err
		return ApplyHeads{}, err
	}
	return heads, nil
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
	heads, err := stage.store.InstallSuccessor(ctx, successor)
	if err != nil {
		return ApplyHeads{}, err
	}
	if err := stage.installReducerBoundary(
		successor.SessionID,
		successor.WorkspaceID,
		successor.RecoveryGeneration,
		successor.GenesisJSON,
		heads,
		successor.Projections,
	); err != nil {
		stage.failed = err
		return ApplyHeads{}, err
	}
	return heads, nil
}

// importCommand is the persistence primitive exercised by store tests. The
// production snapshot path uses ReplayCommand, which derives this input by
// re-running the reducer inside the store package.
func (stage *LogicalSnapshotStage) importCommand(
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

// StreamProjectionRows visits the staged covered projection rows in canonical
// table/key order without materializing another complete state copy.
func (stage *LogicalSnapshotStage) StreamProjectionRows(
	ctx context.Context,
	visit func(chain.LogicalRow) error,
) error {
	if stage == nil || ctx == nil || visit == nil {
		return ErrInvalidLogicalSnapshotStage
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if err := stage.open(); err != nil {
		return err
	}
	stage.store.applyMu.Lock()
	defer stage.store.applyMu.Unlock()
	return stage.store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end := sqlitex.Transaction(conn)
		defer end(&err)
		return streamProjectionLogicalRows(conn, visit)
	})
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

// VerifyArtifact binds replayed state to one structurally verified expanded
// artifact and its complete authority-signed root. Only this stronger
// verification makes a stage eligible for installation.
func (stage *LogicalSnapshotStage) VerifyArtifact(
	ctx context.Context,
	root logicalsnapshot.Root,
	artifact logicalsnapshot.VerifiedExpandedArtifact,
) error {
	if stage == nil {
		return ErrInvalidLogicalSnapshotStage
	}
	if !artifact.MatchesRoot(root) {
		return logicalSnapshotStageError(
			"expanded artifact proof differs from signed root",
			nil,
		)
	}
	expected, err := logicalSnapshotCutFromRoot(root)
	if err != nil {
		return err
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if err := stage.open(); err != nil {
		return err
	}
	if stage.hasRoot {
		return ErrLogicalSnapshotStageFinalized
	}
	if err := stage.store.verifyLogicalSnapshotRoot(
		ctx,
		root,
		expected,
	); err != nil {
		return err
	}
	derivedDigest, err := stage.store.logicalSnapshotDerivedViewsDigest(ctx)
	if err != nil {
		return logicalSnapshotStageError(
			"digest rebuilt local views",
			err,
		)
	}
	stage.root = root
	stage.artifact = artifact
	stage.derivedViewsDigest = derivedDigest
	stage.hasRoot = true
	stage.hasDerivedDigest = true
	stage.verified = true
	return nil
}

func (store *Store) logicalSnapshotDerivedViewsDigest(
	ctx context.Context,
) (Digest, error) {
	if store == nil || ctx == nil {
		return Digest{}, ErrInvalidLogicalSnapshotStage
	}
	if err := ctx.Err(); err != nil {
		return Digest{}, err
	}
	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	var digest Digest
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end := sqlitex.Transaction(conn)
		defer end(&err)
		digest, err = logicalSnapshotDerivedViewsDigest(conn)
		return err
	})
	return digest, err
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
	if stage.consumed {
		return ErrLogicalSnapshotStageConsumed
	}
	return nil
}

func (stage *LogicalSnapshotStage) mutable() error {
	if err := stage.open(); err != nil {
		return err
	}
	if stage.failed != nil {
		return fmt.Errorf(
			"%w: stage previously failed: %v",
			ErrInvalidLogicalSnapshotStage,
			stage.failed,
		)
	}
	if stage.verified {
		return ErrLogicalSnapshotStageFinalized
	}
	return nil
}

func (stage *LogicalSnapshotStage) installReducerBoundary(
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	generation uint64,
	genesisJSON []byte,
	heads ApplyHeads,
	writes ProjectionWrites,
) error {
	state, err := reducerStateFromProjectionWrites(
		sessionID,
		workspaceID,
		generation,
		genesisJSON,
		heads,
		writes,
	)
	if err != nil {
		return logicalSnapshotStageError(
			"construct reducer boundary state",
			err,
		)
	}
	projections, err := NewProjectionScratch(
		nil,
		chain.Versions{
			Digest:           heads.DigestVersion,
			ProjectionSchema: heads.ProjectionSchemaVersion,
		},
	)
	if err != nil {
		return logicalSnapshotStageError(
			"construct reducer projection scratch",
			err,
		)
	}
	if _, err := projections.Apply(writes); err != nil {
		return logicalSnapshotStageError(
			"populate reducer projection scratch",
			err,
		)
	}
	stage.reducerState = state
	stage.projections = projections
	stage.heads = heads
	stage.sessionID = sessionID
	stage.workspaceID = workspaceID
	stage.generation = generation
	stage.reducerReady = true
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
		return verifyLogicalSnapshotStageConnection(
			conn,
			expected,
			nil,
			true,
		)
	})
}

func (store *Store) verifyLogicalSnapshotRoot(
	ctx context.Context,
	root logicalsnapshot.Root,
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
	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	return store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end := sqlitex.Transaction(conn)
		defer end(&err)
		return verifyLogicalSnapshotStageConnection(
			conn,
			expected,
			&root,
			true,
		)
	})
}

func verifyLogicalSnapshotStageConnection(
	conn *sqlite.Conn,
	expected LogicalSnapshotCut,
	root *logicalsnapshot.Root,
	requireEmptyEvidence bool,
) error {
	if err := validateLogicalSnapshotCut(expected); err != nil {
		return err
	}
	if root != nil {
		rootCut, err := logicalSnapshotCutFromRoot(*root)
		if err != nil {
			return err
		}
		if rootCut != expected {
			return logicalSnapshotStageError(
				"signed root differs from expected cut",
				nil,
			)
		}
	}
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
	if requireEmptyEvidence {
		if err := requireLogicalSnapshotStageEvidenceEmpty(conn); err != nil {
			return err
		}
	}
	if err := verifyCompleteLogicalSnapshotHistory(conn, state); err != nil {
		return logicalSnapshotStageError(
			"verify complete commitment history",
			err,
		)
	}
	if err := verifyLogicalSnapshotCheckpointRows(conn); err != nil {
		return logicalSnapshotStageError(
			"verify complete checkpoint rows",
			err,
		)
	}
	if err := verifyDerivedViews(conn); err != nil {
		return logicalSnapshotStageError(
			"verify rebuilt derived views",
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
	rootSigner, err := requireLogicalSnapshotSigner(
		conn,
		authority,
		expected.SignerDeviceID,
	)
	if err != nil {
		return logicalSnapshotStageError(
			"snapshot signer authorization",
			err,
		)
	}
	if root != nil {
		if err := logicalsnapshot.VerifyRoot(
			*root,
			rootSigner.IdentityPublicKey,
		); err != nil {
			return logicalSnapshotStageError(
				"snapshot root signature",
				err,
			)
		}
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
}

func verifyLogicalSnapshotCheckpointRows(conn *sqlite.Conn) error {
	var (
		acceptedCount int64
		storedCount   int64
	)
	if err := queryOne(
		conn,
		`SELECT count(*) FROM command_results
		  WHERE kind = 'consensus.checkpoint'
		    AND outcome_status = 'accepted';`,
		func(stmt *sqlite.Stmt) {
			acceptedCount = stmt.ColumnInt64(0)
		},
	); err != nil {
		return appliedCheckpointIntegrity(
			"count accepted checkpoint results",
			err,
		)
	}
	if err := queryOne(
		conn,
		"SELECT count(*) FROM chain_checkpoints;",
		func(stmt *sqlite.Stmt) {
			storedCount = stmt.ColumnInt64(0)
		},
	); err != nil {
		return appliedCheckpointIntegrity(
			"count stored checkpoint rows",
			err,
		)
	}
	if acceptedCount < 0 || storedCount != acceptedCount {
		return appliedCheckpointIntegrity(
			"checkpoint rows do not exactly cover accepted checkpoint results",
			nil,
		)
	}
	var rowErr error
	if err := query(
		conn,
		`SELECT checkpoint_event_id FROM chain_checkpoints
		  ORDER BY recovery_generation, covered_result_index,
		           checkpoint_event_id;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			eventID := domain.UUIDv7(stmt.ColumnText(0))
			if !eventID.Valid() {
				rowErr = errors.New("invalid checkpoint row identity")
				return
			}
			record, found, err := readCheckpointRecord(conn, eventID)
			if err != nil {
				rowErr = err
				return
			}
			if !found {
				rowErr = errors.New(
					"checkpoint row disappeared during verification",
				)
				return
			}
			if err := record.Validate(); err != nil {
				rowErr = err
				return
			}
			rowErr = verifyCheckpointResultBinding(conn, record)
		},
	); err != nil {
		return appliedCheckpointIntegrity(
			"enumerate checkpoint rows",
			err,
		)
	}
	if rowErr != nil {
		return appliedCheckpointIntegrity(
			"checkpoint row differs from accepted result",
			rowErr,
		)
	}
	return nil
}

func logicalSnapshotCutFromRoot(
	root logicalsnapshot.Root,
) (LogicalSnapshotCut, error) {
	if len(root.CanonicalBytes()) == 0 {
		return LogicalSnapshotCut{}, logicalSnapshotStageError(
			"invalid signed root",
			nil,
		)
	}
	input := root.Unsigned().Input()
	cut := LogicalSnapshotCut{
		SessionID:               input.SessionID,
		WorkspaceID:             input.WorkspaceID,
		RecoveryGeneration:      input.RecoveryGeneration,
		CheckpointEventID:       input.CheckpointEventID,
		ChainIndex:              input.ChainIndex,
		ChainHash:               Digest(input.ChainHash),
		ResultIndex:             input.ResultIndex,
		ResultHash:              Digest(input.ResultHash),
		ProjectionAccumulator:   Digest(input.ProjectionAccumulator),
		ProjectionStateDigest:   Digest(input.ProjectionStateDigest),
		AuthorityVersion:        input.AuthorityVersion,
		SignerDeviceID:          input.SignerDeviceID,
		DigestVersion:           input.DigestVersion,
		ProjectionSchemaVersion: input.ProjectionSchemaVersion,
		RecordCount:             input.RecordCount,
	}
	if err := validateLogicalSnapshotCut(cut); err != nil {
		return LogicalSnapshotCut{}, err
	}
	return cut, nil
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
