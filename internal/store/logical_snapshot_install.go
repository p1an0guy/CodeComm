package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrLogicalSnapshotInstall = errors.New(
	"store: logical snapshot installation failed",
)

// StandaloneLogicalSnapshotInstallResult names the atomically installed cut.
type StandaloneLogicalSnapshotInstallResult struct {
	Heads             ApplyHeads
	Cut               LogicalSnapshotCut
	AttestationID     string
	AdmissionRevision uint64
}

// StandaloneLogicalSnapshotInstallOptions binds local evidence written by one
// replacement transaction. Lease timers are reconstructed from replicated
// active leases at InstalledAt; quarantine timer rows are never trusted.
type StandaloneLogicalSnapshotInstallOptions struct {
	VerifiedAt     domain.Timestamp
	OriginBootID   domain.UUIDv7
	InstalledAt    domain.Timestamp
	MonotonicNowNS int64
}

type recoveryBoundaryAuditTimes struct {
	first domain.Timestamp
	last  domain.Timestamp
}

type storedLogicalSnapshotAttestation struct {
	id                         string
	sessionID                  domain.UUIDv7
	workspaceID                domain.UUIDv4
	recoveryGeneration         uint64
	signerDeviceID             domain.DeviceID
	authorityVersion           uint64
	fromResultIndex            uint64
	toResultIndex              uint64
	startResultHash            Digest
	endResultHash              Digest
	startChainIndex            uint64
	endChainIndex              uint64
	startChainHash             Digest
	endChainHash               Digest
	startProjectionAccumulator Digest
	endProjectionAccumulator   Digest
	startProjectionStateDigest Digest
	endProjectionStateDigest   Digest
	checkpointEventID          domain.UUIDv7
	envelopeJSON               []byte
	signature                  [ed25519.SignatureSize]byte
	verifiedAt                 domain.Timestamp
	root                       logicalsnapshot.Root
}

// InstallStandaloneLogicalSnapshot atomically replaces authoritative state
// from a signed-root-verified stage and enters settled-nonvoter mode. The
// source remains quarantined, is consumed exactly once, and supplies no Raft
// provenance or watermark.
func (store *Store) InstallStandaloneLogicalSnapshot(
	ctx context.Context,
	stage *LogicalSnapshotStage,
	options StandaloneLogicalSnapshotInstallOptions,
) (StandaloneLogicalSnapshotInstallResult, error) {
	if ctx == nil ||
		!options.VerifiedAt.Valid() ||
		!options.OriginBootID.Valid() ||
		!options.InstalledAt.Valid() ||
		options.MonotonicNowNS < 0 {
		return StandaloneLogicalSnapshotInstallResult{},
			logicalSnapshotInstallError("invalid context or verification time", nil)
	}
	installedAt, err := options.InstalledAt.Time()
	if err != nil {
		return StandaloneLogicalSnapshotInstallResult{},
			logicalSnapshotInstallError("invalid installation time", err)
	}
	if err := ctx.Err(); err != nil {
		return StandaloneLogicalSnapshotInstallResult{}, err
	}
	if store == nil || stage == nil {
		return StandaloneLogicalSnapshotInstallResult{},
			logicalSnapshotInstallError("nil store or stage", nil)
	}

	if err := lockLogicalSnapshotMutex(ctx, &stage.mu); err != nil {
		return StandaloneLogicalSnapshotInstallResult{}, err
	}
	defer stage.mu.Unlock()
	if err := stage.open(); err != nil {
		return StandaloneLogicalSnapshotInstallResult{}, err
	}
	if !stage.verified ||
		!stage.hasRoot ||
		!stage.hasDerivedDigest ||
		!stage.artifact.MatchesRoot(stage.root) {
		return StandaloneLogicalSnapshotInstallResult{},
			logicalSnapshotInstallError(
				"stage is not bound to a verified signed artifact",
				nil,
			)
	}
	if stage.store == store || stage.path == store.Path() {
		return StandaloneLogicalSnapshotInstallResult{},
			logicalSnapshotInstallError(
				"source stage and destination store are identical",
				nil,
			)
	}
	root := stage.root
	cut, err := logicalSnapshotCutFromRoot(root)
	if err != nil {
		return StandaloneLogicalSnapshotInstallResult{}, err
	}
	attestationID := logicalSnapshotAttestationID(root)
	if attestationID == "" {
		return StandaloneLogicalSnapshotInstallResult{},
			logicalSnapshotInstallError("signed root is invalid", nil)
	}

	if err := lockLogicalSnapshotMutex(ctx, &stage.store.applyMu); err != nil {
		return StandaloneLogicalSnapshotInstallResult{}, err
	}
	defer stage.store.applyMu.Unlock()
	if err := lockLogicalSnapshotMutex(ctx, &store.applyMu); err != nil {
		return StandaloneLogicalSnapshotInstallResult{}, err
	}
	defer store.applyMu.Unlock()

	err = stage.store.withConn(ctx, func(source *sqlite.Conn) (err error) {
		previousInterrupt := source.SetInterrupt(ctx.Done())
		defer source.SetInterrupt(previousInterrupt)
		endSource := sqlitex.Transaction(source)
		sourceEnded := false
		defer func() {
			if sourceEnded {
				return
			}
			rollback := errors.New("abort logical snapshot source read")
			endSource(&rollback)
		}()

		if err := verifyLogicalSnapshotStageConnection(
			source,
			cut,
			&root,
			true,
		); err != nil {
			return logicalSnapshotInstallError(
				"reverify frozen source",
				err,
			)
		}
		if err := requireLogicalSnapshotInstallSourceLocalState(source); err != nil {
			return err
		}
		derivedDigest, err := logicalSnapshotDerivedViewsDigest(source)
		if err != nil {
			return logicalSnapshotInstallError(
				"revalidate rebuilt local views",
				err,
			)
		}
		if derivedDigest != stage.derivedViewsDigest {
			return logicalSnapshotInstallError(
				"rebuilt local views changed after verification",
				nil,
			)
		}
		sourceState, found, err := readConsensusState(source)
		if err != nil {
			return err
		}
		if !found {
			return logicalSnapshotInstallError(
				"verified source has no active generation",
				nil,
			)
		}

		return store.withConn(ctx, func(destination *sqlite.Conn) (err error) {
			previousInterrupt := destination.SetInterrupt(ctx.Done())
			defer destination.SetInterrupt(previousInterrupt)
			end, err := sqlitex.ImmediateTransaction(destination)
			if err != nil {
				return err
			}
			defer end(&err)

			generationChanged, err :=
				verifyLogicalSnapshotInstallDestination(
					source,
					destination,
					sourceState,
					cut,
				)
			if err != nil {
				return err
			}
			preservedRecoveryTimes, err :=
				readRecoveryBoundaryAuditTimes(destination)
			if err != nil {
				return logicalSnapshotInstallError(
					"read recovery audit observation times",
					err,
				)
			}
			if generationChanged {
				if err := clearGenerationLocalState(destination); err != nil {
					return logicalSnapshotInstallError(
						"clear predecessor generation local state",
						err,
					)
				}
			}
			if err := clearLogicalSnapshotDestination(
				destination,
				cut,
			); err != nil {
				return err
			}
			for _, table := range logicalSnapshotCopiedTables() {
				if err := copyLogicalSnapshotTable(
					source,
					destination,
					table,
				); err != nil {
					return logicalSnapshotInstallError(
						"copy "+table,
						err,
					)
				}
			}
			if generationChanged {
				if err := clearSuccessorGitArtifacts(destination); err != nil {
					return logicalSnapshotInstallError(
						"reconcile successor Git artifacts",
						err,
					)
				}
			}
			if err := rebuildLogicalSnapshotDerivedViews(
				source,
				destination,
			); err != nil {
				return err
			}
			if err := restoreRecoveryBoundaryAuditTimes(
				destination,
				preservedRecoveryTimes,
			); err != nil {
				return err
			}
			if err := mergeLogicalSnapshotControlApprovals(
				source,
				destination,
			); err != nil {
				return err
			}
			if err := verifyLogicalSnapshotControlApprovals(
				destination,
			); err != nil {
				return err
			}
			if err := rearmLeaseDeadlines(
				destination,
				options.OriginBootID,
				installedAt,
				options.MonotonicNowNS,
			); err != nil {
				return logicalSnapshotInstallError(
					"rearm imported leases",
					err,
				)
			}
			if err := reconcileLogicalSnapshotLocalState(
				destination,
				cut,
			); err != nil {
				return err
			}
			if err := store.reachApplyStage(applyAfterOutbox); err != nil {
				return err
			}
			var sourceEndErr error
			endSource(&sourceEndErr)
			sourceEnded = true
			if sourceEndErr != nil {
				return logicalSnapshotInstallError(
					"close verified source snapshot",
					sourceEndErr,
				)
			}
			if err := writeLogicalSnapshotAttestation(
				destination,
				root,
				options.VerifiedAt,
			); err != nil {
				return err
			}
			if err := writeStandaloneSettledNonvoterState(
				destination,
				cut,
				options.VerifiedAt,
			); err != nil {
				return err
			}
			if err := verifyLogicalSnapshotStageConnection(
				destination,
				cut,
				&root,
				false,
			); err != nil {
				return logicalSnapshotInstallError(
					"verify installed state",
					err,
				)
			}
			state, found, err := readConsensusState(destination)
			if err != nil {
				return err
			}
			if !found {
				return logicalSnapshotInstallError(
					"installed consensus state is missing",
					nil,
				)
			}
			settled, found, err := readSettledNonvoterState(destination)
			if err != nil {
				return err
			}
			if !found {
				return logicalSnapshotInstallError(
					"installed settled-nonvoter evidence is missing",
					nil,
				)
			}
			if err := verifySettledNonvoterEvidence(
				destination,
				state,
				settled,
			); err != nil {
				return logicalSnapshotInstallError(
					"verify installed replication evidence",
					err,
				)
			}
			if err := verifyHistoricalReplicationAttestations(
				destination,
				state,
			); err != nil {
				return logicalSnapshotInstallError(
					"verify installed predecessor replication evidence",
					err,
				)
			}
			if err := requireNoStandaloneSnapshotRaftEvidence(
				destination,
			); err != nil {
				return err
			}
			if err := checkForeignKeys(destination); err != nil {
				return err
			}
			return store.reachApplyStage(applyAfterConsensus)
		})
	})
	if err != nil {
		return StandaloneLogicalSnapshotInstallResult{}, err
	}

	stage.consumed = true
	stage.root = logicalsnapshot.Root{}
	stage.artifact = logicalsnapshot.VerifiedExpandedArtifact{}
	stage.derivedViewsDigest = Digest{}
	stage.hasRoot = false
	stage.hasDerivedDigest = false
	result := StandaloneLogicalSnapshotInstallResult{
		Heads: ApplyHeads{
			ChainIndex:              cut.ChainIndex,
			ChainHash:               cut.ChainHash,
			ResultIndex:             cut.ResultIndex,
			ResultHash:              cut.ResultHash,
			ProjectionAccumulator:   cut.ProjectionAccumulator,
			DigestVersion:           cut.DigestVersion,
			ProjectionSchemaVersion: cut.ProjectionSchemaVersion,
		},
		Cut:           cut,
		AttestationID: attestationID,
	}
	result.AdmissionRevision = store.advanceAdmissionRevision()
	return result, nil
}

func lockLogicalSnapshotMutex(
	ctx context.Context,
	mutex *sync.Mutex,
) error {
	if ctx == nil || mutex == nil {
		return ErrLogicalSnapshotInstall
	}
	if mutex.TryLock() {
		return nil
	}
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if mutex.TryLock() {
				return nil
			}
			timer.Reset(time.Millisecond)
		}
	}
}

func logicalSnapshotCopiedTables() []string {
	tables := []string{
		"genesis_records",
		"initial_projection_boundary",
		"initial_projection_rows",
		"consensus_state",
		"events",
		"command_results",
		"chain_checkpoints",
	}
	for _, table := range projectionTables {
		tables = append(tables, table.name)
	}
	return tables
}

func verifyLogicalSnapshotInstallDestination(
	source *sqlite.Conn,
	destination *sqlite.Conn,
	sourceState consensusState,
	cut LogicalSnapshotCut,
) (bool, error) {
	destinationState, found, err := readConsensusState(destination)
	if err != nil {
		return false, err
	}
	if !found {
		return false, requireEmptyLogicalSnapshotDestination(destination)
	}
	settled, found, err := readSettledNonvoterState(destination)
	if err != nil {
		return false, err
	}
	if !found {
		return false, logicalSnapshotInstallError(
			"destination is not a settled nonvoter",
			nil,
		)
	}
	if err := verifyCompleteLogicalSnapshotHistory(
		destination,
		destinationState,
	); err != nil {
		return false, logicalSnapshotInstallError(
			"verify destination commitment history",
			err,
		)
	}
	if err := verifyHistoricalReplicationAttestations(
		destination,
		destinationState,
	); err != nil {
		return false, logicalSnapshotInstallError(
			"verify destination predecessor replication evidence",
			err,
		)
	}
	if err := verifyLogicalSnapshotCheckpointRows(destination); err != nil {
		return false, logicalSnapshotInstallError(
			"verify destination checkpoint rows",
			err,
		)
	}
	if err := verifyDerivedViews(destination); err != nil {
		return false, logicalSnapshotInstallError(
			"verify destination derived views",
			err,
		)
	}
	if err := verifySettledNonvoterEvidence(
		destination,
		destinationState,
		settled,
	); err != nil {
		return false, logicalSnapshotInstallError(
			"verify destination settled evidence",
			err,
		)
	}
	destinationWorkspace, err := activeWorkspaceID(
		destination,
		destinationState,
	)
	if err != nil {
		return false, err
	}
	if destinationWorkspace != cut.WorkspaceID ||
		destinationState.recoveryGeneration > sourceState.recoveryGeneration ||
		destinationState.resultIndex > cut.ResultIndex ||
		destinationState.chainIndex > cut.ChainIndex ||
		destinationState.digestVersion != cut.DigestVersion ||
		destinationState.projectionSchemaVersion !=
			cut.ProjectionSchemaVersion {
		return false, logicalSnapshotInstallError(
			"snapshot is not a forward extension of the destination lineage",
			nil,
		)
	}

	sourceGeneration, err := logicalSnapshotSourceGenerationState(
		source,
		sourceState,
		destinationState.recoveryGeneration,
		destinationState.sessionID,
	)
	if err != nil {
		return false, logicalSnapshotInstallError(
			"find destination generation in snapshot lineage",
			err,
		)
	}
	if destinationState.recoveryGeneration ==
		sourceState.recoveryGeneration &&
		destinationState.sessionID != cut.SessionID {
		return false, logicalSnapshotInstallError(
			"snapshot active generation has another session identity",
			nil,
		)
	}
	sourceWorkspace, err := activeWorkspaceID(source, sourceGeneration)
	if err != nil {
		return false, err
	}
	if sourceWorkspace != destinationWorkspace ||
		destinationState.resultIndex > sourceGeneration.resultIndex ||
		destinationState.chainIndex > sourceGeneration.chainIndex {
		return false, logicalSnapshotInstallError(
			"snapshot generation does not contain the destination cut",
			nil,
		)
	}
	sourceGenesis, err := readGenesisBoundary(
		source,
		sourceGeneration.recoveryGeneration,
		sourceGeneration.sessionID,
	)
	if err != nil {
		return false, err
	}
	destinationGenesis, err := readGenesisBoundary(
		destination,
		destinationState.recoveryGeneration,
		destinationState.sessionID,
	)
	if err != nil {
		return false, err
	}
	if !sameLogicalSnapshotGenesisBoundary(
		sourceGenesis,
		destinationGenesis,
	) {
		return false, logicalSnapshotInstallError(
			"snapshot and destination genesis boundaries differ",
			nil,
		)
	}
	sourceHead, err := resultRangeStart(
		source,
		sourceGeneration,
		sourceGenesis,
		destinationState.resultIndex,
	)
	if err != nil {
		return false, err
	}
	sourceAccumulator, err := projectionAccumulatorAtResultCut(
		source,
		sourceGeneration,
		sourceGenesis,
		destinationState.resultIndex,
	)
	if err != nil {
		return false, err
	}
	if sourceHead.resultHash != destinationState.resultHash ||
		sourceHead.chainIndex != destinationState.chainIndex ||
		sourceHead.chainHash != destinationState.chainHash ||
		sourceAccumulator != destinationState.projectionAccumulator {
		return false, logicalSnapshotInstallError(
			"snapshot does not contain the exact destination cut",
			nil,
		)
	}
	if destinationState.recoveryGeneration ==
		sourceState.recoveryGeneration {
		sourceStateDigest, err := projectionStateDigestAtResultCut(
			source,
			sourceGeneration,
			sourceGenesis,
			destinationState.resultIndex,
			nil,
		)
		if err != nil {
			return false, err
		}
		destinationStateDigest, err := projectionStateDigest(
			destination,
			chain.Versions{
				Digest: destinationState.digestVersion,
				ProjectionSchema: destinationState.
					projectionSchemaVersion,
			},
		)
		if err != nil {
			return false, err
		}
		if sourceStateDigest != destinationStateDigest {
			return false, logicalSnapshotInstallError(
				"snapshot projection state differs at destination cut",
				nil,
			)
		}
	}
	return destinationState.recoveryGeneration <
		sourceState.recoveryGeneration, nil
}

func logicalSnapshotSourceGenerationState(
	source *sqlite.Conn,
	active consensusState,
	generation uint64,
	sessionID domain.UUIDv7,
) (consensusState, error) {
	if generation > active.recoveryGeneration || !sessionID.Valid() {
		return consensusState{}, errors.New(
			"requested generation is outside the snapshot lineage",
		)
	}
	if generation == active.recoveryGeneration {
		if sessionID != active.sessionID {
			return consensusState{}, errors.New(
				"active generation has another session identity",
			)
		}
		return active, nil
	}
	if _, err := readGenesisBoundary(source, generation, sessionID); err != nil {
		return consensusState{}, err
	}
	var successorSessionID domain.UUIDv7
	if err := queryOneArgs(
		source,
		`SELECT session_id FROM genesis_records
		  WHERE recovery_generation = ?1;`,
		[]any{generation + 1},
		func(stmt *sqlite.Stmt) {
			successorSessionID = domain.UUIDv7(stmt.ColumnText(0))
		},
	); err != nil {
		return consensusState{}, err
	}
	if !successorSessionID.Valid() {
		return consensusState{}, errors.New(
			"successor generation has an invalid session identity",
		)
	}
	successor, err := readGenesisBoundary(
		source,
		generation+1,
		successorSessionID,
	)
	if err != nil {
		return consensusState{}, err
	}
	if !successor.hasPredecessor {
		return consensusState{}, errors.New(
			"successor generation lacks a predecessor cut",
		)
	}
	return consensusState{
		sessionID:               sessionID,
		recoveryGeneration:      generation,
		chainIndex:              successor.predecessorChainIndex,
		chainHash:               successor.predecessorChainHash,
		resultIndex:             successor.predecessorResultIndex,
		resultHash:              successor.predecessorResultHash,
		projectionAccumulator:   successor.predecessorAccumulator,
		digestVersion:           active.digestVersion,
		projectionSchemaVersion: active.projectionSchemaVersion,
	}, nil
}

func sameLogicalSnapshotGenesisBoundary(
	left storedGenesisBoundary,
	right storedGenesisBoundary,
) bool {
	return bytes.Equal(left.genesisJSON, right.genesisJSON) &&
		left.genesisDigest == right.genesisDigest &&
		left.stateDigest == right.stateDigest &&
		left.predecessorChainIndex == right.predecessorChainIndex &&
		left.predecessorChainHash == right.predecessorChainHash &&
		left.predecessorResultIndex == right.predecessorResultIndex &&
		left.predecessorResultHash == right.predecessorResultHash &&
		left.predecessorAccumulator == right.predecessorAccumulator &&
		left.hasPredecessor == right.hasPredecessor
}

func requireEmptyLogicalSnapshotDestination(conn *sqlite.Conn) error {
	var tables []string
	if err := query(
		conn,
		`SELECT name FROM sqlite_schema
		  WHERE type = 'table'
		    AND name != 'schema_migrations'
		    AND name NOT LIKE 'sqlite_%'
		  ORDER BY name;`,
		func(stmt *sqlite.Stmt) {
			tables = append(tables, stmt.ColumnText(0))
		},
	); err != nil {
		return err
	}
	for _, table := range tables {
		if !validLogicalSnapshotTableName(table) {
			return logicalSnapshotInstallError(
				"destination schema contains an invalid table name",
				nil,
			)
		}
		var count int64
		if err := queryOne(
			conn,
			"SELECT count(*) FROM "+table+";",
			func(stmt *sqlite.Stmt) {
				count = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if count != 0 {
			return logicalSnapshotInstallError(
				"uninitialized destination contains rows in "+table,
				nil,
			)
		}
	}
	return nil
}

func clearLogicalSnapshotDestination(
	conn *sqlite.Conn,
	cut LogicalSnapshotCut,
) error {
	if err := clearLogicalSnapshotReplicationAttestations(
		conn,
		cut,
	); err != nil {
		return err
	}
	for _, table := range []string{
		"event_provenance",
		"raft_command_applications",
		"raft_snapshot_installs",
		"raft_committed_configuration",
		"replication_cursors",
		"replication_watermark_observations",
		"settled_nonvoter_state",
	} {
		if err := execute(conn, "DELETE FROM "+table+";"); err != nil {
			return logicalSnapshotInstallError("clear "+table, err)
		}
	}
	tables := logicalSnapshotCopiedTables()
	for index := len(tables) - 1; index >= 0; index-- {
		if tables[index] == "control_file_approvals" ||
			tables[index] == "control_file_proposals" {
			continue
		}
		if err := execute(conn, "DELETE FROM "+tables[index]+";"); err != nil {
			return logicalSnapshotInstallError(
				"clear "+tables[index],
				err,
			)
		}
	}
	if err := execute(conn, "DELETE FROM activity;"); err != nil {
		return logicalSnapshotInstallError("clear activity", err)
	}
	if err := execute(
		conn,
		`DELETE FROM audit_events
		  WHERE source_kind != 'local_aggregate'
		     OR event_id IS NOT NULL
		     OR result_index IS NOT NULL;`,
	); err != nil {
		return logicalSnapshotInstallError(
			"clear rebuilt audit events",
			err,
		)
	}
	return nil
}

func clearLogicalSnapshotReplicationAttestations(
	conn *sqlite.Conn,
	cut LogicalSnapshotCut,
) error {
	if err := execute(
		conn,
		`DELETE FROM replication_attestations
		  WHERE session_id = ?1 AND recovery_generation = ?2;`,
		string(cut.SessionID),
		cut.RecoveryGeneration,
	); err != nil {
		return logicalSnapshotInstallError(
			"clear active-generation replication attestations",
			err,
		)
	}
	return nil
}

func requireLogicalSnapshotInstallSourceLocalState(conn *sqlite.Conn) error {
	for _, table := range []string{
		"agent_launches",
		"agent_resume_tokens",
		"git_artifacts",
		"local_requests",
		"managed_roots",
		"origin_counters",
		"outbox",
		"owner_recovery_challenges",
		"pairing_attempt_finalizations",
		"pairing_attempts",
		"pairing_invites",
		"pairing_secret_deletions",
		"peer_acks",
		"peer_endpoints",
		"raft_committed_configuration",
		"replication_cursors",
		"replication_watermark_observations",
	} {
		var count int64
		if err := queryOne(
			conn,
			"SELECT count(*) FROM "+table+";",
			func(stmt *sqlite.Stmt) {
				count = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if count != 0 {
			return logicalSnapshotInstallError(
				"quarantine contains source-local rows in "+table,
				nil,
			)
		}
	}
	return nil
}

func reconcileLogicalSnapshotLocalState(
	conn *sqlite.Conn,
	cut LogicalSnapshotCut,
) error {
	if err := compactLogicalSnapshotLocalCommands(conn, cut); err != nil {
		return logicalSnapshotInstallError(
			"compact committed local commands",
			err,
		)
	}
	if err := execute(
		conn,
		`DELETE FROM agent_resume_tokens
		  WHERE session_id = ?1 AND recovery_generation = ?2
		    AND EXISTS (
		        SELECT 1 FROM agent_sessions
		         WHERE agent_sessions.agent_session_id =
		                   agent_resume_tokens.agent_session_id
		           AND agent_sessions.state = 'ended'
		    );`,
		string(cut.SessionID),
		cut.RecoveryGeneration,
	); err != nil {
		return logicalSnapshotInstallError(
			"remove ended agent resume tokens",
			err,
		)
	}
	if err := execute(
		conn,
		`UPDATE agent_launches
		    SET state = 'cleared'
		  WHERE session_id = ?1 AND recovery_generation = ?2
		    AND state IN ('reserved', 'consumed')
		    AND EXISTS (
		        SELECT 1 FROM agent_sessions
		         WHERE agent_sessions.agent_session_id =
		                   agent_launches.agent_session_id
		           AND agent_sessions.state = 'ended'
		    );`,
		string(cut.SessionID),
		cut.RecoveryGeneration,
	); err != nil {
		return logicalSnapshotInstallError(
			"clear ended agent launches",
			err,
		)
	}
	if err := advanceLogicalSnapshotOriginCounters(conn); err != nil {
		return logicalSnapshotInstallError(
			"advance local origin counters",
			err,
		)
	}
	var committedOutboxRows int64
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM outbox
		   JOIN command_results USING (event_id)
		  WHERE outbox.session_id = ?1
		    AND outbox.recovery_generation = ?2;`,
		[]any{string(cut.SessionID), cut.RecoveryGeneration},
		func(stmt *sqlite.Stmt) {
			committedOutboxRows = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if committedOutboxRows != 0 {
		return logicalSnapshotInstallError(
			"committed commands remain queued locally",
			nil,
		)
	}
	return nil
}

func compactLogicalSnapshotLocalCommands(
	conn *sqlite.Conn,
	cut LogicalSnapshotCut,
) error {
	eventIDs := make([]domain.UUIDv7, 0)
	var rowErr error
	if err := queryArgs(
		conn,
		`SELECT local_requests.event_id
		   FROM local_requests
		   JOIN command_results USING (event_id)
		  WHERE local_requests.session_id = ?1
		    AND local_requests.recovery_generation = ?2
		    AND local_requests.state IN ('signed', 'pending')
		  ORDER BY command_results.result_index;`,
		[]any{string(cut.SessionID), cut.RecoveryGeneration},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			eventID := domain.UUIDv7(stmt.ColumnText(0))
			if !eventID.Valid() ||
				len(eventIDs) >= MaxUnresolvedCommandsPerSession {
				rowErr = ErrLocalStateIntegrity
				return
			}
			eventIDs = append(eventIDs, eventID)
		},
	); err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	for _, eventID := range eventIDs {
		stored, found, err := readStoredCommandResult(conn, eventID)
		if err != nil {
			return err
		}
		if !found ||
			stored.sessionID != cut.SessionID ||
			stored.recoveryGeneration != cut.RecoveryGeneration ||
			verifyStoredCommandResult(conn, stored) != nil {
			return ErrLocalStateIntegrity
		}
		proposal, err := event.InspectUnverifiedProposal(stored.proposalJSON)
		if err != nil || proposal.EventID != eventID {
			return ErrLocalStateIntegrity
		}
		member, found, err := readStatusMember(
			conn,
			proposal.Origin.DeviceID(),
		)
		if err != nil || !found {
			return ErrLocalStateIntegrity
		}
		signed, err := event.ParseAndVerify(
			stored.proposalJSON,
			event.VerificationContext{
				SessionID:         cut.SessionID,
				WorkspaceID:       cut.WorkspaceID,
				IdentityPublicKey: member.IdentityPublicKey,
			},
		)
		if err != nil {
			return ErrLocalStateIntegrity
		}
		if err := writePostCommandLocalCleanup(conn, ApplyRequest{
			RecoveryGeneration: cut.RecoveryGeneration,
			Proposal:           signed,
			Outcome:            stored.outcome,
		}); err != nil {
			return err
		}
	}
	return nil
}

func advanceLogicalSnapshotOriginCounters(conn *sqlite.Conn) error {
	if err := execute(
		conn,
		`UPDATE origin_counters AS counters
		    SET next_sequence = CASE
		            WHEN (
		                SELECT scopes.last_sequence
		                  FROM origin_scopes AS scopes
		                 WHERE scopes.device_id = counters.device_id
		                   AND scopes.scope_kind = counters.scope_kind
		                   AND scopes.scope_id = counters.scope_id
		            ) = ?1
		            THEN NULL
		            ELSE (
		                SELECT scopes.last_sequence + 1
		                  FROM origin_scopes AS scopes
		                 WHERE scopes.device_id = counters.device_id
		                   AND scopes.scope_kind = counters.scope_kind
		                   AND scopes.scope_id = counters.scope_id
		            )
		        END,
		        exhausted = CASE
		            WHEN (
		                SELECT scopes.last_sequence
		                  FROM origin_scopes AS scopes
		                 WHERE scopes.device_id = counters.device_id
		                   AND scopes.scope_kind = counters.scope_kind
		                   AND scopes.scope_id = counters.scope_id
		            ) = ?1
		            THEN 1
		            ELSE 0
		        END
		  WHERE counters.exhausted = 0
		    AND EXISTS (
		        SELECT 1 FROM origin_scopes AS scopes
		         WHERE scopes.device_id = counters.device_id
		           AND scopes.scope_kind = counters.scope_kind
		           AND scopes.scope_id = counters.scope_id
		           AND scopes.last_sequence >= counters.next_sequence
		    );`,
		domain.MaxSafeInteger,
	); err != nil {
		return err
	}
	var stale int64
	if err := queryOne(
		conn,
		`SELECT count(*)
		   FROM origin_counters AS counters
		   JOIN origin_scopes AS scopes
		     ON scopes.device_id = counters.device_id
		    AND scopes.scope_kind = counters.scope_kind
		    AND scopes.scope_id = counters.scope_id
		  WHERE (counters.exhausted = 0
		         AND counters.next_sequence <= scopes.last_sequence)
		     OR (scopes.last_sequence = 9007199254740991
		         AND counters.exhausted != 1);`,
		func(stmt *sqlite.Stmt) {
			stale = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if stale != 0 {
		return ErrLocalStateIntegrity
	}
	return nil
}

func copyLogicalSnapshotTable(
	source *sqlite.Conn,
	destination *sqlite.Conn,
	table string,
) (err error) {
	if !validLogicalSnapshotTableName(table) {
		return errors.New("invalid table name")
	}
	sourceColumns, err := logicalSnapshotTableColumnCount(source, table)
	if err != nil {
		return err
	}
	destinationColumns, err := logicalSnapshotTableColumnCount(
		destination,
		table,
	)
	if err != nil {
		return err
	}
	if sourceColumns < 1 || sourceColumns != destinationColumns {
		return fmt.Errorf(
			"column count differs: source=%d destination=%d",
			sourceColumns,
			destinationColumns,
		)
	}

	read, err := source.Prepare("SELECT * FROM " + table + ";")
	if err != nil {
		return err
	}
	defer func() {
		if resetErr := read.Reset(); err == nil {
			err = resetErr
		}
	}()

	placeholders := make([]string, sourceColumns)
	for index := range placeholders {
		placeholders[index] = fmt.Sprintf("?%d", index+1)
	}
	insert := "INSERT INTO "
	if table == "control_file_approvals" ||
		table == "control_file_proposals" {
		insert = "INSERT OR IGNORE INTO "
	}
	write, err := destination.Prepare(
		insert + table + " VALUES (" +
			strings.Join(placeholders, ", ") + ");",
	)
	if err != nil {
		return err
	}
	defer func() {
		resetErr := write.Reset()
		clearErr := write.ClearBindings()
		if err == nil {
			err = resetErr
		}
		if err == nil {
			err = clearErr
		}
	}()

	for {
		hasRow, err := read.Step()
		if err != nil {
			return err
		}
		if !hasRow {
			return nil
		}
		for column := 0; column < sourceColumns; column++ {
			parameter := column + 1
			switch read.ColumnType(column) {
			case sqlite.TypeNull:
				write.BindNull(parameter)
			case sqlite.TypeInteger:
				write.BindInt64(parameter, read.ColumnInt64(column))
			case sqlite.TypeFloat:
				write.BindFloat(parameter, read.ColumnFloat(column))
			case sqlite.TypeText:
				write.BindText(parameter, read.ColumnText(column))
			case sqlite.TypeBlob:
				write.BindBytes(parameter, columnBytes(read, column))
			default:
				return errors.New("unsupported SQLite column type")
			}
		}
		hasResult, err := write.Step()
		if err != nil {
			return err
		}
		if hasResult {
			return errors.New("INSERT unexpectedly returned a row")
		}
		if err := write.Reset(); err != nil {
			return err
		}
		if err := write.ClearBindings(); err != nil {
			return err
		}
	}
}

func rebuildLogicalSnapshotDerivedViews(
	source *sqlite.Conn,
	destination *sqlite.Conn,
) error {
	if err := copyLogicalSnapshotActivity(source, destination); err != nil {
		return logicalSnapshotInstallError("rebuild activity", err)
	}
	if err := copyLogicalSnapshotAudit(source, destination); err != nil {
		return logicalSnapshotInstallError("rebuild audit events", err)
	}
	return nil
}

func readRecoveryBoundaryAuditTimes(
	conn *sqlite.Conn,
) (map[domain.UUIDv7]recoveryBoundaryAuditTimes, error) {
	result := make(map[domain.UUIDv7]recoveryBoundaryAuditTimes)
	var rowErr error
	if err := query(
		conn,
		`SELECT session_id, first_seen_at, last_seen_at
		   FROM audit_events
		  WHERE source_kind = 'recovery_boundary'
		  ORDER BY session_id;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			sessionID := domain.UUIDv7(stmt.ColumnText(0))
			times := recoveryBoundaryAuditTimes{
				first: domain.Timestamp(stmt.ColumnText(1)),
				last:  domain.Timestamp(stmt.ColumnText(2)),
			}
			if !sessionID.Valid() ||
				!times.first.Valid() ||
				!times.last.Valid() {
				rowErr = errors.New(
					"invalid recovery-boundary audit observation time",
				)
				return
			}
			if _, exists := result[sessionID]; exists {
				rowErr = errors.New(
					"duplicate recovery-boundary audit observation time",
				)
				return
			}
			result[sessionID] = times
		},
	); err != nil {
		return nil, err
	}
	if rowErr != nil {
		return nil, rowErr
	}
	return result, nil
}

func restoreRecoveryBoundaryAuditTimes(
	conn *sqlite.Conn,
	times map[domain.UUIDv7]recoveryBoundaryAuditTimes,
) error {
	for sessionID, observed := range times {
		if err := execute(
			conn,
			`UPDATE audit_events
			    SET first_seen_at = ?1, last_seen_at = ?2
			  WHERE source_kind = 'recovery_boundary'
			    AND session_id = ?3;`,
			string(observed.first),
			string(observed.last),
			string(sessionID),
		); err != nil {
			return logicalSnapshotInstallError(
				"restore recovery audit observation time",
				err,
			)
		}
		var matches int64
		if err := queryOneArgs(
			conn,
			`SELECT count(*) FROM audit_events
			  WHERE source_kind = 'recovery_boundary'
			    AND session_id = ?1
			    AND first_seen_at = ?2
			    AND last_seen_at = ?3;`,
			[]any{
				string(sessionID),
				string(observed.first),
				string(observed.last),
			},
			func(stmt *sqlite.Stmt) {
				matches = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if matches != 1 {
			return logicalSnapshotInstallError(
				"restored recovery audit observation is missing",
				nil,
			)
		}
	}
	return nil
}

func copyLogicalSnapshotActivity(
	source *sqlite.Conn,
	destination *sqlite.Conn,
) (err error) {
	const columns = 12
	read, err := source.Prepare(
		`SELECT event_id, session_id, device_id, actor_type,
		        agent_session_id, event_kind, task_id, rationale_summary,
		        capture_level, actions_json, redaction_json, created_at
		   FROM activity
		  ORDER BY event_id;`,
	)
	if err != nil {
		return err
	}
	defer func() {
		if resetErr := read.Reset(); err == nil {
			err = resetErr
		}
	}()
	write, err := destination.Prepare(
		`INSERT INTO activity(
		    event_id, session_id, device_id, actor_type, agent_session_id,
		    event_kind, task_id, rationale_summary, capture_level,
		    actions_json, redaction_json, created_at
		) VALUES (
		    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
		);`,
	)
	if err != nil {
		return err
	}
	defer func() {
		resetErr := write.Reset()
		clearErr := write.ClearBindings()
		if err == nil {
			err = resetErr
		}
		if err == nil {
			err = clearErr
		}
	}()
	return copyLogicalSnapshotRows(read, write, columns, nil)
}

func copyLogicalSnapshotAudit(
	source *sqlite.Conn,
	destination *sqlite.Conn,
) (err error) {
	const columns = 16
	read, err := source.Prepare(
		`SELECT session_id, source_kind, event_id, result_index,
		        reporter_device_id, subject_device_id,
		        subject_credential_epoch, actor_type, ipc_channel,
		        action_code, outcome_code, subject, details_json,
		        first_seen_at, last_seen_at, observation_count
		   FROM audit_events
		  ORDER BY audit_id;`,
	)
	if err != nil {
		return err
	}
	defer func() {
		if resetErr := read.Reset(); err == nil {
			err = resetErr
		}
	}()
	write, err := destination.Prepare(
		`INSERT INTO audit_events(
		    session_id, source_kind, event_id, result_index,
		    reporter_device_id, subject_device_id, subject_credential_epoch,
		    actor_type, ipc_channel, action_code, outcome_code, subject,
		    details_json, first_seen_at, last_seen_at, observation_count
		) VALUES (
		    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
		    ?13, ?14, ?15, ?16
		);`,
	)
	if err != nil {
		return err
	}
	defer func() {
		resetErr := write.Reset()
		clearErr := write.ClearBindings()
		if err == nil {
			err = resetErr
		}
		if err == nil {
			err = clearErr
		}
	}()
	return copyLogicalSnapshotRows(
		read,
		write,
		columns,
		nil,
	)
}

func copyLogicalSnapshotRows(
	read *sqlite.Stmt,
	write *sqlite.Stmt,
	columns int,
	include func(*sqlite.Stmt) (bool, error),
) error {
	for {
		hasRow, err := read.Step()
		if err != nil {
			return err
		}
		if !hasRow {
			return nil
		}
		if include != nil {
			keep, err := include(read)
			if err != nil {
				return err
			}
			if !keep {
				continue
			}
		}
		for column := 0; column < columns; column++ {
			if err := bindLogicalSnapshotColumn(
				write,
				column+1,
				read,
				column,
			); err != nil {
				return err
			}
		}
		hasResult, err := write.Step()
		if err != nil {
			return err
		}
		if hasResult {
			return errors.New("INSERT unexpectedly returned a row")
		}
		if err := write.Reset(); err != nil {
			return err
		}
		if err := write.ClearBindings(); err != nil {
			return err
		}
	}
}

func bindLogicalSnapshotColumn(
	destination *sqlite.Stmt,
	parameter int,
	source *sqlite.Stmt,
	column int,
) error {
	switch source.ColumnType(column) {
	case sqlite.TypeNull:
		destination.BindNull(parameter)
	case sqlite.TypeInteger:
		destination.BindInt64(parameter, source.ColumnInt64(column))
	case sqlite.TypeFloat:
		destination.BindFloat(parameter, source.ColumnFloat(column))
	case sqlite.TypeText:
		destination.BindText(parameter, source.ColumnText(column))
	case sqlite.TypeBlob:
		destination.BindBytes(parameter, columnBytes(source, column))
	default:
		return errors.New("unsupported SQLite column type")
	}
	return nil
}

func mergeLogicalSnapshotControlApprovals(
	source *sqlite.Conn,
	destination *sqlite.Conn,
) error {
	var invalid int64
	if err := queryOne(
		source,
		`SELECT count(*)
		   FROM control_file_proposals AS proposals
		   LEFT JOIN control_file_approvals AS approvals
		     ON approvals.proposal_event_id = proposals.proposal_event_id
		  WHERE approvals.proposal_event_id IS NULL
		     OR approvals.session_id != proposals.session_id
		     OR approvals.path != proposals.path
		     OR approvals.operation != proposals.operation
		     OR approvals.content_digest IS NOT proposals.content_digest
		     OR approvals.decision != 'pending'
		     OR approvals.content_store_ref IS NOT NULL
		     OR approvals.manifest_version IS NOT NULL
		     OR approvals.decided_at IS NOT NULL;`,
		func(stmt *sqlite.Stmt) {
			invalid = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if invalid != 0 {
		return logicalSnapshotInstallError(
			"quarantine contains authoritative control-file decisions",
			nil,
		)
	}
	if err := copyLogicalSnapshotTable(
		source,
		destination,
		"control_file_approvals",
	); err != nil {
		return logicalSnapshotInstallError(
			"merge pending control-file approvals",
			err,
		)
	}
	return nil
}

func logicalSnapshotTableColumnCount(
	conn *sqlite.Conn,
	table string,
) (int, error) {
	var count int64
	if err := queryOne(
		conn,
		"SELECT count(*) FROM pragma_table_info('"+table+"');",
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	); err != nil {
		return 0, err
	}
	if count < 1 || count > 256 {
		return 0, errors.New("invalid table column count")
	}
	return int(count), nil
}

func validLogicalSnapshotTableName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if character != '_' &&
			(character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func verifyLogicalSnapshotControlApprovals(conn *sqlite.Conn) error {
	var invalid int64
	if err := queryOne(
		conn,
		`SELECT count(*)
		   FROM control_file_proposals AS proposals
		   LEFT JOIN control_file_approvals AS approvals
		     ON approvals.proposal_event_id = proposals.proposal_event_id
		  WHERE approvals.proposal_event_id IS NULL
		     OR approvals.session_id != proposals.session_id
		     OR approvals.path != proposals.path
		     OR approvals.operation != proposals.operation
		     OR approvals.content_digest IS NOT proposals.content_digest;`,
		func(stmt *sqlite.Stmt) {
			invalid = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if invalid != 0 {
		return logicalSnapshotInstallError(
			"local control-file approvals do not match imported proposals",
			nil,
		)
	}
	return nil
}

func writeLogicalSnapshotAttestation(
	conn *sqlite.Conn,
	root logicalsnapshot.Root,
	verifiedAt domain.Timestamp,
) error {
	cut, err := logicalSnapshotCutFromRoot(root)
	if err != nil {
		return err
	}
	start, startDigest, err := logicalSnapshotInitialBoundary(conn)
	if err != nil {
		return logicalSnapshotInstallError(
			"derive snapshot coverage start",
			err,
		)
	}
	canonical := root.CanonicalBytes()
	signature := root.Signature()
	attestationID := logicalSnapshotAttestationID(root)
	if attestationID == "" {
		return logicalSnapshotInstallError("invalid signed root", nil)
	}
	return execute(
		conn,
		`INSERT INTO replication_attestations(
		    attestation_id, attestation_kind, session_id, workspace_id,
		    recovery_generation, signer_device_id,
		    authority_voter_set_version, from_result_index, to_result_index,
		    server_applied_result_index, start_result_hash, end_result_hash,
		    start_chain_index, end_chain_index, start_chain_hash,
		    end_chain_hash, start_projection_accumulator,
		    end_projection_accumulator, start_projection_state_digest,
		    end_projection_state_digest, checkpoint_event_id, envelope_json,
		    signature, verified_at
		) VALUES (
		    ?1, 'snapshot', ?2, ?3, ?4, ?5, ?6, 0, ?7, NULL, ?8, ?9,
		    0, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
		);`,
		attestationID,
		string(cut.SessionID),
		string(cut.WorkspaceID),
		cut.RecoveryGeneration,
		string(cut.SignerDeviceID),
		cut.AuthorityVersion,
		cut.ResultIndex,
		start.ResultHash[:],
		cut.ResultHash[:],
		cut.ChainIndex,
		start.ChainHash[:],
		cut.ChainHash[:],
		start.ProjectionAccumulator[:],
		cut.ProjectionAccumulator[:],
		startDigest[:],
		cut.ProjectionStateDigest[:],
		string(cut.CheckpointEventID),
		string(canonical),
		signature[:],
		string(verifiedAt),
	)
}

func readLogicalSnapshotAttestation(
	conn *sqlite.Conn,
	state consensusState,
) (storedLogicalSnapshotAttestation, bool, error) {
	var (
		result storedLogicalSnapshotAttestation
		count  int
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT attestation_id, session_id, workspace_id,
		        recovery_generation, signer_device_id,
		        authority_voter_set_version, from_result_index,
		        to_result_index, server_applied_result_index,
		        start_result_hash, end_result_hash, start_chain_index,
		        end_chain_index, start_chain_hash, end_chain_hash,
		        start_projection_accumulator, end_projection_accumulator,
		        start_projection_state_digest, end_projection_state_digest,
		        checkpoint_event_id, envelope_json, signature, verified_at
		   FROM replication_attestations
		  WHERE attestation_kind = 'snapshot'
		    AND session_id = ?1 AND recovery_generation = ?2
		  ORDER BY attestation_id;`,
		[]any{string(state.sessionID), state.recoveryGeneration},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 || rowErr != nil {
				return
			}
			result.id = stmt.ColumnText(0)
			result.sessionID = domain.UUIDv7(stmt.ColumnText(1))
			result.workspaceID = domain.UUIDv4(stmt.ColumnText(2))
			result.signerDeviceID = domain.DeviceID(stmt.ColumnText(4))
			result.checkpointEventID = domain.UUIDv7(stmt.ColumnText(19))
			result.envelopeJSON = []byte(stmt.ColumnText(20))
			result.verifiedAt = domain.Timestamp(stmt.ColumnText(22))
			if stmt.ColumnType(8) != sqlite.TypeNull {
				rowErr = errors.New(
					"snapshot attestation carries a server watermark",
				)
				return
			}
			numbers := []*uint64{
				&result.recoveryGeneration,
				&result.authorityVersion,
				&result.fromResultIndex,
				&result.toResultIndex,
				&result.startChainIndex,
				&result.endChainIndex,
			}
			for index, column := range [...]int{3, 5, 6, 7, 11, 12} {
				value := stmt.ColumnInt64(column)
				if value < 0 {
					rowErr = errors.New(
						"negative snapshot attestation number",
					)
					return
				}
				*numbers[index] = uint64(value)
			}
			digests := []*Digest{
				&result.startResultHash,
				&result.endResultHash,
				&result.startChainHash,
				&result.endChainHash,
				&result.startProjectionAccumulator,
				&result.endProjectionAccumulator,
				&result.startProjectionStateDigest,
				&result.endProjectionStateDigest,
			}
			for index, column := range [...]int{
				9, 10, 13, 14, 15, 16, 17, 18,
			} {
				if rowErr = copyDigestColumn(
					digests[index],
					stmt,
					column,
				); rowErr != nil {
					return
				}
			}
			if stmt.ColumnType(21) != sqlite.TypeBlob ||
				stmt.ColumnLen(21) != ed25519.SignatureSize {
				rowErr = errors.New(
					"invalid snapshot signature storage",
				)
				return
			}
			copy(result.signature[:], columnBytes(stmt, 21))
		},
	)
	if err != nil {
		return storedLogicalSnapshotAttestation{}, false, err
	}
	if rowErr != nil {
		return storedLogicalSnapshotAttestation{}, false,
			replicationEvidenceError(
				"decode snapshot attestation",
				rowErr,
			)
	}
	if count > 1 {
		return storedLogicalSnapshotAttestation{}, false,
			replicationEvidenceError(
				"multiple snapshot baselines cover the active generation",
				nil,
			)
	}
	if count == 0 {
		return storedLogicalSnapshotAttestation{}, false, nil
	}
	root, err := logicalsnapshot.ParseRoot(result.envelopeJSON)
	if err != nil {
		return storedLogicalSnapshotAttestation{}, false,
			replicationEvidenceError("parse retained snapshot root", err)
	}
	if root.Signature() != result.signature {
		return storedLogicalSnapshotAttestation{}, false,
			replicationEvidenceError(
				"retained snapshot signature differs from root",
				nil,
			)
	}
	result.root = root
	if !result.sessionID.Valid() ||
		!result.workspaceID.Valid() ||
		!result.signerDeviceID.Valid() ||
		!result.checkpointEventID.Valid() ||
		!result.verifiedAt.Valid() ||
		result.fromResultIndex != 0 ||
		result.toResultIndex < 1 ||
		result.startChainIndex != 0 ||
		result.endChainIndex > result.toResultIndex ||
		result.authorityVersion < 1 ||
		result.id != logicalSnapshotAttestationID(root) {
		return storedLogicalSnapshotAttestation{}, false,
			replicationEvidenceError(
				"invalid snapshot attestation fields",
				nil,
			)
	}
	return result, true, nil
}

func verifyLogicalSnapshotBaseline(
	conn *sqlite.Conn,
	state consensusState,
	settled settledNonvoterState,
	attestation storedLogicalSnapshotAttestation,
) error {
	cut, err := logicalSnapshotCutFromRoot(attestation.root)
	if err != nil {
		return err
	}
	baseline := settled.baselineHeads
	if attestation.sessionID != state.sessionID ||
		attestation.workspaceID != settled.workspaceID ||
		attestation.recoveryGeneration != state.recoveryGeneration ||
		attestation.signerDeviceID != cut.SignerDeviceID ||
		attestation.authorityVersion != cut.AuthorityVersion ||
		attestation.toResultIndex != cut.ResultIndex ||
		attestation.endResultHash != cut.ResultHash ||
		attestation.endChainIndex != cut.ChainIndex ||
		attestation.endChainHash != cut.ChainHash ||
		attestation.endProjectionAccumulator !=
			cut.ProjectionAccumulator ||
		attestation.endProjectionStateDigest !=
			cut.ProjectionStateDigest ||
		attestation.checkpointEventID != cut.CheckpointEventID ||
		cut.SessionID != state.sessionID ||
		cut.WorkspaceID != settled.workspaceID ||
		cut.RecoveryGeneration != state.recoveryGeneration ||
		cut.ResultIndex > state.resultIndex ||
		cut.ChainIndex > state.chainIndex ||
		cut.DigestVersion != state.digestVersion ||
		cut.ProjectionSchemaVersion !=
			state.projectionSchemaVersion ||
		baseline.ResultIndex != cut.ResultIndex ||
		baseline.ResultHash != cut.ResultHash ||
		baseline.ChainIndex != cut.ChainIndex ||
		baseline.ChainHash != cut.ChainHash ||
		baseline.ProjectionAccumulator !=
			cut.ProjectionAccumulator {
		return errors.New(
			"snapshot root, attestation, baseline, and active lineage differ",
		)
	}

	start, startDigest, err := logicalSnapshotInitialBoundary(conn)
	if err != nil {
		return err
	}
	if attestation.startResultHash != start.ResultHash ||
		attestation.startChainHash != start.ChainHash ||
		attestation.startProjectionAccumulator !=
			start.ProjectionAccumulator ||
		attestation.startProjectionStateDigest != startDigest {
		return errors.New("snapshot coverage does not begin at genesis")
	}
	if err := verifyCompleteLogicalSnapshotHistory(conn, state); err != nil {
		return err
	}
	genesis, err := readGenesisBoundary(
		conn,
		state.recoveryGeneration,
		state.sessionID,
	)
	if err != nil {
		return err
	}
	if cut.ResultIndex < genesis.predecessorResultIndex ||
		cut.ChainIndex < genesis.predecessorChainIndex {
		return errors.New("snapshot cut precedes the active generation")
	}
	head, err := resultRangeStart(
		conn,
		state,
		genesis,
		cut.ResultIndex,
	)
	if err != nil {
		return err
	}
	accumulator, err := projectionAccumulatorAtResultCut(
		conn,
		state,
		genesis,
		cut.ResultIndex,
	)
	if err != nil {
		return err
	}
	authorityRows, stateDigest, err :=
		projectionAuthorityRowsAtResultCut(
			conn,
			state,
			genesis,
			cut.ResultIndex,
		)
	if err != nil {
		return err
	}
	if head.resultHash != cut.ResultHash ||
		head.chainIndex != cut.ChainIndex ||
		head.chainHash != cut.ChainHash ||
		accumulator != cut.ProjectionAccumulator ||
		stateDigest != cut.ProjectionStateDigest {
		return errors.New(
			"retained commitments differ from the snapshot endpoint",
		)
	}
	authority, err := newReplicationEvidenceAuthority(
		state.sessionID,
		authorityRows,
	)
	if err != nil {
		return err
	}
	if authority.authority.VoterSetVersion != cut.AuthorityVersion {
		return errors.New("snapshot authority version differs")
	}
	rootSigner, err := logicalSnapshotAuthoritySigner(
		authority,
		cut.SignerDeviceID,
	)
	if err != nil {
		return err
	}
	if err := logicalsnapshot.VerifyRoot(
		attestation.root,
		rootSigner.IdentityPublicKey,
	); err != nil {
		return err
	}

	checkpoint, found, err := readCheckpointRecord(
		conn,
		cut.CheckpointEventID,
	)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("snapshot checkpoint is missing")
	}
	if err := checkpoint.Validate(); err != nil {
		return err
	}
	if err := verifyCheckpointResultBinding(conn, checkpoint); err != nil {
		return err
	}
	if checkpoint.SessionID != cut.SessionID ||
		checkpoint.WorkspaceID != cut.WorkspaceID ||
		checkpoint.RecoveryGeneration != cut.RecoveryGeneration ||
		checkpoint.AuthorityVoterSetVersion != cut.AuthorityVersion ||
		checkpoint.CoveredChainIndex == domain.MaxSafeInteger ||
		checkpoint.CoveredResultIndex == domain.MaxSafeInteger ||
		checkpoint.CoveredChainIndex+1 != cut.ChainIndex ||
		checkpoint.CoveredResultIndex+1 != cut.ResultIndex ||
		checkpoint.DigestVersion != cut.DigestVersion ||
		checkpoint.ProjectionSchemaVersion !=
			cut.ProjectionSchemaVersion {
		return errors.New("snapshot checkpoint differs from the root cut")
	}
	if err := verifyLogicalSnapshotCheckpointKeepsAuthority(
		conn,
		checkpoint.CheckpointEventID,
	); err != nil {
		return err
	}
	checkpointSigner, err := logicalSnapshotAuthoritySigner(
		authority,
		checkpoint.SignerDeviceID,
	)
	if err != nil {
		return err
	}
	return codecommcrypto.VerifyEd25519(
		checkpointSigner.IdentityPublicKey,
		codec.SignatureCheckpoint,
		checkpoint.CheckpointJSON,
		checkpoint.AuthoritySignature[:],
	)
}

func logicalSnapshotAuthoritySigner(
	authority replicationEvidenceAuthority,
	signerID domain.DeviceID,
) (device.Device, error) {
	signer, found := authority.devices[signerID]
	if !found ||
		signer.Status != device.StatusActive ||
		!authority.authority.Contains(signerID) {
		return device.Device{}, errors.New(
			"snapshot signer is not active in the authority",
		)
	}
	return signer, nil
}

func writeStandaloneSettledNonvoterState(
	conn *sqlite.Conn,
	cut LogicalSnapshotCut,
	enteredAt domain.Timestamp,
) error {
	return execute(
		conn,
		`INSERT INTO settled_nonvoter_state(
		    singleton, session_id, workspace_id, recovery_generation,
		    baseline_chain_index, baseline_chain_hash,
		    baseline_result_index, baseline_result_hash,
		    baseline_projection_accumulator, digest_version,
		    projection_schema_version, frozen_current_term,
		    frozen_last_raft_applied_log_index, entered_at
		) VALUES (
		    1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
		    NULL, NULL, ?11
		);`,
		string(cut.SessionID),
		string(cut.WorkspaceID),
		cut.RecoveryGeneration,
		cut.ChainIndex,
		cut.ChainHash[:],
		cut.ResultIndex,
		cut.ResultHash[:],
		cut.ProjectionAccumulator[:],
		cut.DigestVersion,
		cut.ProjectionSchemaVersion,
		string(enteredAt),
	)
}

func logicalSnapshotInitialBoundary(
	conn *sqlite.Conn,
) (ApplyHeads, Digest, error) {
	var sessionID domain.UUIDv7
	if err := queryOne(
		conn,
		`SELECT session_id FROM genesis_records
		  WHERE recovery_generation = 0 AND genesis_kind = 'initial';`,
		func(stmt *sqlite.Stmt) {
			sessionID = domain.UUIDv7(stmt.ColumnText(0))
		},
	); err != nil {
		return ApplyHeads{}, Digest{}, err
	}
	if !sessionID.Valid() {
		return ApplyHeads{}, Digest{}, errors.New(
			"initial session ID is invalid",
		)
	}
	genesis, err := readGenesisBoundary(conn, 0, sessionID)
	if err != nil {
		return ApplyHeads{}, Digest{}, err
	}
	genesisDigest, err := chain.GenesisDigest(genesis.genesisJSON)
	if err != nil || genesisDigest != chain.Digest(genesis.genesisDigest) {
		return ApplyHeads{}, Digest{}, errors.New(
			"initial genesis digest differs",
		)
	}
	eventSeed, err := chain.EventSeed(chain.Boundary{
		Genesis: genesisDigest,
	})
	if err != nil {
		return ApplyHeads{}, Digest{}, err
	}
	resultSeed, err := chain.ResultSeed(chain.Boundary{
		Genesis: genesisDigest,
	})
	if err != nil {
		return ApplyHeads{}, Digest{}, err
	}
	accumulator := chain.AccumulatorSeedInitial(
		genesisDigest,
		chain.Digest(genesis.stateDigest),
	)
	return ApplyHeads{
			ChainHash:             Digest(eventSeed),
			ResultHash:            Digest(resultSeed),
			ProjectionAccumulator: Digest(accumulator),
		},
		genesis.stateDigest,
		nil
}

func logicalSnapshotAttestationID(root logicalsnapshot.Root) string {
	canonical := root.CanonicalBytes()
	if len(canonical) == 0 {
		return ""
	}
	digest := sha256.Sum256(canonical)
	return "snapshot:" + codec.EncodeBase64URL(digest[:])
}

func requireNoStandaloneSnapshotRaftEvidence(conn *sqlite.Conn) error {
	var count int64
	if err := queryOne(
		conn,
		`SELECT
		    (SELECT count(*) FROM event_provenance) +
		    (SELECT count(*) FROM raft_command_applications) +
		    (SELECT count(*) FROM raft_snapshot_installs) +
		    (SELECT count(*) FROM raft_committed_configuration) +
		    (SELECT count(*) FROM consensus_state
		      WHERE current_term IS NOT NULL
		         OR last_raft_applied_log_index IS NOT NULL);`,
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if count != 0 {
		return logicalSnapshotInstallError(
			"standalone import created or retained Raft evidence",
			nil,
		)
	}
	return nil
}

func checkForeignKeys(conn *sqlite.Conn) error {
	var count int64
	if err := query(
		conn,
		"PRAGMA foreign_key_check;",
		func(*sqlite.Stmt) {
			count++
		},
	); err != nil {
		return err
	}
	if count != 0 {
		return logicalSnapshotInstallError(
			"installed state violates foreign keys",
			nil,
		)
	}
	return nil
}

func logicalSnapshotInstallError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrLogicalSnapshotInstall, detail)
	}
	return fmt.Errorf("%w: %s: %w", ErrLogicalSnapshotInstall, detail, cause)
}
