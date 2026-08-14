package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// InitialState is a verified generation-zero genesis record and the complete
// projection baseline it defines. Genesis signature and semantic validation
// belongs to the identity/bootstrap layer; the store independently binds the
// canonical record, logical state digest, and all commitment seeds atomically.
type InitialState struct {
	SessionID               domain.UUIDv7
	WorkspaceID             domain.UUIDv4
	GenesisJSON             []byte
	Projections             ProjectionWrites
	DigestVersion           uint64
	ProjectionSchemaVersion uint64
}

func (initial InitialState) validate() error {
	if !initial.SessionID.Valid() || !initial.WorkspaceID.Valid() {
		return fmt.Errorf("%w: invalid initial lineage identity", ErrInvalidApply)
	}
	if initial.DigestVersion < 1 ||
		initial.ProjectionSchemaVersion < 1 ||
		!domain.ValidUnsignedInteger(initial.DigestVersion) ||
		!domain.ValidUnsignedInteger(initial.ProjectionSchemaVersion) {
		return fmt.Errorf("%w: invalid projection versions", ErrInvalidApply)
	}
	return validateGenesisBinding(
		initial.GenesisJSON,
		initial.SessionID,
		initial.WorkspaceID,
		0,
	)
}

func validateGenesisBinding(
	genesisJSON []byte,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	recoveryGeneration uint64,
) error {
	canonical, err := codec.CanonicalizeSignedObject(genesisJSON)
	if err != nil || !bytes.Equal(canonical, genesisJSON) {
		return fmt.Errorf("%w: genesis JSON is not canonical: %v", ErrInvalidApply, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(genesisJSON, &members); err != nil {
		return fmt.Errorf("%w: decode genesis JSON: %v", ErrInvalidApply, err)
	}
	if err := requireGenesisString(members, "session_id", string(sessionID)); err != nil {
		return err
	}
	if err := requireGenesisString(
		members,
		"workspace_id",
		string(workspaceID),
	); err != nil {
		return err
	}
	var encodedGeneration uint64
	rawGeneration, exists := members["recovery_generation"]
	if !exists ||
		json.Unmarshal(rawGeneration, &encodedGeneration) != nil ||
		encodedGeneration != recoveryGeneration {
		return fmt.Errorf(
			"%w: genesis recovery_generation does not match typed value",
			ErrInvalidApply,
		)
	}
	return nil
}

// SuccessorState is a verified successor genesis plus the complete
// post-transform covered projection snapshot. Callers must perform §3.1's
// semantic recovery transform and signature checks before invoking the store.
type SuccessorState struct {
	SessionID                 domain.UUIDv7
	WorkspaceID               domain.UUIDv4
	RecoveryGeneration        uint64
	GenesisJSON               []byte
	RecoveryAuthorizationJSON []byte
	Predecessor               ApplyHeads
	Projections               ProjectionWrites
	DigestVersion             uint64
	ProjectionSchemaVersion   uint64
}

type successorGenesisBinding struct {
	predecessorGenesisDigest    Digest
	predecessorChainIndex       uint64
	predecessorChainHash        Digest
	predecessorResultIndex      uint64
	predecessorResultHash       Digest
	predecessorAccumulator      Digest
	postTransformStateDigest    Digest
	digestVersion               uint64
	projectionSchemaVersion     uint64
	recoveringIdentitySignature Signature
	quorumRecoverySignature     Signature
}

func (successor SuccessorState) validate() error {
	if !successor.SessionID.Valid() ||
		!successor.WorkspaceID.Valid() ||
		successor.RecoveryGeneration < 1 ||
		!domain.ValidUnsignedInteger(successor.RecoveryGeneration) {
		return fmt.Errorf("%w: invalid successor lineage identity", ErrInvalidApply)
	}
	if successor.DigestVersion < 1 ||
		successor.ProjectionSchemaVersion < 1 ||
		!domain.ValidUnsignedInteger(successor.DigestVersion) ||
		!domain.ValidUnsignedInteger(successor.ProjectionSchemaVersion) {
		return fmt.Errorf("%w: invalid successor projection versions", ErrInvalidApply)
	}
	if successor.Predecessor.ChainIndex >
		successor.Predecessor.ResultIndex ||
		!domain.ValidUnsignedInteger(successor.Predecessor.ChainIndex) ||
		!domain.ValidUnsignedInteger(successor.Predecessor.ResultIndex) {
		return fmt.Errorf("%w: invalid predecessor heads", ErrInvalidApply)
	}
	if err := validateGenesisBinding(
		successor.GenesisJSON,
		successor.SessionID,
		successor.WorkspaceID,
		successor.RecoveryGeneration,
	); err != nil {
		return err
	}
	binding, err := parseSuccessorGenesisBinding(successor.GenesisJSON)
	if err != nil {
		return err
	}
	if binding.predecessorChainIndex != successor.Predecessor.ChainIndex ||
		binding.predecessorChainHash != successor.Predecessor.ChainHash ||
		binding.predecessorResultIndex != successor.Predecessor.ResultIndex ||
		binding.predecessorResultHash != successor.Predecessor.ResultHash ||
		binding.predecessorAccumulator !=
			successor.Predecessor.ProjectionAccumulator ||
		binding.digestVersion != successor.DigestVersion ||
		binding.projectionSchemaVersion !=
			successor.ProjectionSchemaVersion {
		return fmt.Errorf(
			"%w: successor genesis commitment fields disagree with typed state",
			ErrInvalidApply,
		)
	}
	canonical, err := codec.CanonicalizeSignedObject(
		successor.RecoveryAuthorizationJSON,
	)
	if err != nil ||
		!bytes.Equal(canonical, successor.RecoveryAuthorizationJSON) {
		return fmt.Errorf(
			"%w: recovery authorization JSON is not canonical: %v",
			ErrInvalidApply,
			err,
		)
	}
	return nil
}

func parseSuccessorGenesisBinding(
	genesisJSON []byte,
) (successorGenesisBinding, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(genesisJSON, &members); err != nil {
		return successorGenesisBinding{}, fmt.Errorf(
			"%w: decode successor genesis: %v",
			ErrInvalidApply,
			err,
		)
	}
	var (
		result successorGenesisBinding
		err    error
	)
	if result.predecessorGenesisDigest, err = requireGenesisDigest(
		members,
		"predecessor_genesis_digest",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	if result.predecessorChainIndex, err = requireGenesisUint(
		members,
		"predecessor_chain_index",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	if result.predecessorChainHash, err = requireGenesisDigest(
		members,
		"predecessor_chain_hash",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	if result.predecessorResultIndex, err = requireGenesisUint(
		members,
		"predecessor_result_index",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	if result.predecessorResultHash, err = requireGenesisDigest(
		members,
		"predecessor_result_hash",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	if result.predecessorAccumulator, err = requireGenesisDigest(
		members,
		"predecessor_projection_accumulator",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	if result.postTransformStateDigest, err = requireGenesisDigest(
		members,
		"post_transform_state_digest",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	if result.digestVersion, err = requireGenesisUint(
		members,
		"digest_version",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	if result.projectionSchemaVersion, err = requireGenesisUint(
		members,
		"projection_schema_version",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	if result.recoveringIdentitySignature, err = requireGenesisSignature(
		members,
		"recovering_identity_signature",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	if result.quorumRecoverySignature, err = requireGenesisSignature(
		members,
		"quorum_recovery_signature",
	); err != nil {
		return successorGenesisBinding{}, err
	}
	return result, nil
}

func requireGenesisUint(
	members map[string]json.RawMessage,
	name string,
) (uint64, error) {
	var value uint64
	raw, exists := members[name]
	if !exists ||
		json.Unmarshal(raw, &value) != nil ||
		!domain.ValidUnsignedInteger(value) {
		return 0, fmt.Errorf(
			"%w: successor genesis %s is not an exact unsigned integer",
			ErrInvalidApply,
			name,
		)
	}
	return value, nil
}

func requireGenesisDigest(
	members map[string]json.RawMessage,
	name string,
) (Digest, error) {
	var text string
	raw, exists := members[name]
	if !exists || json.Unmarshal(raw, &text) != nil {
		return Digest{}, fmt.Errorf(
			"%w: successor genesis %s is not a digest",
			ErrInvalidApply,
			name,
		)
	}
	value, err := codec.DecodeBase64URLExact(text, len(Digest{}))
	if err != nil {
		return Digest{}, fmt.Errorf(
			"%w: successor genesis %s: %v",
			ErrInvalidApply,
			name,
			err,
		)
	}
	var digest Digest
	copy(digest[:], value)
	return digest, nil
}

func requireGenesisSignature(
	members map[string]json.RawMessage,
	name string,
) (Signature, error) {
	var text string
	raw, exists := members[name]
	if !exists || json.Unmarshal(raw, &text) != nil {
		return Signature{}, fmt.Errorf(
			"%w: successor genesis %s is not a signature",
			ErrInvalidApply,
			name,
		)
	}
	value, err := codec.DecodeBase64URLExact(text, len(Signature{}))
	if err != nil {
		return Signature{}, fmt.Errorf(
			"%w: successor genesis %s: %v",
			ErrInvalidApply,
			name,
			err,
		)
	}
	var signature Signature
	copy(signature[:], value)
	return signature, nil
}

func requireGenesisString(
	members map[string]json.RawMessage,
	name string,
	want string,
) error {
	var got string
	raw, exists := members[name]
	if !exists || json.Unmarshal(raw, &got) != nil || got != want {
		return fmt.Errorf(
			"%w: genesis %s does not match typed value",
			ErrInvalidApply,
			name,
		)
	}
	return nil
}

// Initialize commits one generation-zero boundary. It refuses to infer a
// seed from the first command: a store must have an explicit genesis and
// projection baseline before Raft apply begins.
func (store *Store) Initialize(
	ctx context.Context,
	initial InitialState,
) (ApplyHeads, error) {
	if err := initial.validate(); err != nil {
		return ApplyHeads{}, err
	}
	prepared, err := prepareProjectionWrites(initial.Projections)
	if err != nil {
		return ApplyHeads{}, err
	}
	genesisDigest, err := chain.GenesisDigest(initial.GenesisJSON)
	if err != nil {
		return ApplyHeads{}, fmt.Errorf("%w: genesis digest: %v", ErrInvalidApply, err)
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	var heads ApplyHeads
	err = store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		end, err := sqlitex.ImmediateTransaction(conn)
		if err != nil {
			return err
		}
		defer end(&err)

		if _, found, err := readConsensusState(conn); err != nil {
			return err
		} else if found {
			return fmt.Errorf("%w: store is already initialized", ErrApplyConflict)
		}
		var genesisCount int64
		if err := queryOne(
			conn,
			"SELECT count(*) FROM genesis_records;",
			func(stmt *sqlite.Stmt) {
				genesisCount = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if genesisCount != 0 {
			return fmt.Errorf(
				"%w: genesis history exists without consensus state",
				ErrIntegrityCheck,
			)
		}
		if err := assertCoveredTablesEmpty(conn); err != nil {
			return err
		}
		if err := writePreparedProjections(conn, prepared); err != nil {
			return err
		}
		if err := ensurePendingControlFileApprovals(
			conn,
			initial.SessionID,
			prepared.controlFileProposalRows,
		); err != nil {
			return err
		}
		stateDigest, err := projectionStateDigest(conn, chain.Versions{
			Digest:           initial.DigestVersion,
			ProjectionSchema: initial.ProjectionSchemaVersion,
		})
		if err != nil {
			return err
		}
		eventSeed, err := chain.EventSeed(chain.Boundary{
			Genesis: genesisDigest,
		})
		if err != nil {
			return err
		}
		resultSeed, err := chain.ResultSeed(chain.Boundary{
			Genesis: genesisDigest,
		})
		if err != nil {
			return err
		}
		accumulator := chain.AccumulatorSeedInitial(
			genesisDigest,
			chain.Digest(stateDigest),
		)
		heads = ApplyHeads{
			ChainHash:               Digest(eventSeed),
			ResultHash:              Digest(resultSeed),
			ProjectionAccumulator:   Digest(accumulator),
			DigestVersion:           initial.DigestVersion,
			ProjectionSchemaVersion: initial.ProjectionSchemaVersion,
		}
		if err := execute(
			conn,
			`INSERT INTO genesis_records(
			    recovery_generation, session_id, workspace_id, genesis_kind,
			    genesis_json, genesis_digest, recovery_authorization_json,
			    predecessor_chain_index, predecessor_chain_hash,
			    predecessor_result_index, predecessor_result_hash,
			    predecessor_projection_accumulator,
			    boundary_transform_digest
			) VALUES (
			    0, ?1, ?2, 'initial', ?3, ?4, NULL,
			    NULL, NULL, NULL, NULL, NULL, ?5
			);`,
			string(initial.SessionID),
			string(initial.WorkspaceID),
			string(initial.GenesisJSON),
			genesisDigest[:],
			stateDigest[:],
		); err != nil {
			return err
		}
		return writeBoundaryConsensusState(conn, initial, heads)
	})
	return heads, err
}

// InstallSuccessor atomically replaces covered projections with a verified
// §3.1 post-transform snapshot, records its signed successor genesis, and
// reseeds all commitments without restarting dense indices.
func (store *Store) InstallSuccessor(
	ctx context.Context,
	successor SuccessorState,
) (ApplyHeads, error) {
	if err := successor.validate(); err != nil {
		return ApplyHeads{}, err
	}
	prepared, err := prepareProjectionWrites(successor.Projections)
	if err != nil {
		return ApplyHeads{}, err
	}
	genesisDigest, err := chain.GenesisDigest(successor.GenesisJSON)
	if err != nil {
		return ApplyHeads{}, fmt.Errorf("%w: genesis digest: %v", ErrInvalidApply, err)
	}
	genesisBinding, err := parseSuccessorGenesisBinding(
		successor.GenesisJSON,
	)
	if err != nil {
		return ApplyHeads{}, err
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	var heads ApplyHeads
	err = store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
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
				"%w: successor requires an initialized predecessor",
				ErrApplyConflict,
			)
		}
		if successor.RecoveryGeneration != prior.recoveryGeneration+1 ||
			successor.SessionID == prior.sessionID ||
			!sameCommitmentHeads(
				successor.Predecessor,
				headsFromConsensus(prior),
			) ||
			successor.DigestVersion != prior.digestVersion ||
			successor.ProjectionSchemaVersion !=
				prior.projectionSchemaVersion {
			return fmt.Errorf(
				"%w: successor does not extend the current boundary",
				ErrApplyConflict,
			)
		}
		var (
			predecessorWorkspace     string
			predecessorGenesisDigest Digest
			predecessorRowErr        error
		)
		if err := queryOneArgs(
			conn,
			`SELECT workspace_id, genesis_digest FROM genesis_records
			  WHERE recovery_generation = ?1 AND session_id = ?2;`,
			[]any{prior.recoveryGeneration, string(prior.sessionID)},
			func(stmt *sqlite.Stmt) {
				predecessorWorkspace = stmt.ColumnText(0)
				predecessorRowErr = copyDigestColumn(
					&predecessorGenesisDigest,
					stmt,
					1,
				)
			},
		); err != nil {
			return err
		}
		if predecessorRowErr != nil {
			return commitmentIntegrityError(
				"invalid predecessor genesis digest",
				predecessorRowErr,
			)
		}
		if predecessorWorkspace != string(successor.WorkspaceID) {
			return fmt.Errorf(
				"%w: successor changed workspace identity",
				ErrApplyConflict,
			)
		}
		if predecessorGenesisDigest !=
			genesisBinding.predecessorGenesisDigest {
			return fmt.Errorf(
				"%w: successor genesis names another predecessor genesis",
				ErrApplyConflict,
			)
		}

		if err := replaceCoveredProjections(conn, prepared); err != nil {
			return err
		}
		if err := ensurePendingControlFileApprovals(
			conn,
			successor.SessionID,
			prepared.controlFileProposalRows,
		); err != nil {
			return err
		}
		if err := clearGenerationLocalState(conn); err != nil {
			return err
		}
		stateDigest, err := projectionStateDigest(conn, chain.Versions{
			Digest:           successor.DigestVersion,
			ProjectionSchema: successor.ProjectionSchemaVersion,
		})
		if err != nil {
			return err
		}
		if stateDigest != genesisBinding.postTransformStateDigest {
			return fmt.Errorf(
				"%w: successor post-transform digest disagrees with genesis",
				ErrApplyConflict,
			)
		}
		eventSeed, err := chain.EventSeed(chain.Boundary{
			Genesis:     genesisDigest,
			Generation:  successor.RecoveryGeneration,
			ChainIndex:  prior.chainIndex,
			ResultIndex: prior.resultIndex,
			ChainHash:   chain.Digest(prior.chainHash),
			ResultHash:  chain.Digest(prior.resultHash),
		})
		if err != nil {
			return err
		}
		resultSeed, err := chain.ResultSeed(chain.Boundary{
			Genesis:     genesisDigest,
			Generation:  successor.RecoveryGeneration,
			ChainIndex:  prior.chainIndex,
			ResultIndex: prior.resultIndex,
			ChainHash:   chain.Digest(prior.chainHash),
			ResultHash:  chain.Digest(prior.resultHash),
		})
		if err != nil {
			return err
		}
		accumulator := chain.AccumulatorSeedSuccessor(
			chain.Digest(prior.projectionAccumulator),
			genesisDigest,
			chain.Digest(stateDigest),
		)
		heads = ApplyHeads{
			ChainIndex:              prior.chainIndex,
			ChainHash:               Digest(eventSeed),
			ResultIndex:             prior.resultIndex,
			ResultHash:              Digest(resultSeed),
			ProjectionAccumulator:   Digest(accumulator),
			DigestVersion:           successor.DigestVersion,
			ProjectionSchemaVersion: successor.ProjectionSchemaVersion,
		}
		if err := execute(
			conn,
			`INSERT INTO genesis_records(
			    recovery_generation, session_id, workspace_id, genesis_kind,
			    genesis_json, genesis_digest, recovery_authorization_json,
			    predecessor_chain_index, predecessor_chain_hash,
			    predecessor_result_index, predecessor_result_hash,
			    predecessor_projection_accumulator,
			    boundary_transform_digest
			) VALUES (
			    ?1, ?2, ?3, 'successor', ?4, ?5, ?6, ?7, ?8, ?9, ?10,
			    ?11, ?12
			);`,
			successor.RecoveryGeneration,
			string(successor.SessionID),
			string(successor.WorkspaceID),
			string(successor.GenesisJSON),
			genesisDigest[:],
			string(successor.RecoveryAuthorizationJSON),
			prior.chainIndex,
			prior.chainHash[:],
			prior.resultIndex,
			prior.resultHash[:],
			prior.projectionAccumulator[:],
			stateDigest[:],
		); err != nil {
			return err
		}
		return writeSuccessorConsensusState(conn, successor, heads)
	})
	return heads, err
}

func sameCommitmentHeads(left, right ApplyHeads) bool {
	return left.ChainIndex == right.ChainIndex &&
		left.ChainHash == right.ChainHash &&
		left.ResultIndex == right.ResultIndex &&
		left.ResultHash == right.ResultHash &&
		left.ProjectionAccumulator == right.ProjectionAccumulator &&
		left.DigestVersion == right.DigestVersion &&
		left.ProjectionSchemaVersion == right.ProjectionSchemaVersion
}

func replaceCoveredProjections(
	conn *sqlite.Conn,
	prepared preparedProjectionWrites,
) error {
	for index := len(projectionTables) - 1; index >= 0; index-- {
		if err := execute(
			conn,
			"DELETE FROM "+projectionTables[index].name+";",
		); err != nil {
			return fmt.Errorf(
				"store: clear %s for successor: %w",
				projectionTables[index].name,
				err,
			)
		}
	}
	return writePreparedProjections(conn, prepared)
}

func clearGenerationLocalState(conn *sqlite.Conn) error {
	// Pairing rows are retained as idempotency evidence, but predecessor
	// secrets and unfinished attempts cannot remain live across the boundary.
	if err := queueGenerationPairingCleanup(conn); err != nil {
		return fmt.Errorf("store: queue predecessor pairing cleanup: %w", err)
	}
	if err := execute(
		conn,
		`DELETE FROM pairing_attempts
		  WHERE state = 'proof_rejected'
		    AND invite_id IN (
		        SELECT invite_id FROM pairing_invites
		         WHERE state IN ('preparing', 'outstanding')
		    );`,
	); err != nil {
		return fmt.Errorf("store: scrub predecessor pairing failures: %w", err)
	}
	if err := execute(
		conn,
		`UPDATE pairing_attempts
		    SET state = 'revoked',
		        terminal_at = coalesce(
		            terminal_at,
		            local_confirmed_at,
		            remote_confirmed_at,
		            created_at
		        )
		  WHERE state = 'awaiting_sas'
		     OR (state = 'confirmed' AND EXISTS (
		            SELECT 1
		              FROM pairing_attempt_finalizations AS finalizations
		             WHERE finalizations.attempt_id = pairing_attempts.attempt_id
		               AND finalizations.state = 'finalizing'
		        ));`,
	); err != nil {
		return fmt.Errorf("store: revoke predecessor pairing attempts: %w", err)
	}
	if err := execute(
		conn,
		`DELETE FROM pairing_attempt_finalizations WHERE state = 'finalizing';`,
	); err != nil {
		return fmt.Errorf("store: clear predecessor pairing finalizations: %w", err)
	}
	if err := execute(
		conn,
		`UPDATE pairing_invites
		    SET state = 'abandoned',
		        terminal_at = (
		            SELECT queued_at
		              FROM pairing_secret_deletions
		             WHERE pairing_secret_deletions.invite_id =
		                   pairing_invites.invite_id
		        )
		  WHERE state IN ('preparing', 'outstanding');`,
	); err != nil {
		return fmt.Errorf("store: abandon predecessor pairing invites: %w", err)
	}
	for _, table := range []string{
		"agent_resume_tokens",
		"agent_launches",
		"managed_roots",
		"peer_acks",
		"peer_endpoints",
		"lease_deadlines",
		"replication_cursors",
		"outbox",
		"local_requests",
		"owner_recovery_challenges",
		"origin_counters",
	} {
		if err := execute(conn, "DELETE FROM "+table+";"); err != nil {
			return fmt.Errorf(
				"store: clear generation-local table %s: %w",
				table,
				err,
			)
		}
	}
	return nil
}

type generationPairingCleanup struct {
	inviteID  domain.UUIDv7
	sessionID domain.UUIDv7
	queuedAt  domain.Timestamp
}

func queueGenerationPairingCleanup(conn *sqlite.Conn) error {
	var (
		candidates []generationPairingCleanup
		indexes    = make(map[domain.UUIDv7]int)
		rowErr     error
	)
	if err := queryArgs(
		conn,
		`SELECT invites.invite_id, invites.session_id, invites.created_at,
		        attempts.terminal_at
		   FROM pairing_invites AS invites
		   LEFT JOIN pairing_attempts AS attempts
		     ON attempts.invite_id = invites.invite_id
		    AND attempts.state = 'proof_rejected'
		  WHERE invites.state IN ('preparing', 'outstanding')
		  ORDER BY invites.invite_id, attempts.attempt_id;`,
		nil,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			inviteID := domain.UUIDv7(stmt.ColumnText(0))
			sessionID := domain.UUIDv7(stmt.ColumnText(1))
			createdAt := domain.Timestamp(stmt.ColumnText(2))
			if !inviteID.Valid() || !sessionID.Valid() || !createdAt.Valid() {
				rowErr = ErrPairingStateIntegrity
				return
			}
			index, found := indexes[inviteID]
			if !found {
				index = len(candidates)
				indexes[inviteID] = index
				candidates = append(candidates, generationPairingCleanup{
					inviteID:  inviteID,
					sessionID: sessionID,
					queuedAt:  createdAt,
				})
			} else if candidates[index].sessionID != sessionID {
				rowErr = ErrPairingStateIntegrity
				return
			}
			if stmt.ColumnType(3) == sqlite.TypeNull {
				return
			}
			observedAt := domain.Timestamp(stmt.ColumnText(3))
			if !observedAt.Valid() {
				rowErr = ErrPairingStateIntegrity
				return
			}
			beforeCreated, err := timestampBefore(observedAt, createdAt)
			if err != nil || beforeCreated {
				rowErr = ErrPairingStateIntegrity
				return
			}
			latestBeforeObserved, err := timestampBefore(
				candidates[index].queuedAt,
				observedAt,
			)
			if err != nil {
				rowErr = ErrPairingStateIntegrity
				return
			}
			if latestBeforeObserved {
				candidates[index].queuedAt = observedAt
			}
		},
	); err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	for _, candidate := range candidates {
		if err := execute(
			conn,
			`INSERT INTO pairing_secret_deletions(
			    invite_id, session_id, reason, queued_at, failure_count
			) VALUES (?1, ?2, 'generation_changed', ?3, 0)
			ON CONFLICT(invite_id) DO NOTHING;`,
			string(candidate.inviteID),
			string(candidate.sessionID),
			string(candidate.queuedAt),
		); err != nil {
			return err
		}
		record, found, err := readPairingSecretDeletion(conn, candidate.inviteID)
		if err != nil {
			return err
		}
		if !found ||
			record.SessionID != candidate.sessionID ||
			record.Reason != "generation_changed" ||
			record.QueuedAt != candidate.queuedAt ||
			record.FailureCount != 0 {
			return ErrPairingStateIntegrity
		}
	}
	return nil
}

func assertCoveredTablesEmpty(conn *sqlite.Conn) error {
	for _, table := range projectionTables {
		var count int64
		if err := queryOne(
			conn,
			"SELECT count(*) FROM "+table.name+";",
			func(stmt *sqlite.Stmt) {
				count = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf(
				"%w: covered table %s is nonempty before initialization",
				ErrIntegrityCheck,
				table.name,
			)
		}
	}
	return nil
}

func writeSuccessorConsensusState(
	conn *sqlite.Conn,
	successor SuccessorState,
	heads ApplyHeads,
) error {
	return execute(
		conn,
		`UPDATE consensus_state SET
		    session_id = ?1,
		    recovery_generation = ?2,
		    current_term = NULL,
		    last_raft_applied_log_index = NULL,
		    chain_index = ?3,
		    chain_hash = ?4,
		    result_index = ?5,
		    result_hash = ?6,
		    projection_accumulator = ?7,
		    digest_version = ?8,
		    projection_schema_version = ?9
		  WHERE singleton = 1;`,
		string(successor.SessionID),
		successor.RecoveryGeneration,
		heads.ChainIndex,
		heads.ChainHash[:],
		heads.ResultIndex,
		heads.ResultHash[:],
		heads.ProjectionAccumulator[:],
		heads.DigestVersion,
		heads.ProjectionSchemaVersion,
	)
}

func writeBoundaryConsensusState(
	conn *sqlite.Conn,
	initial InitialState,
	heads ApplyHeads,
) error {
	if heads.ChainIndex != 0 || heads.ResultIndex != 0 {
		return errors.New("store: initial boundary has nonzero position")
	}
	return execute(
		conn,
		`INSERT INTO consensus_state(
		    singleton, session_id, recovery_generation, current_term,
		    last_raft_applied_log_index, chain_index, chain_hash,
		    result_index, result_hash, projection_accumulator,
		    digest_version, projection_schema_version
		) VALUES (1, ?1, 0, NULL, NULL, 0, ?2, 0, ?3, ?4, ?5, ?6);`,
		string(initial.SessionID),
		heads.ChainHash[:],
		heads.ResultHash[:],
		heads.ProjectionAccumulator[:],
		heads.DigestVersion,
		heads.ProjectionSchemaVersion,
	)
}
