package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrRaftSnapshotInstall = errors.New(
	"store: Raft snapshot installation failed",
)

type raftSnapshotInstallRecord struct {
	sessionID               domain.UUIDv7
	workspaceID             domain.UUIDv4
	recoveryGeneration      uint64
	sourceServerID          domain.DeviceID
	snapshotID              string
	snapshotIndex           uint64
	snapshotTerm            uint64
	configurationIndex      uint64
	configurationDigest     Digest
	payloadDigest           Digest
	baselineCommandLogIndex uint64
	baselineCommandTerm     uint64
	hasBaselineCommand      bool
	heads                   ApplyHeads
	projectionStateDigest   Digest
	installedAt             domain.Timestamp
}

// RaftSnapshotInstallRecord is the verified receiver-local baseline for one
// successfully installed Raft snapshot. SnapshotID is local to this replica.
type RaftSnapshotInstallRecord struct {
	SessionID               domain.UUIDv7
	WorkspaceID             domain.UUIDv4
	RecoveryGeneration      uint64
	SourceServerID          domain.DeviceID
	SnapshotID              string
	SnapshotIndex           uint64
	SnapshotTerm            uint64
	ConfigurationIndex      uint64
	ConfigurationDigest     Digest
	PayloadDigest           Digest
	BaselineCommandLogIndex *uint64
	BaselineCommandTerm     *uint64
	Heads                   ApplyHeads
	ProjectionStateDigest   Digest
	InstalledAt             domain.Timestamp
}

// RaftSnapshotInstallRebindOptions identifies an exact replay of a snapshot
// whose prior installation may have completed after the sender timed out.
// The caller must have reverified the finalized snapshot frame and payload
// digest before requesting the receiver-local snapshot ID change.
type RaftSnapshotInstallRebindOptions struct {
	SourceServerID          domain.DeviceID
	SnapshotID              string
	SnapshotIndex           uint64
	SnapshotTerm            uint64
	ConfigurationIndex      uint64
	ConfigurationDigest     Digest
	PayloadDigest           Digest
	BaselineCommandLogIndex *uint64
	BaselineCommandTerm     *uint64
}

// VerifiedRaftSnapshotInstall returns the active generation's exact installed
// baseline after revalidating its signed logical root and durable bindings.
func (store *Store) VerifiedRaftSnapshotInstall(
	ctx context.Context,
) (RaftSnapshotInstallRecord, bool, error) {
	if store == nil || ctx == nil {
		return RaftSnapshotInstallRecord{}, false,
			fmt.Errorf("%w: invalid Raft snapshot query", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return RaftSnapshotInstallRecord{}, false, err
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	var (
		result RaftSnapshotInstallRecord
		found  bool
	)
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end := sqlitex.Transaction(conn)
		defer end(&err)

		state, active, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !active {
			return raftSnapshotInstallError(
				"active consensus state is missing",
				nil,
			)
		}
		record, exists, err := validateRaftSnapshotInstallBinding(
			conn,
			state,
		)
		if err != nil || !exists {
			return err
		}
		if err := verifyRaftSnapshotInstallEvidence(conn, state); err != nil {
			return err
		}
		result = exportRaftSnapshotInstallRecord(record)
		found = true
		return nil
	})
	if err != nil {
		return RaftSnapshotInstallRecord{}, false, err
	}
	return result, found, nil
}

// RebindVerifiedRaftSnapshotInstall atomically binds a newly finalized local
// snapshot file to an otherwise byte-identical installed baseline. It returns
// matched=false without mutation when the active state or any metadata differs.
func (store *Store) RebindVerifiedRaftSnapshotInstall(
	ctx context.Context,
	options RaftSnapshotInstallRebindOptions,
) (RaftSnapshotInstallRecord, bool, error) {
	if store == nil || ctx == nil {
		return RaftSnapshotInstallRecord{}, false,
			fmt.Errorf("%w: invalid Raft snapshot rebind", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return RaftSnapshotInstallRecord{}, false, err
	}
	if err := validateRaftSnapshotInstallRebindOptions(options); err != nil {
		return RaftSnapshotInstallRecord{}, false, err
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	var (
		result  RaftSnapshotInstallRecord
		matched bool
	)
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end, err := sqlitex.ImmediateTransaction(conn)
		if err != nil {
			return err
		}
		defer end(&err)

		state, active, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !active {
			return raftSnapshotInstallError(
				"active consensus state is missing",
				nil,
			)
		}
		record, found, err := validateRaftSnapshotInstallBinding(
			conn,
			state,
		)
		if err != nil || !found {
			return err
		}
		if err := verifyRaftSnapshotInstallEvidence(conn, state); err != nil {
			return err
		}
		matches, err := raftSnapshotInstallRebindMatches(
			conn,
			state,
			record,
			options,
		)
		if err != nil {
			return err
		}
		if !matches {
			return nil
		}
		if record.snapshotID != options.SnapshotID {
			if err := execute(
				conn,
				`UPDATE raft_snapshot_installs
				    SET snapshot_id = ?1
				  WHERE session_id = ?2
				    AND recovery_generation = ?3
				    AND snapshot_id = ?4;`,
				options.SnapshotID,
				string(record.sessionID),
				record.recoveryGeneration,
				record.snapshotID,
			); err != nil {
				return raftSnapshotInstallError(
					"rebind receiver-local snapshot ID",
					err,
				)
			}
			var changes int64
			if err := queryOne(
				conn,
				"SELECT changes();",
				func(stmt *sqlite.Stmt) {
					if stmt.ColumnType(0) != sqlite.TypeInteger {
						changes = -1
						return
					}
					changes = stmt.ColumnInt64(0)
				},
			); err != nil {
				return err
			}
			if changes != 1 {
				return raftSnapshotInstallError(
					"snapshot ID rebind changed an unexpected row count",
					nil,
				)
			}
		}
		rebound, found, err := validateRaftSnapshotInstallBinding(
			conn,
			state,
		)
		if err != nil || !found {
			return err
		}
		if rebound.snapshotID != options.SnapshotID {
			return raftSnapshotInstallError(
				"snapshot ID rebind was not durable",
				nil,
			)
		}
		if err := verifyRaftSnapshotInstallEvidence(conn, state); err != nil {
			return err
		}
		result = exportRaftSnapshotInstallRecord(rebound)
		matched = true
		return nil
	})
	if err != nil {
		return RaftSnapshotInstallRecord{}, false, err
	}
	return result, matched, nil
}

func exportRaftSnapshotInstallRecord(
	record raftSnapshotInstallRecord,
) RaftSnapshotInstallRecord {
	result := RaftSnapshotInstallRecord{
		SessionID:             record.sessionID,
		WorkspaceID:           record.workspaceID,
		RecoveryGeneration:    record.recoveryGeneration,
		SourceServerID:        record.sourceServerID,
		SnapshotID:            record.snapshotID,
		SnapshotIndex:         record.snapshotIndex,
		SnapshotTerm:          record.snapshotTerm,
		ConfigurationIndex:    record.configurationIndex,
		ConfigurationDigest:   record.configurationDigest,
		PayloadDigest:         record.payloadDigest,
		Heads:                 record.heads,
		ProjectionStateDigest: record.projectionStateDigest,
		InstalledAt:           record.installedAt,
	}
	if record.hasBaselineCommand {
		index := record.baselineCommandLogIndex
		term := record.baselineCommandTerm
		result.BaselineCommandLogIndex = &index
		result.BaselineCommandTerm = &term
	}
	return result
}

func validateRaftSnapshotInstallRebindOptions(
	options RaftSnapshotInstallRebindOptions,
) error {
	if !options.SourceServerID.Valid() ||
		!validRaftSnapshotInstallID(options.SnapshotID) ||
		options.SnapshotIndex < 1 ||
		!domain.ValidUnsignedInteger(options.SnapshotIndex) ||
		options.SnapshotTerm < 1 ||
		!domain.ValidUnsignedInteger(options.SnapshotTerm) ||
		options.ConfigurationIndex < 1 ||
		options.ConfigurationIndex > options.SnapshotIndex ||
		!domain.ValidUnsignedInteger(options.ConfigurationIndex) ||
		(options.BaselineCommandLogIndex == nil) !=
			(options.BaselineCommandTerm == nil) {
		return raftSnapshotInstallError("invalid rebind metadata", nil)
	}
	if options.BaselineCommandLogIndex != nil &&
		(*options.BaselineCommandLogIndex < 1 ||
			*options.BaselineCommandLogIndex > options.SnapshotIndex ||
			!domain.ValidUnsignedInteger(
				*options.BaselineCommandLogIndex,
			) ||
			*options.BaselineCommandTerm < 1 ||
			*options.BaselineCommandTerm > options.SnapshotTerm ||
			!domain.ValidUnsignedInteger(
				*options.BaselineCommandTerm,
			)) {
		return raftSnapshotInstallError("invalid rebind command position", nil)
	}
	return nil
}

func raftSnapshotInstallRebindMatches(
	conn *sqlite.Conn,
	state consensusState,
	record raftSnapshotInstallRecord,
	options RaftSnapshotInstallRebindOptions,
) (bool, error) {
	if conn == nil {
		return false, raftSnapshotInstallError(
			"nil rebind connection",
			nil,
		)
	}
	if record.sourceServerID != options.SourceServerID ||
		record.snapshotIndex != options.SnapshotIndex ||
		record.snapshotTerm != options.SnapshotTerm ||
		record.configurationIndex != options.ConfigurationIndex ||
		record.configurationDigest != options.ConfigurationDigest ||
		record.payloadDigest != options.PayloadDigest ||
		record.hasBaselineCommand !=
			(options.BaselineCommandLogIndex != nil) {
		return false, nil
	}
	if record.hasBaselineCommand &&
		(record.baselineCommandLogIndex !=
			*options.BaselineCommandLogIndex ||
			record.baselineCommandTerm !=
				*options.BaselineCommandTerm ||
			state.lastAppliedLogIndex !=
				record.baselineCommandLogIndex ||
			state.currentTerm != record.baselineCommandTerm) {
		return false, nil
	}
	if !record.hasBaselineCommand &&
		(state.lastAppliedLogIndex != 0 || state.currentTerm != 0) {
		return false, nil
	}
	if state.chainIndex != record.heads.ChainIndex ||
		state.chainHash != record.heads.ChainHash ||
		state.resultIndex != record.heads.ResultIndex ||
		state.resultHash != record.heads.ResultHash ||
		state.projectionAccumulator !=
			record.heads.ProjectionAccumulator ||
		state.digestVersion != record.heads.DigestVersion ||
		state.projectionSchemaVersion !=
			record.heads.ProjectionSchemaVersion {
		return false, nil
	}
	stateDigest, err := projectionStateDigest(conn, chain.Versions{
		Digest:           state.digestVersion,
		ProjectionSchema: state.projectionSchemaVersion,
	})
	if err != nil {
		return false, err
	}
	if stateDigest != record.projectionStateDigest {
		return false, nil
	}
	configuration, found, err := readRaftConfigurationRecord(conn)
	if err != nil {
		return false, err
	}
	return found &&
			configuration.SessionID == state.sessionID &&
			configuration.RecoveryGeneration == state.recoveryGeneration &&
			configuration.LogIndex == record.configurationIndex &&
			configuration.ConfigurationDigest == record.configurationDigest,
		nil
}

func validateRaftLogicalSnapshotInstallOptions(
	options RaftLogicalSnapshotInstallOptions,
	root logicalsnapshot.Root,
) error {
	if !options.VerifiedAt.Valid() ||
		!options.OriginBootID.Valid() ||
		!options.InstalledAt.Valid() ||
		options.MonotonicNowNS < 0 ||
		!options.SourceServerID.Valid() ||
		!validRaftSnapshotInstallID(options.SnapshotID) ||
		options.SnapshotIndex < 1 ||
		!domain.ValidUnsignedInteger(options.SnapshotIndex) ||
		options.SnapshotTerm < 1 ||
		!domain.ValidUnsignedInteger(options.SnapshotTerm) ||
		options.ConfigurationIndex < 1 ||
		options.ConfigurationIndex > options.SnapshotIndex ||
		!domain.ValidUnsignedInteger(options.ConfigurationIndex) ||
		len(options.ConfigurationJSON) == 0 ||
		len(options.ConfigurationJSON) > MaxRaftConfigurationBytes {
		return raftSnapshotInstallError("invalid metadata", nil)
	}
	canonical, err := codec.CanonicalizeSignedObject(
		options.ConfigurationJSON,
	)
	if err != nil ||
		!bytes.Equal(canonical, options.ConfigurationJSON) ||
		!json.Valid(options.ConfigurationJSON) ||
		Digest(sha256.Sum256(options.ConfigurationJSON)) !=
			options.ConfigurationDigest {
		return raftSnapshotInstallError(
			"invalid canonical configuration",
			err,
		)
	}
	if (options.BaselineCommandLogIndex == nil) !=
		(options.BaselineCommandTerm == nil) {
		return raftSnapshotInstallError(
			"partial baseline command position",
			nil,
		)
	}
	if options.BaselineCommandLogIndex != nil &&
		(*options.BaselineCommandLogIndex < 1 ||
			*options.BaselineCommandLogIndex > options.SnapshotIndex ||
			!domain.ValidUnsignedInteger(
				*options.BaselineCommandLogIndex,
			) ||
			*options.BaselineCommandTerm < 1 ||
			*options.BaselineCommandTerm > options.SnapshotTerm ||
			!domain.ValidUnsignedInteger(
				*options.BaselineCommandTerm,
			)) {
		return raftSnapshotInstallError(
			"invalid baseline command position",
			nil,
		)
	}
	input := root.Unsigned().Input()
	if len(root.CanonicalBytes()) == 0 ||
		input.SignerDeviceID != options.SourceServerID {
		return raftSnapshotInstallError(
			"source server differs from signed root",
			nil,
		)
	}
	return nil
}

func writeRaftLogicalSnapshotEvidence(
	conn *sqlite.Conn,
	cut LogicalSnapshotCut,
	options RaftLogicalSnapshotInstallOptions,
) error {
	if conn == nil {
		return raftSnapshotInstallError("nil connection", nil)
	}
	if err := execute(
		conn,
		`UPDATE consensus_state
		    SET current_term = ?1,
		        last_raft_applied_log_index = ?2
		  WHERE singleton = 1
		    AND session_id = ?3
		    AND recovery_generation = ?4;`,
		nullableUint64Pointer(options.BaselineCommandTerm),
		nullableUint64Pointer(options.BaselineCommandLogIndex),
		string(cut.SessionID),
		cut.RecoveryGeneration,
	); err != nil {
		return raftSnapshotInstallError(
			"write baseline command watermark",
			err,
		)
	}
	if err := execute(
		conn,
		`INSERT INTO raft_committed_configuration(
		    singleton, session_id, recovery_generation, log_index,
		    configuration_json, configuration_digest
		) VALUES (1, ?1, ?2, ?3, ?4, ?5);`,
		string(cut.SessionID),
		cut.RecoveryGeneration,
		options.ConfigurationIndex,
		string(options.ConfigurationJSON),
		options.ConfigurationDigest[:],
	); err != nil {
		return raftSnapshotInstallError(
			"write committed configuration baseline",
			err,
		)
	}
	if err := execute(
		conn,
		`INSERT INTO raft_snapshot_installs(
		    session_id, workspace_id, recovery_generation,
		    source_server_id, snapshot_id, snapshot_index, snapshot_term,
		    configuration_index, configuration_digest, payload_digest,
		    baseline_command_log_index, baseline_command_term,
		    chain_index, chain_hash, result_index, result_hash,
		    projection_accumulator, projection_state_digest,
		    digest_version, projection_schema_version, installed_at
		) VALUES (
		    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
		    ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
		);`,
		string(cut.SessionID),
		string(cut.WorkspaceID),
		cut.RecoveryGeneration,
		string(options.SourceServerID),
		options.SnapshotID,
		options.SnapshotIndex,
		options.SnapshotTerm,
		options.ConfigurationIndex,
		options.ConfigurationDigest[:],
		options.PayloadDigest[:],
		nullableUint64Pointer(options.BaselineCommandLogIndex),
		nullableUint64Pointer(options.BaselineCommandTerm),
		cut.ChainIndex,
		cut.ChainHash[:],
		cut.ResultIndex,
		cut.ResultHash[:],
		cut.ProjectionAccumulator[:],
		cut.ProjectionStateDigest[:],
		cut.DigestVersion,
		cut.ProjectionSchemaVersion,
		string(options.InstalledAt),
	); err != nil {
		return raftSnapshotInstallError("write install baseline", err)
	}
	return nil
}

func readRaftSnapshotInstallRecord(
	conn *sqlite.Conn,
) (raftSnapshotInstallRecord, bool, error) {
	var (
		record raftSnapshotInstallRecord
		count  int
		rowErr error
	)
	err := query(
		conn,
		`SELECT session_id, workspace_id, recovery_generation,
		        source_server_id, snapshot_id, snapshot_index, snapshot_term,
		        configuration_index, configuration_digest, payload_digest,
		        baseline_command_log_index, baseline_command_term,
		        chain_index, chain_hash, result_index, result_hash,
		        projection_accumulator, projection_state_digest,
		        digest_version, projection_schema_version, installed_at
		   FROM raft_snapshot_installs
		  ORDER BY recovery_generation, session_id;`,
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 || rowErr != nil {
				return
			}
			record.sessionID = domain.UUIDv7(stmt.ColumnText(0))
			record.workspaceID = domain.UUIDv4(stmt.ColumnText(1))
			record.sourceServerID = domain.DeviceID(stmt.ColumnText(3))
			record.snapshotID = stmt.ColumnText(4)
			record.installedAt = domain.Timestamp(stmt.ColumnText(20))
			numbers := []*uint64{
				&record.recoveryGeneration,
				&record.snapshotIndex,
				&record.snapshotTerm,
				&record.configurationIndex,
				&record.heads.ChainIndex,
				&record.heads.ResultIndex,
				&record.heads.DigestVersion,
				&record.heads.ProjectionSchemaVersion,
			}
			for index, column := range [...]int{
				2, 5, 6, 7, 12, 14, 18, 19,
			} {
				value := stmt.ColumnInt64(column)
				if value < 0 {
					rowErr = errors.New("negative snapshot number")
					return
				}
				*numbers[index] = uint64(value)
			}
			digests := []*Digest{
				&record.configurationDigest,
				&record.payloadDigest,
				&record.heads.ChainHash,
				&record.heads.ResultHash,
				&record.heads.ProjectionAccumulator,
				&record.projectionStateDigest,
			}
			for index, column := range [...]int{8, 9, 13, 15, 16, 17} {
				if rowErr = copyDigestColumn(
					digests[index],
					stmt,
					column,
				); rowErr != nil {
					return
				}
			}
			indexNull := stmt.ColumnType(10) == sqlite.TypeNull
			termNull := stmt.ColumnType(11) == sqlite.TypeNull
			if indexNull != termNull {
				rowErr = errors.New("partial snapshot command position")
				return
			}
			if !indexNull {
				index := stmt.ColumnInt64(10)
				term := stmt.ColumnInt64(11)
				if index < 1 || term < 1 {
					rowErr = errors.New("invalid snapshot command position")
					return
				}
				record.baselineCommandLogIndex = uint64(index)
				record.baselineCommandTerm = uint64(term)
				record.hasBaselineCommand = true
			}
		},
	)
	if err != nil {
		return raftSnapshotInstallRecord{}, false, err
	}
	if rowErr != nil {
		return raftSnapshotInstallRecord{}, false,
			raftSnapshotInstallError("decode install baseline", rowErr)
	}
	if count == 0 {
		return raftSnapshotInstallRecord{}, false, nil
	}
	if count != 1 {
		return raftSnapshotInstallRecord{}, false,
			raftSnapshotInstallError("multiple install baselines", nil)
	}
	if err := validateRaftSnapshotInstallRecord(record); err != nil {
		return raftSnapshotInstallRecord{}, false, err
	}
	return record, true, nil
}

func validateRaftSnapshotInstallRecord(
	record raftSnapshotInstallRecord,
) error {
	if !record.sessionID.Valid() ||
		!record.workspaceID.Valid() ||
		!domain.ValidUnsignedInteger(record.recoveryGeneration) ||
		!record.sourceServerID.Valid() ||
		!validRaftSnapshotInstallID(record.snapshotID) ||
		record.snapshotIndex < 1 ||
		!domain.ValidUnsignedInteger(record.snapshotIndex) ||
		record.snapshotTerm < 1 ||
		!domain.ValidUnsignedInteger(record.snapshotTerm) ||
		record.configurationIndex < 1 ||
		record.configurationIndex > record.snapshotIndex ||
		!domain.ValidUnsignedInteger(record.configurationIndex) ||
		!record.installedAt.Valid() ||
		record.heads.validate() != nil ||
		record.heads.ChainIndex > record.heads.ResultIndex {
		return raftSnapshotInstallError("invalid install baseline", nil)
	}
	if record.hasBaselineCommand &&
		(record.baselineCommandLogIndex < 1 ||
			record.baselineCommandLogIndex > record.snapshotIndex ||
			!domain.ValidUnsignedInteger(
				record.baselineCommandLogIndex,
			) ||
			record.baselineCommandTerm < 1 ||
			record.baselineCommandTerm > record.snapshotTerm ||
			!domain.ValidUnsignedInteger(record.baselineCommandTerm)) {
		return raftSnapshotInstallError(
			"invalid installed command baseline",
			nil,
		)
	}
	return nil
}

func validateRaftSnapshotInstallBinding(
	conn *sqlite.Conn,
	state consensusState,
) (raftSnapshotInstallRecord, bool, error) {
	record, found, err := readRaftSnapshotInstallRecord(conn)
	if err != nil || !found {
		return record, found, err
	}
	workspaceID, err := activeWorkspaceID(conn, state)
	if err != nil {
		return raftSnapshotInstallRecord{}, false, err
	}
	if record.sessionID != state.sessionID ||
		record.workspaceID != workspaceID ||
		record.recoveryGeneration != state.recoveryGeneration ||
		record.heads.ChainIndex > state.chainIndex ||
		record.heads.ResultIndex > state.resultIndex ||
		record.heads.DigestVersion != state.digestVersion ||
		record.heads.ProjectionSchemaVersion !=
			state.projectionSchemaVersion {
		return raftSnapshotInstallRecord{}, false,
			raftSnapshotInstallError(
				"install baseline differs from active lineage",
				nil,
			)
	}
	if record.hasBaselineCommand {
		if state.lastAppliedLogIndex < record.baselineCommandLogIndex ||
			state.lastAppliedLogIndex ==
				record.baselineCommandLogIndex &&
				state.currentTerm != record.baselineCommandTerm {
			return raftSnapshotInstallRecord{}, false,
				raftSnapshotInstallError(
					"active command watermark precedes install baseline",
					nil,
				)
		}
	} else if state.lastAppliedLogIndex == 0 && state.currentTerm != 0 {
		return raftSnapshotInstallRecord{}, false,
			raftSnapshotInstallError(
				"term exists without a command watermark",
				nil,
			)
	}
	configuration, configured, err := readRaftConfigurationRecord(conn)
	if err != nil {
		return raftSnapshotInstallRecord{}, false, err
	}
	if !configured ||
		configuration.SessionID != state.sessionID ||
		configuration.RecoveryGeneration != state.recoveryGeneration ||
		configuration.LogIndex < record.configurationIndex ||
		configuration.LogIndex == record.configurationIndex &&
			configuration.ConfigurationDigest !=
				record.configurationDigest {
		return raftSnapshotInstallRecord{}, false,
			raftSnapshotInstallError(
				"configuration does not cover install baseline",
				nil,
			)
	}
	attestation, attested, err := readLogicalSnapshotAttestation(conn, state)
	if err != nil {
		return raftSnapshotInstallRecord{}, false, err
	}
	if !attested {
		return raftSnapshotInstallRecord{}, false,
			raftSnapshotInstallError(
				"install baseline lacks its signed logical snapshot",
				nil,
			)
	}
	cut, err := logicalSnapshotCutFromRoot(attestation.root)
	if err != nil {
		return raftSnapshotInstallRecord{}, false, err
	}
	if record.sourceServerID != cut.SignerDeviceID ||
		record.heads.ChainIndex != cut.ChainIndex ||
		record.heads.ChainHash != cut.ChainHash ||
		record.heads.ResultIndex != cut.ResultIndex ||
		record.heads.ResultHash != cut.ResultHash ||
		record.heads.ProjectionAccumulator !=
			cut.ProjectionAccumulator ||
		record.projectionStateDigest != cut.ProjectionStateDigest ||
		record.heads.DigestVersion != cut.DigestVersion ||
		record.heads.ProjectionSchemaVersion !=
			cut.ProjectionSchemaVersion {
		return raftSnapshotInstallRecord{}, false,
			raftSnapshotInstallError(
				"signed root differs from install baseline",
				nil,
			)
	}
	return record, true, nil
}

func verifyRaftSnapshotInstallEvidence(
	conn *sqlite.Conn,
	state consensusState,
) error {
	record, found, err := validateRaftSnapshotInstallBinding(conn, state)
	if err != nil {
		return err
	}
	if !found {
		return raftSnapshotInstallError("install baseline is missing", nil)
	}
	attestation, found, err := readLogicalSnapshotAttestation(conn, state)
	if err != nil {
		return err
	}
	if !found {
		return raftSnapshotInstallError(
			"signed snapshot attestation is missing",
			nil,
		)
	}
	return verifyLogicalSnapshotAttestationBaseline(
		conn,
		state,
		record.workspaceID,
		record.heads,
		attestation,
	)
}

func validRaftSnapshotInstallID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for index := 0; index < len(id); index++ {
		value := id[index]
		if value >= 'a' && value <= 'z' ||
			value >= 'A' && value <= 'Z' ||
			value >= '0' && value <= '9' ||
			value == '.' ||
			value == '_' ||
			value == ':' ||
			value == '-' {
			continue
		}
		return false
	}
	return true
}

func raftSnapshotInstallError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrRaftSnapshotInstall, detail)
	}
	return fmt.Errorf("%w: %s: %w", ErrRaftSnapshotInstall, detail, cause)
}
