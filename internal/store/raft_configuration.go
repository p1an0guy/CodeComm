package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const MaxRaftConfigurationBytes = 4096

var (
	ErrInvalidRaftConfiguration = errors.New(
		"store: invalid committed Raft configuration",
	)
	ErrRaftConfigurationConflict = errors.New(
		"store: committed Raft configuration conflict",
	)
)

// RaftConfigurationRecord is local durable evidence emitted by
// raft.ConfigurationStore after a configuration entry commits.
type RaftConfigurationRecord struct {
	SessionID           domain.UUIDv7
	RecoveryGeneration  uint64
	LogIndex            uint64
	ConfigurationJSON   []byte
	ConfigurationDigest Digest
}

// StoreCommittedRaftConfiguration advances the durable configuration
// watermark. Older replay is ignored; the same index must retain exact bytes.
func (store *Store) StoreCommittedRaftConfiguration(
	ctx context.Context,
	logIndex uint64,
	configurationJSON []byte,
) (bool, error) {
	if store == nil || ctx == nil {
		return false, ErrInvalidRaftConfiguration
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	canonical, err := codec.CanonicalizeSignedObject(configurationJSON)
	if err != nil ||
		!bytes.Equal(canonical, configurationJSON) ||
		len(configurationJSON) == 0 ||
		len(configurationJSON) > MaxRaftConfigurationBytes ||
		logIndex < 1 ||
		!domain.ValidUnsignedInteger(logIndex) {
		return false, ErrInvalidRaftConfiguration
	}
	digest := sha256.Sum256(configurationJSON)

	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	stored := false
	err = store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end, err := sqlitex.ImmediateTransaction(conn)
		if err != nil {
			return err
		}
		defer end(&err)

		state, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return ErrInvalidRaftConfiguration
		}
		current, exists, err := readRaftConfigurationRecord(conn)
		if err != nil {
			return err
		}
		if exists {
			if current.SessionID != state.sessionID ||
				current.RecoveryGeneration != state.recoveryGeneration {
				return ErrRaftConfigurationConflict
			}
			switch {
			case current.LogIndex > logIndex:
				return nil
			case current.LogIndex == logIndex:
				if !bytes.Equal(
					current.ConfigurationJSON,
					configurationJSON,
				) {
					return ErrRaftConfigurationConflict
				}
				return nil
			}
		}
		if err := execute(
			conn,
			`INSERT INTO raft_committed_configuration(
			     singleton, session_id, recovery_generation, log_index,
			     configuration_json, configuration_digest
			 ) VALUES (1, ?1, ?2, ?3, ?4, ?5)
			 ON CONFLICT(singleton) DO UPDATE SET
			     session_id = excluded.session_id,
			     recovery_generation = excluded.recovery_generation,
			     log_index = excluded.log_index,
			     configuration_json = excluded.configuration_json,
			     configuration_digest = excluded.configuration_digest;`,
			string(state.sessionID),
			state.recoveryGeneration,
			logIndex,
			string(configurationJSON),
			digest[:],
		); err != nil {
			return err
		}
		stored = true
		return nil
	})
	return stored, err
}

// CommittedRaftConfiguration returns the latest durable configuration
// delivered by this generation's FSM.
func (store *Store) CommittedRaftConfiguration(
	ctx context.Context,
) (RaftConfigurationRecord, bool, error) {
	if store == nil || ctx == nil {
		return RaftConfigurationRecord{}, false,
			ErrInvalidRaftConfiguration
	}
	if err := ctx.Err(); err != nil {
		return RaftConfigurationRecord{}, false, err
	}
	store.applyMu.Lock()
	defer store.applyMu.Unlock()

	var (
		record RaftConfigurationRecord
		found  bool
	)
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end := sqlitex.Transaction(conn)
		defer end(&err)

		state, stateFound, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !stateFound {
			return ErrInvalidRaftConfiguration
		}
		record, found, err = readRaftConfigurationRecord(conn)
		if err != nil || !found {
			return err
		}
		if record.SessionID != state.sessionID ||
			record.RecoveryGeneration != state.recoveryGeneration {
			return ErrRaftConfigurationConflict
		}
		return nil
	})
	if err != nil {
		return RaftConfigurationRecord{}, false, err
	}
	return record, found, nil
}

func readRaftConfigurationRecord(
	conn *sqlite.Conn,
) (RaftConfigurationRecord, bool, error) {
	var (
		record RaftConfigurationRecord
		count  int
	)
	err := query(
		conn,
		`SELECT session_id, recovery_generation, log_index,
		        configuration_json, configuration_digest
		   FROM raft_committed_configuration
		  WHERE singleton = 1;`,
		func(stmt *sqlite.Stmt) {
			count++
			record.SessionID = domain.UUIDv7(stmt.ColumnText(0))
			record.RecoveryGeneration = uint64(stmt.ColumnInt64(1))
			record.LogIndex = uint64(stmt.ColumnInt64(2))
			record.ConfigurationJSON = []byte(stmt.ColumnText(3))
			copy(record.ConfigurationDigest[:], columnBytes(stmt, 4))
		},
	)
	if err != nil {
		return RaftConfigurationRecord{}, false, err
	}
	if count == 0 {
		return RaftConfigurationRecord{}, false, nil
	}
	if count != 1 ||
		!record.SessionID.Valid() ||
		!domain.ValidUnsignedInteger(record.RecoveryGeneration) ||
		record.LogIndex < 1 ||
		!domain.ValidUnsignedInteger(record.LogIndex) ||
		len(record.ConfigurationJSON) == 0 ||
		len(record.ConfigurationJSON) > MaxRaftConfigurationBytes {
		return RaftConfigurationRecord{}, false,
			ErrRaftConfigurationConflict
	}
	canonical, err := codec.CanonicalizeSignedObject(
		record.ConfigurationJSON,
	)
	digest := sha256.Sum256(record.ConfigurationJSON)
	if err != nil ||
		!bytes.Equal(canonical, record.ConfigurationJSON) ||
		Digest(digest) != record.ConfigurationDigest {
		return RaftConfigurationRecord{}, false,
			fmt.Errorf(
				"%w: canonical bytes or digest mismatch",
				ErrRaftConfigurationConflict,
			)
	}
	record.ConfigurationJSON = bytes.Clone(record.ConfigurationJSON)
	return record, true, nil
}

func verifyCommittedRaftConfiguration(conn *sqlite.Conn) error {
	state, stateFound, err := readConsensusState(conn)
	if err != nil {
		return err
	}
	record, found, err := readRaftConfigurationRecord(conn)
	if err != nil || !found {
		return err
	}
	if !stateFound ||
		record.SessionID != state.sessionID ||
		record.RecoveryGeneration != state.recoveryGeneration {
		return ErrRaftConfigurationConflict
	}
	return nil
}
