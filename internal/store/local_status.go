package store

import (
	"context"
	"crypto/ed25519"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"zombiezen.com/go/sqlite"
)

// StatusSnapshot returns one bounded, transactionally consistent read for the
// local operator status API.
func (state LocalState) StatusSnapshot(
	ctx context.Context,
	localDeviceID domain.DeviceID,
	taskLimit int,
) (coordstatus.DurableSnapshot, error) {
	if !localDeviceID.Valid() ||
		taskLimit < 1 ||
		taskLimit > coordstatus.MaxTasks {
		return coordstatus.DurableSnapshot{}, ErrInvalidLocalState
	}
	var snapshot coordstatus.DurableSnapshot
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		committed, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found ||
			committed.sessionID != lineage.sessionID ||
			committed.recoveryGeneration != lineage.recoveryGeneration {
			return ErrLocalStateIntegrity
		}
		member, found, err := readStatusMember(conn, localDeviceID)
		if err != nil {
			return err
		}
		if !found {
			return ErrLocalStateIntegrity
		}
		target, err := readStatusVoterSet(conn, lineage.sessionID)
		if err != nil {
			return err
		}
		authority, err := readStatusCredentialAuthority(
			conn,
			lineage.sessionID,
		)
		if err != nil {
			return err
		}
		sessions, err := readStatusAgentSessions(conn)
		if err != nil {
			return err
		}
		tasks, err := readTaskProjections(conn, taskLimit)
		if err != nil {
			return err
		}
		taskTotal, err := readStatusTaskTotal(conn)
		if err != nil {
			return err
		}
		heads := headsFromConsensus(committed)
		snapshot = coordstatus.DurableSnapshot{
			SessionID:          lineage.sessionID,
			WorkspaceID:        lineage.workspaceID,
			RecoveryGeneration: lineage.recoveryGeneration,
			Heads: coordstatus.AppliedHeads{
				ChainIndex:              heads.ChainIndex,
				ResultIndex:             heads.ResultIndex,
				DigestVersion:           heads.DigestVersion,
				ProjectionSchemaVersion: heads.ProjectionSchemaVersion,
			},
			Member:              member,
			VoterSet:            target,
			CredentialAuthority: authority,
			AgentSessions:       sessions,
			Tasks:               tasks,
			TaskTotal:           taskTotal,
			TasksTruncated: taskTotal >
				uint64(len(tasks)),
		}
		if committed.currentTerm != 0 {
			term := committed.currentTerm
			snapshot.Heads.CurrentTerm = &term
		}
		if committed.lastAppliedLogIndex != 0 {
			index := committed.lastAppliedLogIndex
			snapshot.Heads.LastRaftAppliedLogIndex = &index
		}
		if err := snapshot.Validate(); err != nil {
			return ErrLocalStateIntegrity
		}
		return nil
	})
	if err != nil {
		return coordstatus.DurableSnapshot{}, err
	}
	return snapshot, nil
}

func readStatusMember(
	conn *sqlite.Conn,
	deviceID domain.DeviceID,
) (device.Device, bool, error) {
	var (
		member device.Device
		found  bool
		rowErr error
	)
	count := 0
	err := queryArgs(
		conn,
		`SELECT device_id, role, identity_public_key, daemon_version,
		        max_apply_level, status, entity_version
		   FROM devices
		  WHERE device_id = ?1;`,
		[]any{string(deviceID)},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			found = true
			maxApplyLevel := stmt.ColumnInt64(4)
			entityVersion := stmt.ColumnInt64(6)
			if maxApplyLevel < 1 || entityVersion < 1 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			member = device.Device{
				ID:                domain.DeviceID(stmt.ColumnText(0)),
				Role:              device.Role(stmt.ColumnText(1)),
				IdentityPublicKey: ed25519.PublicKey(columnBytes(stmt, 2)),
				DaemonVersion:     stmt.ColumnText(3),
				MaxApplyLevel:     uint64(maxApplyLevel),
				Status:            device.Status(stmt.ColumnText(5)),
				EntityVersion:     uint64(entityVersion),
			}
		},
	)
	if err != nil {
		return device.Device{}, false, err
	}
	if rowErr != nil {
		return device.Device{}, false, rowErr
	}
	if found {
		if member.ID != deviceID || member.Validate() != nil {
			return device.Device{}, false, ErrLocalStateIntegrity
		}
	}
	return member, found, nil
}

func readStatusCredentialAuthority(
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
) (voterset.Set, error) {
	var (
		encoded string
		version int64
		count   int
	)
	if err := queryArgs(
		conn,
		`SELECT voter_device_ids_json, voter_set_version
		   FROM credential_authority
		  WHERE session_id = ?1;`,
		[]any{string(sessionID)},
		func(stmt *sqlite.Stmt) {
			count++
			encoded = stmt.ColumnText(0)
			version = stmt.ColumnInt64(1)
		},
	); err != nil {
		return voterset.Set{}, err
	}
	if count != 1 || version < 1 {
		return voterset.Set{}, ErrLocalStateIntegrity
	}
	ids, err := decodeCanonicalJSONArray[domain.DeviceID](encoded)
	if err != nil {
		return voterset.Set{}, ErrLocalStateIntegrity
	}
	authority, err := voterset.New(sessionID, ids, uint64(version))
	if err != nil {
		return voterset.Set{}, ErrLocalStateIntegrity
	}
	return authority, nil
}

func readStatusVoterSet(
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
) (voterset.Set, error) {
	var (
		encoded string
		version int64
		count   int
	)
	if err := queryArgs(
		conn,
		`SELECT voter_device_ids_json, voter_set_version
		   FROM voter_set
		  WHERE session_id = ?1;`,
		[]any{string(sessionID)},
		func(stmt *sqlite.Stmt) {
			count++
			encoded = stmt.ColumnText(0)
			version = stmt.ColumnInt64(1)
		},
	); err != nil {
		return voterset.Set{}, err
	}
	if count != 1 || version < 1 {
		return voterset.Set{}, ErrLocalStateIntegrity
	}
	ids, err := decodeCanonicalJSONArray[domain.DeviceID](encoded)
	if err != nil {
		return voterset.Set{}, ErrLocalStateIntegrity
	}
	target, err := voterset.New(sessionID, ids, uint64(version))
	if err != nil {
		return voterset.Set{}, ErrLocalStateIntegrity
	}
	return target, nil
}

func readStatusAgentSessions(
	conn *sqlite.Conn,
) ([]agentsession.Session, error) {
	ids := make([]domain.UUIDv7, 0, coordstatus.MaxAgentSessions+1)
	if err := queryArgs(
		conn,
		`SELECT agent_session_id
		   FROM agent_sessions
		  WHERE state <> 'ended'
		  ORDER BY agent_session_id
		  LIMIT ?1;`,
		[]any{coordstatus.MaxAgentSessions + 1},
		func(stmt *sqlite.Stmt) {
			ids = append(ids, domain.UUIDv7(stmt.ColumnText(0)))
		},
	); err != nil {
		return nil, err
	}
	if len(ids) > coordstatus.MaxAgentSessions {
		return nil, ErrLocalStateIntegrity
	}
	sessions := make([]agentsession.Session, 0, len(ids))
	for _, id := range ids {
		session, found, err := readCommittedAgentSession(conn, id)
		if err != nil {
			return nil, err
		}
		if !found || session.State == agentsession.StateEnded {
			return nil, ErrLocalStateIntegrity
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func readStatusTaskTotal(conn *sqlite.Conn) (uint64, error) {
	var count int64
	if err := queryOneArgs(
		conn,
		"SELECT count(*) FROM tasks;",
		nil,
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	); err != nil {
		return 0, err
	}
	if count < 0 || !domain.ValidUnsignedInteger(uint64(count)) {
		return 0, ErrLocalStateIntegrity
	}
	return uint64(count), nil
}
