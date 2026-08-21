package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/replication"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrInvalidReplicationWatermarkObservation = errors.New(
	"store: invalid replication watermark observation",
)

// VerifiedReplicationWatermarkObservation is one identity- and
// authority-verified equal-cursor acknowledgement ready for local retention.
type VerifiedReplicationWatermarkObservation struct {
	RelayPeerID     domain.DeviceID
	Acknowledgement replication.Acknowledgement
	VerifiedAt      domain.Timestamp
}

type storedReplicationWatermarkObservation struct {
	id                       string
	sessionID                domain.UUIDv7
	workspaceID              domain.UUIDv4
	recoveryGeneration       uint64
	relayPeerID              domain.DeviceID
	signerDeviceID           domain.DeviceID
	authorityVersion         uint64
	resultIndex              uint64
	resultHash               Digest
	chainIndex               uint64
	chainHash                Digest
	projectionAccumulator    Digest
	projectionStateDigest    Digest
	serverAppliedResultIndex uint64
	envelopeJSON             []byte
	signature                [ed25519.SignatureSize]byte
	verifiedAt               domain.Timestamp
}

// RecordSettledReplicationAcknowledgement atomically revalidates and retains
// one equal-cursor observation. It never advances replicated heads or Raft
// provenance.
func (store *Store) RecordSettledReplicationAcknowledgement(
	ctx context.Context,
	request VerifiedReplicationWatermarkObservation,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !request.RelayPeerID.Valid() ||
		!request.VerifiedAt.Valid() ||
		len(request.Acknowledgement.CanonicalBytes()) == 0 ||
		request.Acknowledgement.AttestationID() == "" {
		return watermarkObservationError("invalid request", nil)
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	return store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
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
			return watermarkObservationError(
				"active generation is missing",
				nil,
			)
		}
		settled, found, err := readSettledNonvoterState(conn)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf(
				"%w: %w",
				ErrInvalidReplicationWatermarkObservation,
				ErrReplicaEvidenceMode,
			)
		}
		if err := verifyCommitmentHistory(conn, state); err != nil {
			return err
		}
		if err := verifySettledNonvoterEvidence(
			conn,
			state,
			settled,
		); err != nil {
			return err
		}
		metadata := request.Acknowledgement.Unsigned().Metadata()
		digest, err := projectionStateDigest(conn, chain.Versions{
			Digest:           state.digestVersion,
			ProjectionSchema: state.projectionSchemaVersion,
		})
		if err != nil {
			return err
		}
		if metadata.SessionID != state.sessionID ||
			metadata.WorkspaceID != settled.workspaceID ||
			metadata.RecoveryGeneration != state.recoveryGeneration ||
			metadata.ResultIndex != state.resultIndex ||
			metadata.ResultHash != chain.Digest(state.resultHash) ||
			metadata.ChainIndex != state.chainIndex ||
			metadata.ChainHash != chain.Digest(state.chainHash) ||
			metadata.ProjectionAccumulator !=
				chain.Digest(state.projectionAccumulator) ||
			metadata.ProjectionStateDigest != chain.Digest(digest) ||
			metadata.ServerAppliedResultIndex != state.resultIndex {
			return watermarkObservationError(
				"acknowledgement differs from the current verified cut",
				nil,
			)
		}
		authorization, err := resultRangeAuthorizationAt(
			conn,
			state,
			state.resultIndex,
			metadata.ServerDeviceID,
		)
		if err != nil {
			return err
		}
		if authorization.authority.VoterSetVersion !=
			metadata.ServerAuthorityVersion ||
			!authorization.permits(metadata.ServerDeviceID) {
			return watermarkObservationError(
				"signer is not active in the acknowledged authority",
				nil,
			)
		}
		member, found, err := readStatusMember(
			conn,
			metadata.ServerDeviceID,
		)
		if err != nil {
			return err
		}
		if !found ||
			member.Status != device.StatusActive ||
			replication.VerifyAcknowledgement(
				request.Acknowledgement,
				member.IdentityPublicKey,
			) != nil {
			return watermarkObservationError(
				"acknowledgement identity signature is invalid",
				nil,
			)
		}
		prior, found, err := readStoredWatermarkObservation(
			conn,
			state.sessionID,
			state.recoveryGeneration,
			metadata.ServerDeviceID,
			metadata.ServerAuthorityVersion,
		)
		if err != nil {
			return err
		}
		if found {
			if _, err := validateStoredWatermarkObservation(
				conn,
				state,
				settled,
				prior,
			); err != nil {
				return err
			}
			if metadata.ServerAppliedResultIndex <
				prior.serverAppliedResultIndex ||
				metadata.ServerAppliedResultIndex ==
					prior.serverAppliedResultIndex &&
					(metadata.ResultIndex != prior.resultIndex ||
						metadata.ResultHash !=
							chain.Digest(prior.resultHash)) {
				return watermarkObservationError(
					"signed server watermark regressed or forked",
					nil,
				)
			}
			if err := execute(
				conn,
				`DELETE FROM replication_watermark_observations
				  WHERE observation_id = ?1;`,
				prior.id,
			); err != nil {
				return err
			}
		}
		signature := request.Acknowledgement.Signature()
		return execute(
			conn,
			`INSERT INTO replication_watermark_observations(
			    observation_id, session_id, workspace_id,
			    recovery_generation, relay_peer_device_id,
			    signer_device_id, authority_voter_set_version,
			    result_index, result_hash, chain_index, chain_hash,
			    projection_accumulator, projection_state_digest,
			    server_applied_result_index, envelope_json, signature,
			    verified_at
			) VALUES (
			    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
			    ?13, ?14, ?15, ?16, ?17
			);`,
			request.Acknowledgement.AttestationID(),
			string(metadata.SessionID),
			string(metadata.WorkspaceID),
			metadata.RecoveryGeneration,
			string(request.RelayPeerID),
			string(metadata.ServerDeviceID),
			metadata.ServerAuthorityVersion,
			metadata.ResultIndex,
			metadata.ResultHash[:],
			metadata.ChainIndex,
			metadata.ChainHash[:],
			metadata.ProjectionAccumulator[:],
			metadata.ProjectionStateDigest[:],
			metadata.ServerAppliedResultIndex,
			string(request.Acknowledgement.Unsigned().CanonicalBytes()),
			signature[:],
			string(request.VerifiedAt),
		)
	})
}

func verifyReplicationWatermarkObservations(
	conn *sqlite.Conn,
	state consensusState,
	settled settledNonvoterState,
) error {
	observations, err := readStoredWatermarkObservations(conn)
	if err != nil {
		return err
	}
	type observationKey struct {
		signer    domain.DeviceID
		authority uint64
	}
	seen := make(map[observationKey]struct{}, len(observations))
	for _, observation := range observations {
		key := observationKey{
			signer:    observation.signerDeviceID,
			authority: observation.authorityVersion,
		}
		if _, duplicate := seen[key]; duplicate {
			return watermarkObservationError(
				"multiple observations occupy one signer authority slot",
				nil,
			)
		}
		seen[key] = struct{}{}
		if _, err := validateStoredWatermarkObservation(
			conn,
			state,
			settled,
			observation,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateStoredWatermarkObservation(
	conn *sqlite.Conn,
	state consensusState,
	settled settledNonvoterState,
	observation storedReplicationWatermarkObservation,
) (replication.Acknowledgement, error) {
	if observation.sessionID != state.sessionID ||
		observation.workspaceID != settled.workspaceID ||
		observation.recoveryGeneration != state.recoveryGeneration ||
		!observation.relayPeerID.Valid() ||
		!observation.signerDeviceID.Valid() ||
		observation.authorityVersion < 1 ||
		observation.resultIndex > state.resultIndex ||
		observation.chainIndex > observation.resultIndex ||
		observation.serverAppliedResultIndex != observation.resultIndex ||
		!observation.verifiedAt.Valid() {
		return replication.Acknowledgement{},
			watermarkObservationError(
				"stored observation metadata is invalid",
				nil,
			)
	}
	genesis, err := readGenesisBoundary(
		conn,
		state.recoveryGeneration,
		state.sessionID,
	)
	if err != nil {
		return replication.Acknowledgement{}, err
	}
	head, err := resultRangeStart(
		conn,
		state,
		genesis,
		observation.resultIndex,
	)
	if err != nil {
		return replication.Acknowledgement{}, err
	}
	projection, err := resultRangeProjectionCommitmentsAt(
		conn,
		state,
		genesis,
		observation.resultIndex,
	)
	if err != nil {
		return replication.Acknowledgement{}, err
	}
	if head.resultHash != observation.resultHash ||
		head.chainIndex != observation.chainIndex ||
		head.chainHash != observation.chainHash ||
		projection.accumulator != observation.projectionAccumulator ||
		projection.stateDigest != observation.projectionStateDigest {
		return replication.Acknowledgement{},
			watermarkObservationError(
				"stored observation differs from retained commitments",
				nil,
			)
	}
	authorization, err := resultRangeAuthorizationAt(
		conn,
		state,
		observation.resultIndex,
		observation.signerDeviceID,
	)
	if err != nil {
		return replication.Acknowledgement{}, err
	}
	if authorization.authority.VoterSetVersion !=
		observation.authorityVersion ||
		!authorization.permits(observation.signerDeviceID) {
		return replication.Acknowledgement{},
			watermarkObservationError(
				"stored observation signer was not active at its cut",
				nil,
			)
	}
	member, found, err := readStatusMember(
		conn,
		observation.signerDeviceID,
	)
	if err != nil {
		return replication.Acknowledgement{}, err
	}
	if !found {
		return replication.Acknowledgement{},
			watermarkObservationError(
				"stored observation signer is missing",
				nil,
			)
	}
	unsigned, err := replication.NewUnsignedAcknowledgement(
		replication.AcknowledgementInput{
			SessionID:                observation.sessionID,
			WorkspaceID:              observation.workspaceID,
			RecoveryGeneration:       observation.recoveryGeneration,
			ServerDeviceID:           observation.signerDeviceID,
			ServerAuthorityVersion:   observation.authorityVersion,
			ResultIndex:              observation.resultIndex,
			ResultHash:               chain.Digest(observation.resultHash),
			ChainIndex:               observation.chainIndex,
			ChainHash:                chain.Digest(observation.chainHash),
			ProjectionAccumulator:    chain.Digest(observation.projectionAccumulator),
			ProjectionStateDigest:    chain.Digest(observation.projectionStateDigest),
			ServerAppliedResultIndex: observation.serverAppliedResultIndex,
		},
	)
	if err != nil ||
		!bytes.Equal(
			unsigned.CanonicalBytes(),
			observation.envelopeJSON,
		) {
		return replication.Acknowledgement{},
			watermarkObservationError(
				"stored observation envelope differs",
				err,
			)
	}
	acknowledgement, err := replication.NewAcknowledgement(
		unsigned,
		observation.signature,
	)
	if err != nil ||
		acknowledgement.AttestationID() != observation.id ||
		replication.VerifyAcknowledgement(
			acknowledgement,
			member.IdentityPublicKey,
		) != nil {
		return replication.Acknowledgement{},
			watermarkObservationError(
				"stored observation signature differs",
				err,
			)
	}
	return acknowledgement, nil
}

func readStoredWatermarkObservations(
	conn *sqlite.Conn,
) ([]storedReplicationWatermarkObservation, error) {
	var (
		observations []storedReplicationWatermarkObservation
		rowErr       error
	)
	err := query(
		conn,
		`SELECT observation_id, session_id, workspace_id,
		        recovery_generation, relay_peer_device_id,
		        signer_device_id, authority_voter_set_version,
		        result_index, result_hash, chain_index, chain_hash,
		        projection_accumulator, projection_state_digest,
		        server_applied_result_index, envelope_json, signature,
		        verified_at
		   FROM replication_watermark_observations
		  ORDER BY signer_device_id, authority_voter_set_version;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			observation, err := decodeStoredWatermarkObservation(stmt)
			if err != nil {
				rowErr = err
				return
			}
			observations = append(observations, observation)
		},
	)
	if err != nil {
		return nil, err
	}
	if rowErr != nil {
		return nil, watermarkObservationError(
			"decode stored observation",
			rowErr,
		)
	}
	return observations, nil
}

func readStoredWatermarkObservation(
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
	generation uint64,
	signerID domain.DeviceID,
	authorityVersion uint64,
) (storedReplicationWatermarkObservation, bool, error) {
	var (
		observation storedReplicationWatermarkObservation
		count       int
		rowErr      error
	)
	err := queryArgs(
		conn,
		`SELECT observation_id, session_id, workspace_id,
		        recovery_generation, relay_peer_device_id,
		        signer_device_id, authority_voter_set_version,
		        result_index, result_hash, chain_index, chain_hash,
		        projection_accumulator, projection_state_digest,
		        server_applied_result_index, envelope_json, signature,
		        verified_at
		   FROM replication_watermark_observations
		  WHERE session_id = ?1 AND recovery_generation = ?2
		    AND signer_device_id = ?3
		    AND authority_voter_set_version = ?4;`,
		[]any{
			string(sessionID),
			generation,
			string(signerID),
			authorityVersion,
		},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				rowErr = errors.New("duplicate observation")
				return
			}
			observation, rowErr =
				decodeStoredWatermarkObservation(stmt)
		},
	)
	if err != nil {
		return storedReplicationWatermarkObservation{}, false, err
	}
	if rowErr != nil {
		return storedReplicationWatermarkObservation{}, false,
			watermarkObservationError(
				"decode prior observation",
				rowErr,
			)
	}
	return observation, count == 1, nil
}

func decodeStoredWatermarkObservation(
	stmt *sqlite.Stmt,
) (storedReplicationWatermarkObservation, error) {
	result := storedReplicationWatermarkObservation{
		id:             stmt.ColumnText(0),
		sessionID:      domain.UUIDv7(stmt.ColumnText(1)),
		workspaceID:    domain.UUIDv4(stmt.ColumnText(2)),
		relayPeerID:    domain.DeviceID(stmt.ColumnText(4)),
		signerDeviceID: domain.DeviceID(stmt.ColumnText(5)),
		envelopeJSON:   []byte(stmt.ColumnText(14)),
		verifiedAt:     domain.Timestamp(stmt.ColumnText(16)),
	}
	numbers := []*uint64{
		&result.recoveryGeneration,
		&result.authorityVersion,
		&result.resultIndex,
		&result.chainIndex,
		&result.serverAppliedResultIndex,
	}
	for index, column := range [...]int{3, 6, 7, 9, 13} {
		value := stmt.ColumnInt64(column)
		if value < 0 {
			return storedReplicationWatermarkObservation{},
				errors.New("negative observation number")
		}
		*numbers[index] = uint64(value)
	}
	digests := []*Digest{
		&result.resultHash,
		&result.chainHash,
		&result.projectionAccumulator,
		&result.projectionStateDigest,
	}
	for index, column := range [...]int{8, 10, 11, 12} {
		if err := copyDigestColumn(
			digests[index],
			stmt,
			column,
		); err != nil {
			return storedReplicationWatermarkObservation{}, err
		}
	}
	if stmt.ColumnType(15) != sqlite.TypeBlob ||
		stmt.ColumnLen(15) != ed25519.SignatureSize {
		return storedReplicationWatermarkObservation{},
			errors.New("invalid observation signature")
	}
	copy(result.signature[:], columnBytes(stmt, 15))
	return result, nil
}

func watermarkObservationError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf(
			"%w: %s",
			ErrInvalidReplicationWatermarkObservation,
			detail,
		)
	}
	return fmt.Errorf(
		"%w: %s: %w",
		ErrInvalidReplicationWatermarkObservation,
		detail,
		cause,
	)
}
