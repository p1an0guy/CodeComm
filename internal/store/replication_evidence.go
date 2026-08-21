package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/voteractivation"
	"zombiezen.com/go/sqlite"
)

type storedReplicationAttestation struct {
	id                         string
	sessionID                  domain.UUIDv7
	workspaceID                domain.UUIDv4
	recoveryGeneration         uint64
	signerDeviceID             domain.DeviceID
	authorityVersion           uint64
	fromResultIndex            uint64
	toResultIndex              uint64
	serverAppliedResultIndex   uint64
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
	envelopeJSON               []byte
	signature                  [ed25519.SignatureSize]byte
	verifiedAt                 domain.Timestamp
}

type replicationEvidenceAuthority struct {
	devices   map[domain.DeviceID]device.Device
	authority credentialauthority.Authority
}

func verifySettledNonvoterEvidence(
	conn *sqlite.Conn,
	state consensusState,
	settled settledNonvoterState,
) error {
	if err := validateSettledNonvoterState(conn, state, settled); err != nil {
		return err
	}
	if err := verifyRaftCommandLedgerThrough(
		conn,
		state,
		settled.baselineHeads.ResultIndex,
	); err != nil {
		return replicationEvidenceError("verify settled Raft baseline", err)
	}
	genesis, err := readGenesisBoundary(
		conn,
		state.recoveryGeneration,
		state.sessionID,
	)
	if err != nil {
		return err
	}
	baseline := settled.baselineHeads
	start, err := resultRangeStart(
		conn,
		state,
		genesis,
		baseline.ResultIndex,
	)
	if err != nil {
		return replicationEvidenceError("reconstruct baseline heads", err)
	}
	accumulator, err := projectionAccumulatorAtResultCut(
		conn,
		state,
		genesis,
		baseline.ResultIndex,
	)
	if err != nil {
		return replicationEvidenceError(
			"reconstruct baseline accumulator",
			err,
		)
	}
	if baseline.ResultHash != start.resultHash ||
		baseline.ChainIndex != start.chainIndex ||
		baseline.ChainHash != start.chainHash ||
		baseline.ProjectionAccumulator != accumulator {
		return replicationEvidenceError(
			"settled baseline differs from retained commitments",
			nil,
		)
	}
	baselineStateDigest, err := projectionStateDigestAtResultCut(
		conn,
		state,
		genesis,
		baseline.ResultIndex,
		nil,
	)
	if err != nil {
		return replicationEvidenceError(
			"reconstruct baseline projections",
			err,
		)
	}
	attestationCount, err := activeAttestationCount(conn, state)
	if err != nil {
		return err
	}
	if state.resultIndex == baseline.ResultIndex {
		if attestationCount != 0 {
			return replicationEvidenceError(
				"boundary-only settled state has attestations",
				nil,
			)
		}
		if err := verifyImportedRowsLackRaftProvenance(
			conn,
			state,
			baseline.ResultIndex,
		); err != nil {
			return err
		}
		return verifyReplicationWatermarkObservations(
			conn,
			state,
			settled,
		)
	}
	baselineAuthorityRows, verifiedStateDigest, err :=
		projectionAuthorityRowsAtResultCut(
			conn,
			state,
			genesis,
			baseline.ResultIndex,
		)
	if err != nil {
		return replicationEvidenceError(
			"reconstruct baseline authority",
			err,
		)
	}
	if verifiedStateDigest != baselineStateDigest {
		return replicationEvidenceError(
			"baseline projection digest changed",
			nil,
		)
	}
	authority, err := newReplicationEvidenceAuthority(
		state.sessionID,
		baselineAuthorityRows,
	)
	if err != nil {
		return replicationEvidenceError(
			"decode baseline authority",
			err,
		)
	}
	cursor := baseline
	cursorStateDigest := chain.Digest(verifiedStateDigest)
	verifiedCount := int64(0)
	for cursor.ResultIndex < state.resultIndex {
		if cursor.ResultIndex == domain.MaxSafeInteger {
			return replicationEvidenceError(
				"attestation cursor is exhausted",
				nil,
			)
		}
		attestation, found, err := readReplicationAttestationStartingAt(
			conn,
			state,
			cursor.ResultIndex+1,
		)
		if err != nil {
			return err
		}
		if !found {
			return replicationEvidenceError(
				fmt.Sprintf(
					"missing attestation beginning at result %d",
					cursor.ResultIndex+1,
				),
				nil,
			)
		}
		if attestation.workspaceID != settled.workspaceID {
			return replicationEvidenceError(
				"batch attestation workspace differs",
				nil,
			)
		}
		batch, mutations, err := reconstructAttestedBatch(
			conn,
			state,
			attestation,
		)
		if err != nil {
			return err
		}
		metadata := batch.Unsigned().Metadata()
		if metadata.StartResultHash != chain.Digest(cursor.ResultHash) ||
			metadata.StartChainIndex != cursor.ChainIndex ||
			metadata.StartChainHash != chain.Digest(cursor.ChainHash) ||
			metadata.StartProjectionAccumulator !=
				chain.Digest(cursor.ProjectionAccumulator) ||
			metadata.StartProjectionStateDigest != cursorStateDigest {
			return replicationEvidenceError(
				"attestation does not extend the prior verified cut",
				nil,
			)
		}
		input := batch.Unsigned().Input()
		resultHead := metadata.StartResultHash
		projectionAccumulator := metadata.StartProjectionAccumulator
		for index, encoded := range mutations {
			values, err := chain.DecodeMutations(encoded)
			if err != nil {
				return replicationEvidenceError(
					"decode attested projection mutations",
					err,
				)
			}
			result, err := chain.DecodeResult(input.Results[index])
			if err != nil {
				return replicationEvidenceError(
					"decode attested command result",
					err,
				)
			}
			signed, err := authority.verifyProposal(
				result.Proposal,
				state.sessionID,
				settled.workspaceID,
			)
			if err != nil {
				return replicationEvidenceError(
					"verify attested proposal origin",
					err,
				)
			}
			nextResultHead, _, err := chain.AppendResult(resultHead, result)
			if err != nil {
				return replicationEvidenceError(
					"advance attested result head",
					err,
				)
			}
			nextAccumulator, canonical, err := chain.AppendAccumulator(
				projectionAccumulator,
				result.ResultIndex,
				nextResultHead,
				values,
			)
			if err != nil || !bytes.Equal(canonical, encoded) {
				return replicationEvidenceError(
					"advance attested projection accumulator",
					err,
				)
			}
			resultHead = nextResultHead
			projectionAccumulator = nextAccumulator
			if err := authority.apply(
				signed,
				result.ChainIndex != nil,
				values,
				settled.workspaceID,
				state.recoveryGeneration,
			); err != nil {
				return replicationEvidenceError(
					"advance attested authority",
					err,
				)
			}
		}
		if resultHead != metadata.EndResultHash ||
			projectionAccumulator != metadata.EndProjectionAccumulator {
			return replicationEvidenceError(
				"attested projection accumulator differs from signed end",
				nil,
			)
		}
		endStateDigest, err := projectionStateDigestAtResultCut(
			conn,
			state,
			genesis,
			metadata.ToResultIndex,
			nil,
		)
		if err != nil {
			return replicationEvidenceError(
				"reconstruct attested projection state",
				err,
			)
		}
		if chain.Digest(endStateDigest) !=
			metadata.EndProjectionStateDigest {
			return replicationEvidenceError(
				"attested projection state differs from signed end",
				nil,
			)
		}
		if authority.authority.SessionID != state.sessionID {
			return replicationEvidenceError(
				"attested authority changed session",
				nil,
			)
		}
		signer, exists := authority.devices[metadata.ServerDeviceID]
		if !exists ||
			signer.Status != device.StatusActive ||
			authority.authority.VoterSetVersion !=
				metadata.ServerAuthorityVersion ||
			!authority.authority.Contains(metadata.ServerDeviceID) {
			return replicationEvidenceError(
				"batch signer was not active in the authority at its end",
				nil,
			)
		}
		if err := replication.VerifyBatch(
			batch,
			signer.IdentityPublicKey,
		); err != nil {
			return replicationEvidenceError(
				"verify batch identity signature",
				err,
			)
		}
		cursor.ResultIndex = metadata.ToResultIndex
		cursor.ResultHash = Digest(metadata.EndResultHash)
		cursor.ChainIndex = metadata.EndChainIndex
		cursor.ChainHash = Digest(metadata.EndChainHash)
		cursor.ProjectionAccumulator = Digest(
			metadata.EndProjectionAccumulator,
		)
		cursorStateDigest = metadata.EndProjectionStateDigest
		verifiedCount++
	}
	currentStateDigest, err := projectionStateDigest(conn, chain.Versions{
		Digest:           state.digestVersion,
		ProjectionSchema: state.projectionSchemaVersion,
	})
	if err != nil {
		return err
	}
	if verifiedCount != attestationCount ||
		cursor.ResultIndex != state.resultIndex ||
		cursor.ResultHash != state.resultHash ||
		cursor.ChainIndex != state.chainIndex ||
		cursor.ChainHash != state.chainHash ||
		cursor.ProjectionAccumulator != state.projectionAccumulator ||
		cursorStateDigest != chain.Digest(currentStateDigest) {
		return replicationEvidenceError(
			"attestation coverage does not end at the active heads",
			nil,
		)
	}
	if err := verifyImportedRowsLackRaftProvenance(
		conn,
		state,
		baseline.ResultIndex,
	); err != nil {
		return err
	}
	return verifyReplicationWatermarkObservations(conn, state, settled)
}

func projectionAccumulatorAtResultCut(
	conn *sqlite.Conn,
	state consensusState,
	genesis storedGenesisBoundary,
	resultCut uint64,
) (Digest, error) {
	if resultCut < genesis.predecessorResultIndex ||
		resultCut > state.resultIndex {
		return Digest{}, errors.New("result cut is outside active generation")
	}
	genesisDigest, err := chain.GenesisDigest(genesis.genesisJSON)
	if err != nil ||
		genesisDigest != chain.Digest(genesis.genesisDigest) {
		return Digest{}, errors.New("invalid active genesis digest")
	}
	accumulator := chain.AccumulatorSeedInitial(
		genesisDigest,
		chain.Digest(genesis.stateDigest),
	)
	if genesis.hasPredecessor {
		accumulator = chain.AccumulatorSeedSuccessor(
			chain.Digest(genesis.predecessorAccumulator),
			genesisDigest,
			chain.Digest(genesis.stateDigest),
		)
	}
	index := genesis.predecessorResultIndex
	var rowErr error
	err = queryArgs(
		conn,
		`SELECT result_index, result_hash, projection_mutations_json
		   FROM command_results
		  WHERE session_id = ?1 AND recovery_generation = ?2
		    AND result_index <= ?3
		  ORDER BY result_index;`,
		[]any{string(state.sessionID), state.recoveryGeneration, resultCut},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			value := stmt.ColumnInt64(0)
			if value < 1 ||
				index == domain.MaxSafeInteger ||
				uint64(value) != index+1 {
				rowErr = errors.New("result indexes are not dense")
				return
			}
			var resultHash Digest
			if rowErr = copyDigestColumn(
				&resultHash,
				stmt,
				1,
			); rowErr != nil {
				return
			}
			mutationJSON := []byte(stmt.ColumnText(2))
			mutations, err := chain.DecodeMutations(mutationJSON)
			if err != nil {
				rowErr = err
				return
			}
			next, canonical, err := chain.AppendAccumulator(
				accumulator,
				uint64(value),
				chain.Digest(resultHash),
				mutations,
			)
			if err != nil || !bytes.Equal(canonical, mutationJSON) {
				rowErr = errors.New(
					"projection accumulator input does not round trip",
				)
				return
			}
			index = uint64(value)
			accumulator = next
		},
	)
	if err != nil {
		return Digest{}, err
	}
	if rowErr != nil {
		return Digest{}, rowErr
	}
	if index != resultCut {
		return Digest{}, errors.New("result cut is not retained")
	}
	return Digest(accumulator), nil
}

func activeAttestationCount(
	conn *sqlite.Conn,
	state consensusState,
) (int64, error) {
	var count int64
	err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM replication_attestations
		  WHERE session_id = ?1 AND recovery_generation = ?2;`,
		[]any{string(state.sessionID), state.recoveryGeneration},
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	)
	return count, err
}

func readReplicationAttestationStartingAt(
	conn *sqlite.Conn,
	state consensusState,
	fromResultIndex uint64,
) (storedReplicationAttestation, bool, error) {
	var (
		result storedReplicationAttestation
		count  int
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT attestation_id, attestation_kind, session_id, workspace_id,
		        recovery_generation, signer_device_id,
		        authority_voter_set_version, from_result_index,
		        to_result_index, start_result_hash, end_result_hash,
		        start_chain_index, end_chain_index, start_chain_hash,
		        end_chain_hash, start_projection_accumulator,
		        end_projection_accumulator, start_projection_state_digest,
		        end_projection_state_digest, checkpoint_event_id,
		        envelope_json, signature, verified_at,
		        server_applied_result_index
		   FROM replication_attestations
		  WHERE session_id = ?1 AND recovery_generation = ?2
		    AND from_result_index = ?3
		  ORDER BY attestation_id;`,
		[]any{
			string(state.sessionID),
			state.recoveryGeneration,
			fromResultIndex,
		},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 || rowErr != nil {
				return
			}
			result.id = stmt.ColumnText(0)
			if stmt.ColumnText(1) != "batch" ||
				stmt.ColumnType(19) != sqlite.TypeNull {
				rowErr = errors.New("active attestation is not a batch")
				return
			}
			result.sessionID = domain.UUIDv7(stmt.ColumnText(2))
			result.workspaceID = domain.UUIDv4(stmt.ColumnText(3))
			result.signerDeviceID = domain.DeviceID(stmt.ColumnText(5))
			numbers := []*uint64{
				&result.recoveryGeneration,
				&result.authorityVersion,
				&result.fromResultIndex,
				&result.toResultIndex,
				&result.startChainIndex,
				&result.endChainIndex,
				&result.serverAppliedResultIndex,
			}
			for index, column := range [...]int{
				4, 6, 7, 8, 11, 12, 23,
			} {
				value := stmt.ColumnInt64(column)
				if value < 0 {
					rowErr = errors.New(
						"negative replication attestation number",
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
			result.envelopeJSON = []byte(stmt.ColumnText(20))
			if stmt.ColumnType(21) != sqlite.TypeBlob ||
				stmt.ColumnLen(21) != ed25519.SignatureSize {
				rowErr = errors.New("invalid batch signature storage")
				return
			}
			copy(result.signature[:], columnBytes(stmt, 21))
			result.verifiedAt = domain.Timestamp(stmt.ColumnText(22))
		},
	)
	if err != nil {
		return storedReplicationAttestation{}, false, err
	}
	if rowErr != nil {
		return storedReplicationAttestation{}, false,
			replicationEvidenceError("decode batch attestation", rowErr)
	}
	if count > 1 {
		return storedReplicationAttestation{}, false,
			replicationEvidenceError(
				"multiple attestations begin at one result",
				nil,
			)
	}
	if count == 0 {
		return storedReplicationAttestation{}, false, nil
	}
	if !result.sessionID.Valid() ||
		!result.workspaceID.Valid() ||
		!result.signerDeviceID.Valid() ||
		result.sessionID != state.sessionID ||
		result.recoveryGeneration != state.recoveryGeneration ||
		result.authorityVersion < 1 ||
		result.fromResultIndex != fromResultIndex ||
		result.toResultIndex < result.fromResultIndex ||
		result.toResultIndex-result.fromResultIndex >=
			replication.MaxBatchResults ||
		result.serverAppliedResultIndex < result.toResultIndex ||
		!result.verifiedAt.Valid() {
		return storedReplicationAttestation{}, false,
			replicationEvidenceError(
				"invalid batch attestation fields",
				nil,
			)
	}
	return result, true, nil
}

func reconstructAttestedBatch(
	conn *sqlite.Conn,
	state consensusState,
	attestation storedReplicationAttestation,
) (replication.Batch, [][]byte, error) {
	type resultRow struct {
		eventID     domain.UUIDv7
		resultIndex uint64
		mutations   []byte
	}
	rows := make(
		[]resultRow,
		0,
		int(attestation.toResultIndex-attestation.fromResultIndex+1),
	)
	var rowErr error
	err := queryArgs(
		conn,
		`SELECT event_id, result_index, projection_mutations_json
		   FROM command_results
		  WHERE session_id = ?1 AND recovery_generation = ?2
		    AND result_index BETWEEN ?3 AND ?4
		  ORDER BY result_index;`,
		[]any{
			string(state.sessionID),
			state.recoveryGeneration,
			attestation.fromResultIndex,
			attestation.toResultIndex,
		},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			expected := attestation.fromResultIndex + uint64(len(rows))
			index := stmt.ColumnInt64(1)
			eventID := domain.UUIDv7(stmt.ColumnText(0))
			mutationJSON := []byte(stmt.ColumnText(2))
			if index < 1 ||
				uint64(index) != expected ||
				!eventID.Valid() {
				rowErr = errors.New("attested result range is not dense")
				return
			}
			if _, err := chain.DecodeMutations(mutationJSON); err != nil {
				rowErr = err
				return
			}
			rows = append(rows, resultRow{
				eventID:     eventID,
				resultIndex: uint64(index),
				mutations:   bytes.Clone(mutationJSON),
			})
		},
	)
	if err != nil {
		return replication.Batch{}, nil, err
	}
	if rowErr != nil {
		return replication.Batch{}, nil,
			replicationEvidenceError("read attested results", rowErr)
	}
	results := make(
		[][]byte,
		0,
		len(rows),
	)
	mutations := make([][]byte, 0, len(rows))
	for _, row := range rows {
		stored, found, err := readStoredCommandResult(conn, row.eventID)
		if err != nil || !found {
			return replication.Batch{}, nil,
				replicationEvidenceError(
					fmt.Sprintf(
						"read attested result %d",
						row.resultIndex,
					),
					err,
				)
		}
		if err := verifyStoredCommandResult(conn, stored); err != nil {
			return replication.Batch{}, nil,
				replicationEvidenceError(
					"verify attested result",
					err,
				)
		}
		encoded, err := encodeStoredCommandResult(stored)
		if err != nil {
			return replication.Batch{}, nil, err
		}
		results = append(results, encoded)
		mutations = append(mutations, row.mutations)
	}
	expectedCount := attestation.toResultIndex -
		attestation.fromResultIndex + 1
	if uint64(len(results)) != expectedCount {
		return replication.Batch{}, nil,
			replicationEvidenceError(
				"attestation range has missing results",
				nil,
			)
	}
	unsigned, err := replication.NewUnsignedBatch(replication.BatchInput{
		FromResultIndex: attestation.fromResultIndex,
		ToResultIndex:   attestation.toResultIndex,
		StartResultHash: chain.Digest(attestation.startResultHash),
		EndResultHash:   chain.Digest(attestation.endResultHash),
		StartChainIndex: attestation.startChainIndex,
		StartChainHash:  chain.Digest(attestation.startChainHash),
		EndChainIndex:   attestation.endChainIndex,
		EndChainHash:    chain.Digest(attestation.endChainHash),
		StartProjectionAccumulator: chain.Digest(
			attestation.startProjectionAccumulator,
		),
		EndProjectionAccumulator: chain.Digest(
			attestation.endProjectionAccumulator,
		),
		StartProjectionStateDigest: chain.Digest(
			attestation.startProjectionStateDigest,
		),
		EndProjectionStateDigest: chain.Digest(
			attestation.endProjectionStateDigest,
		),
		Results:                  results,
		SessionID:                attestation.sessionID,
		WorkspaceID:              attestation.workspaceID,
		RecoveryGeneration:       attestation.recoveryGeneration,
		ServerDeviceID:           attestation.signerDeviceID,
		ServerAppliedResultIndex: attestation.serverAppliedResultIndex,
		ServerAuthorityVersion:   attestation.authorityVersion,
	})
	if err != nil {
		return replication.Batch{}, nil,
			replicationEvidenceError("rebuild batch preimage", err)
	}
	batch, err := replication.NewBatch(unsigned, attestation.signature)
	if err != nil {
		return replication.Batch{}, nil,
			replicationEvidenceError("rebuild signed batch", err)
	}
	if batch.AttestationID() != attestation.id ||
		!bytes.Equal(
			batch.AttestationEnvelope(),
			attestation.envelopeJSON,
		) {
		return replication.Batch{}, nil,
			replicationEvidenceError(
				"batch attestation metadata differs from signed bytes",
				nil,
			)
	}
	return batch, mutations, nil
}

func encodeStoredCommandResult(
	stored storedCommandResult,
) ([]byte, error) {
	value := chain.Result{
		ResultIndex:    stored.resultIndex,
		Proposal:       stored.proposalJSON,
		Outcome:        stored.outcome.JSON,
		ProposalDigest: chain.Digest(stored.proposalDigest),
	}
	if stored.chainIndex != nil {
		index := *stored.chainIndex
		hash := chain.Digest(*stored.chainHash)
		value.ChainIndex = &index
		value.ChainHash = &hash
	}
	return chain.EncodeResult(value)
}

func newReplicationEvidenceAuthority(
	sessionID domain.UUIDv7,
	rows []chain.LogicalRow,
) (replicationEvidenceAuthority, error) {
	result := replicationEvidenceAuthority{
		devices: make(map[domain.DeviceID]device.Device),
	}
	authorityFound := false
	for _, row := range rows {
		switch row.Table {
		case "devices":
			member, err := decodeEvidenceDevice(row.Row)
			if err != nil {
				return replicationEvidenceAuthority{}, err
			}
			if _, exists := result.devices[member.ID]; exists {
				return replicationEvidenceAuthority{},
					errors.New("duplicate device row")
			}
			result.devices[member.ID] = member
		case "credential_authority":
			if authorityFound {
				return replicationEvidenceAuthority{},
					errors.New("duplicate credential authority row")
			}
			authority, err := decodeEvidenceAuthority(row.Row)
			if err != nil {
				return replicationEvidenceAuthority{}, err
			}
			if authority.SessionID != sessionID {
				return replicationEvidenceAuthority{},
					errors.New("credential authority session differs")
			}
			result.authority = authority
			authorityFound = true
		}
	}
	if !authorityFound {
		return replicationEvidenceAuthority{},
			errors.New("credential authority row is missing")
	}
	return result, nil
}

func (state *replicationEvidenceAuthority) apply(
	signed event.SignedEvent,
	accepted bool,
	mutations []chain.Mutation,
	workspaceID domain.UUIDv4,
	recoveryGeneration uint64,
) error {
	var authorityMutation *chain.Mutation
	for _, mutation := range mutations {
		switch mutation.Table {
		case "devices":
			if mutation.After == nil {
				return errors.New("device projection was deleted")
			}
			member, err := decodeEvidenceDevice(mutation.After)
			if err != nil {
				return err
			}
			before, exists := state.devices[member.ID]
			if exists != (mutation.Before != nil) {
				return errors.New("device mutation before-image presence differs")
			}
			if exists {
				storedBefore, err := decodeEvidenceDevice(mutation.Before)
				if err != nil {
					return err
				}
				if !equalEvidenceDevice(before, storedBefore) ||
					before.ID != member.ID ||
					!bytes.Equal(
						before.IdentityPublicKey,
						member.IdentityPublicKey,
					) {
					return errors.New(
						"device mutation changes its identity binding",
					)
				}
			}
			state.devices[member.ID] = member
		case "credential_authority":
			if authorityMutation != nil {
				return errors.New(
					"command carries multiple authority mutations",
				)
			}
			if mutation.Before == nil || mutation.After == nil {
				return errors.New("credential authority was deleted")
			}
			copy := mutation
			authorityMutation = &copy
		}
	}
	if authorityMutation == nil {
		return nil
	}
	if !accepted ||
		signed.Proposal().Kind != event.KindMembershipVoterSetActivated {
		return errors.New(
			"authority changed outside an accepted voter activation",
		)
	}
	before, err := decodeEvidenceAuthority(authorityMutation.Before)
	if err != nil {
		return err
	}
	if !equalEvidenceAuthority(before, state.authority) {
		return errors.New("authority mutation before-image differs")
	}
	after, err := decodeEvidenceAuthority(authorityMutation.After)
	if err != nil {
		return err
	}
	payload, err := voteractivation.DecodeActivationPayload(
		signed.Proposal().Payload,
	)
	if err != nil {
		return err
	}
	handoff := payload.UnsignedHandoff().Input()
	if handoff.SessionID != state.authority.SessionID ||
		handoff.WorkspaceID != workspaceID ||
		handoff.RecoveryGeneration != recoveryGeneration ||
		handoff.ExpectedAuthorityVoterSetVersion !=
			state.authority.VoterSetVersion {
		return errors.New("authority handoff lineage differs")
	}
	expected := credentialauthority.Authority{
		SessionID:                   handoff.SessionID,
		VoterDeviceIDs:              append([]domain.DeviceID(nil), handoff.VoterSet...),
		VoterSetVersion:             handoff.TargetVoterSetVersion,
		ActivationSource:            credentialauthority.ActivationHandoff,
		ActivationCheckpointEventID: handoff.ActivationCheckpointEventID,
		ActivationProofs: make(
			[]credentialauthority.ActivationProof,
			len(handoff.ActivationProofs),
		),
		PriorAuthoritySigner: handoff.PriorAuthoritySigner,
	}
	handoffSignature := payload.HandoffSignature()
	expected.PriorAuthorityHandoff = &handoffSignature
	for index, proof := range handoff.ActivationProofs {
		expected.ActivationProofs[index] =
			credentialauthority.ActivationProof{
				VoterDeviceID: proof.VoterDeviceID(),
				CanonicalJSON: proof.CanonicalBytes(),
			}
	}
	if err := credentialauthority.ValidateTransition(
		credentialauthority.OperationActivate,
		state.authority,
		expected,
	); err != nil {
		return err
	}
	if !equalEvidenceAuthority(after, expected) {
		return errors.New(
			"authority projection differs from signed handoff",
		)
	}
	priorSigner, exists := state.devices[handoff.PriorAuthoritySigner]
	if !exists ||
		priorSigner.Status != device.StatusActive ||
		!state.authority.Contains(priorSigner.ID) {
		return errors.New("prior authority signer is not active")
	}
	if err := voteractivation.VerifyAuthorityHandoff(
		payload,
		priorSigner.IdentityPublicKey,
	); err != nil {
		return err
	}
	for _, proof := range handoff.ActivationProofs {
		member, exists := state.devices[proof.VoterDeviceID()]
		if !exists || member.Status != device.StatusActive {
			return errors.New("activation proof voter is not active")
		}
		if err := voteractivation.VerifyProof(
			proof,
			member.IdentityPublicKey,
		); err != nil {
			return err
		}
	}
	if len(handoff.ActivationProofs) == 0 {
		return errors.New("authority handoff has no activation proofs")
	}
	checkpoint := handoff.ActivationProofs[0].Unsigned().Input()
	checkpointSigner, exists := state.devices[checkpoint.Checkpoint.SignerDeviceID]
	if !exists ||
		checkpointSigner.Status != device.StatusActive ||
		!state.authority.Contains(checkpointSigner.ID) {
		return errors.New("activation checkpoint signer is not active")
	}
	checkpointJSON, err := event.EncodeCheckpoint(checkpoint.Checkpoint)
	if err != nil {
		return err
	}
	if err := codecommcrypto.VerifyEd25519(
		checkpointSigner.IdentityPublicKey,
		codec.SignatureCheckpoint,
		checkpointJSON,
		checkpoint.CheckpointSignature[:],
	); err != nil {
		return err
	}
	state.authority = after
	return nil
}

func (state *replicationEvidenceAuthority) verifyProposal(
	encoded []byte,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
) (event.SignedEvent, error) {
	proposal, err := event.InspectUnverifiedProposal(encoded)
	if err != nil {
		return event.SignedEvent{}, err
	}
	member, exists := state.devices[proposal.Origin.DeviceID()]
	if !exists {
		return event.SignedEvent{},
			errors.New("proposal origin has no retained identity")
	}
	return event.ParseAndVerify(
		encoded,
		event.VerificationContext{
			SessionID:         sessionID,
			WorkspaceID:       workspaceID,
			IdentityPublicKey: member.IdentityPublicKey,
		},
	)
}

func equalEvidenceDevice(first, second device.Device) bool {
	return first.ID == second.ID &&
		first.Role == second.Role &&
		bytes.Equal(first.IdentityPublicKey, second.IdentityPublicKey) &&
		first.DaemonVersion == second.DaemonVersion &&
		first.MaxApplyLevel == second.MaxApplyLevel &&
		first.Status == second.Status &&
		first.EntityVersion == second.EntityVersion
}

func equalEvidenceAuthority(
	first credentialauthority.Authority,
	second credentialauthority.Authority,
) bool {
	if first.SessionID != second.SessionID ||
		first.VoterSetVersion != second.VoterSetVersion ||
		first.ActivationSource != second.ActivationSource ||
		first.ActivationCheckpointEventID !=
			second.ActivationCheckpointEventID ||
		first.PriorAuthoritySigner != second.PriorAuthoritySigner ||
		len(first.VoterDeviceIDs) != len(second.VoterDeviceIDs) ||
		len(first.ActivationProofs) != len(second.ActivationProofs) ||
		(first.PriorAuthorityHandoff == nil) !=
			(second.PriorAuthorityHandoff == nil) {
		return false
	}
	for index := range first.VoterDeviceIDs {
		if first.VoterDeviceIDs[index] != second.VoterDeviceIDs[index] {
			return false
		}
	}
	for index := range first.ActivationProofs {
		if first.ActivationProofs[index].VoterDeviceID !=
			second.ActivationProofs[index].VoterDeviceID ||
			!bytes.Equal(
				first.ActivationProofs[index].CanonicalJSON,
				second.ActivationProofs[index].CanonicalJSON,
			) {
			return false
		}
	}
	return first.PriorAuthorityHandoff == nil ||
		*first.PriorAuthorityHandoff == *second.PriorAuthorityHandoff
}

func decodeEvidenceDevice(raw []byte) (device.Device, error) {
	var wire struct {
		DeviceID          string `json:"device_id"`
		Role              string `json:"role"`
		IdentityPublicKey string `json:"identity_public_key"`
		DaemonVersion     string `json:"daemon_version"`
		MaxApplyLevel     uint64 `json:"max_apply_level"`
		Status            string `json:"status"`
		EntityVersion     uint64 `json:"entity_version"`
	}
	if err := decodeExactObject(raw, &wire, []string{
		"device_id",
		"role",
		"identity_public_key",
		"daemon_version",
		"max_apply_level",
		"status",
		"entity_version",
	}); err != nil {
		return device.Device{}, err
	}
	key, err := codec.DecodeBase64URLExact(
		wire.IdentityPublicKey,
		ed25519.PublicKeySize,
	)
	if err != nil {
		return device.Device{}, err
	}
	member := device.Device{
		ID:                domain.DeviceID(wire.DeviceID),
		Role:              device.Role(wire.Role),
		IdentityPublicKey: ed25519.PublicKey(bytes.Clone(key)),
		DaemonVersion:     wire.DaemonVersion,
		MaxApplyLevel:     wire.MaxApplyLevel,
		Status:            device.Status(wire.Status),
		EntityVersion:     wire.EntityVersion,
	}
	if err := member.Validate(); err != nil {
		return device.Device{}, err
	}
	return member, nil
}

func decodeEvidenceAuthority(
	raw []byte,
) (credentialauthority.Authority, error) {
	var wire struct {
		SessionID                   string            `json:"session_id"`
		VoterDeviceIDs              []domain.DeviceID `json:"voter_device_ids"`
		VoterSetVersion             uint64            `json:"voter_set_version"`
		ActivationSource            string            `json:"activation_source"`
		ActivationCheckpointEventID *string           `json:"activation_checkpoint_event_id"`
		ActivationProofs            []json.RawMessage `json:"activation_proofs"`
		PriorAuthoritySigner        *string           `json:"prior_authority_signer"`
		PriorAuthorityHandoff       *string           `json:"prior_authority_handoff"`
	}
	if err := decodeExactObject(raw, &wire, []string{
		"session_id",
		"voter_device_ids",
		"voter_set_version",
		"activation_source",
		"activation_checkpoint_event_id",
		"activation_proofs",
		"prior_authority_signer",
		"prior_authority_handoff",
	}); err != nil {
		return credentialauthority.Authority{}, err
	}
	authority := credentialauthority.Authority{
		SessionID:        domain.UUIDv7(wire.SessionID),
		VoterDeviceIDs:   append([]domain.DeviceID(nil), wire.VoterDeviceIDs...),
		VoterSetVersion:  wire.VoterSetVersion,
		ActivationSource: credentialauthority.ActivationSource(wire.ActivationSource),
		ActivationProofs: make(
			[]credentialauthority.ActivationProof,
			len(wire.ActivationProofs),
		),
	}
	if wire.ActivationCheckpointEventID != nil {
		authority.ActivationCheckpointEventID = domain.UUIDv7(
			*wire.ActivationCheckpointEventID,
		)
	}
	if wire.PriorAuthoritySigner != nil {
		authority.PriorAuthoritySigner = domain.DeviceID(
			*wire.PriorAuthoritySigner,
		)
	}
	if wire.PriorAuthorityHandoff != nil {
		decoded, err := codec.DecodeBase64URLExact(
			*wire.PriorAuthorityHandoff,
			ed25519.SignatureSize,
		)
		if err != nil {
			return credentialauthority.Authority{}, err
		}
		var signature [ed25519.SignatureSize]byte
		copy(signature[:], decoded)
		authority.PriorAuthorityHandoff = &signature
	}
	for index, raw := range wire.ActivationProofs {
		proof, err := voteractivation.ParseProof(raw)
		if err != nil {
			return credentialauthority.Authority{}, err
		}
		authority.ActivationProofs[index] =
			credentialauthority.ActivationProof{
				VoterDeviceID: proof.VoterDeviceID(),
				CanonicalJSON: proof.CanonicalBytes(),
			}
	}
	if err := authority.Validate(); err != nil {
		return credentialauthority.Authority{}, err
	}
	return authority, nil
}

func decodeExactObject(
	raw []byte,
	destination any,
	fields []string,
) error {
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("logical row is not a canonical object")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil ||
		len(members) != len(fields) {
		return errors.New("logical row has the wrong field set")
	}
	for _, field := range fields {
		if _, exists := members[field]; !exists {
			return fmt.Errorf("logical row is missing field %q", field)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("logical row has trailing data")
	}
	return nil
}

func verifyImportedRowsLackRaftProvenance(
	conn *sqlite.Conn,
	state consensusState,
	baselineResultIndex uint64,
) error {
	var count int64
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM command_results AS r
		   JOIN raft_command_applications AS a
		     ON a.recovery_generation = r.recovery_generation
		    AND a.event_id = r.event_id
		  WHERE r.session_id = ?1 AND r.recovery_generation = ?2
		    AND r.result_index > ?3;`,
		[]any{
			string(state.sessionID),
			state.recoveryGeneration,
			baselineResultIndex,
		},
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if count != 0 {
		return replicationEvidenceError(
			"imported result has a Raft command binding",
			nil,
		)
	}
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM command_results AS r
		   JOIN event_provenance AS p ON p.event_id = r.event_id
		  WHERE r.session_id = ?1 AND r.recovery_generation = ?2
		    AND r.result_index > ?3;`,
		[]any{
			string(state.sessionID),
			state.recoveryGeneration,
			baselineResultIndex,
		},
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if count != 0 {
		return replicationEvidenceError(
			"imported accepted event has Raft provenance",
			nil,
		)
	}
	return nil
}

func replicationEvidenceError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrReplicaEvidenceMode, detail)
	}
	return fmt.Errorf("%w: %s: %w", ErrReplicaEvidenceMode, detail, cause)
}
