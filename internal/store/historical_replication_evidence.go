package store

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/replication"
	"zombiezen.com/go/sqlite"
)

type historicalAttestationCoverage struct {
	found       bool
	toResult    uint64
	stateDigest chain.Digest
}

// verifyHistoricalReplicationAttestations revalidates every retained
// attestation outside the active generation. Recovery deliberately replaces
// predecessor projection rows, so historical state digests remain protected
// by their identity signatures and contiguous evidence links; immutable
// result/event heads and projection accumulators are reconstructed locally.
func verifyHistoricalReplicationAttestations(
	conn *sqlite.Conn,
	active consensusState,
) error {
	if conn == nil {
		return replicationEvidenceError(
			"verify historical attestations with nil database",
			nil,
		)
	}
	if err := verifyHistoricalAttestationInventory(conn, active); err != nil {
		return err
	}
	identities, err := historicalIdentityCatalog(conn)
	if err != nil {
		return replicationEvidenceError(
			"read retained historical identities",
			err,
		)
	}

	for generation := uint64(0); generation < active.recoveryGeneration; generation++ {
		sessionID, workspaceID, err := historicalGenesisIdentity(
			conn,
			generation,
		)
		if err != nil {
			return replicationEvidenceError(
				fmt.Sprintf(
					"read historical generation %d identity",
					generation,
				),
				err,
			)
		}
		state, err := logicalSnapshotSourceGenerationState(
			conn,
			active,
			generation,
			sessionID,
		)
		if err != nil {
			return replicationEvidenceError(
				fmt.Sprintf(
					"derive historical generation %d terminal cut",
					generation,
				),
				err,
			)
		}
		if err := verifyHistoricalGenerationAttestations(
			conn,
			state,
			workspaceID,
			identities,
		); err != nil {
			return replicationEvidenceError(
				fmt.Sprintf(
					"verify historical generation %d",
					generation,
				),
				err,
			)
		}
	}
	return nil
}

func verifyHistoricalAttestationInventory(
	conn *sqlite.Conn,
	active consensusState,
) error {
	var invalid int64
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM replication_attestations AS a
		   LEFT JOIN genesis_records AS g
		     ON g.session_id = a.session_id
		    AND g.recovery_generation = a.recovery_generation
		  WHERE NOT (
		        a.session_id = ?1
		    AND a.recovery_generation = ?2
		  )
		    AND (
		        g.recovery_generation IS NULL
		        OR a.recovery_generation >= ?2
		    );`,
		[]any{string(active.sessionID), active.recoveryGeneration},
		func(stmt *sqlite.Stmt) {
			invalid = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if invalid != 0 {
		return replicationEvidenceError(
			"non-active attestation lacks an exact predecessor genesis",
			nil,
		)
	}
	return nil
}

func historicalGenesisIdentity(
	conn *sqlite.Conn,
	generation uint64,
) (domain.UUIDv7, domain.UUIDv4, error) {
	var (
		sessionID   domain.UUIDv7
		workspaceID domain.UUIDv4
	)
	if err := queryOneArgs(
		conn,
		`SELECT session_id, workspace_id
		   FROM genesis_records
		  WHERE recovery_generation = ?1;`,
		[]any{generation},
		func(stmt *sqlite.Stmt) {
			sessionID = domain.UUIDv7(stmt.ColumnText(0))
			workspaceID = domain.UUIDv4(stmt.ColumnText(1))
		},
	); err != nil {
		return "", "", err
	}
	if !sessionID.Valid() || !workspaceID.Valid() {
		return "", "", errors.New(
			"historical genesis identity is malformed",
		)
	}
	return sessionID, workspaceID, nil
}

func historicalIdentityCatalog(
	conn *sqlite.Conn,
) (map[domain.DeviceID]device.Device, error) {
	result := make(map[domain.DeviceID]device.Device)
	err := streamProjectionLogicalRows(
		conn,
		func(row chain.LogicalRow) error {
			if row.Table != "devices" {
				return nil
			}
			member, err := decodeEvidenceDevice(row.Row)
			if err != nil {
				return err
			}
			if _, exists := result[member.ID]; exists {
				return errors.New("duplicate retained device identity")
			}
			result[member.ID] = cloneHistoricalDevice(member)
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func cloneHistoricalDevice(member device.Device) device.Device {
	member.IdentityPublicKey = bytes.Clone(member.IdentityPublicKey)
	return member
}

func verifyHistoricalGenerationAttestations(
	conn *sqlite.Conn,
	state consensusState,
	workspaceID domain.UUIDv4,
	identities map[domain.DeviceID]device.Device,
) error {
	genesis, err := readGenesisBoundary(
		conn,
		state.recoveryGeneration,
		state.sessionID,
	)
	if err != nil {
		return err
	}
	if err := validateHistoricalAttestationRanges(
		conn,
		state,
		workspaceID,
		genesis,
	); err != nil {
		return err
	}
	storedCount, err := activeAttestationCount(conn, state)
	if err != nil {
		return err
	}
	generationResults := state.resultIndex -
		genesis.predecessorResultIndex
	if storedCount < 0 ||
		uint64(storedCount) > generationResults+1 {
		return errors.New(
			"historical attestation count exceeds generation bounds",
		)
	}
	if storedCount == 0 {
		return nil
	}

	processed := int64(0)
	var coverage historicalAttestationCoverage
	var verifiedAuthority *replicationEvidenceAuthority
	snapshot, found, err := readLogicalSnapshotAttestation(conn, state)
	if err != nil {
		return err
	}
	if found {
		cut, authority, err := verifyHistoricalLogicalSnapshotAttestation(
			conn,
			state,
			workspaceID,
			genesis,
			snapshot,
			identities,
		)
		if err != nil {
			return err
		}
		coverage = historicalAttestationCoverage{
			found:       true,
			toResult:    cut.ResultIndex,
			stateDigest: chain.Digest(cut.ProjectionStateDigest),
		}
		verifiedAuthority = &authority
		processed++
	}

	searchAfter := genesis.predecessorResultIndex
	for searchAfter < state.resultIndex {
		from, found, err := nextHistoricalBatchStart(
			conn,
			state,
			searchAfter,
		)
		if err != nil {
			return err
		}
		if !found {
			break
		}
		attestation, found, err :=
			readReplicationAttestationStartingAt(
				conn,
				state,
				from,
			)
		if err != nil {
			return err
		}
		if !found {
			return errors.New(
				"historical attestation index lost its batch",
			)
		}
		if coverage.found {
			if coverage.toResult == domain.MaxSafeInteger ||
				attestation.fromResultIndex != coverage.toResult+1 ||
				chain.Digest(attestation.startProjectionStateDigest) !=
					coverage.stateDigest {
				return errors.New(
					"historical attestations are not a contiguous state-digest chain",
				)
			}
		} else if attestation.fromResultIndex !=
			genesis.predecessorResultIndex+1 ||
			attestation.startProjectionStateDigest !=
				genesis.stateDigest {
			return errors.New(
				"historical batch coverage does not begin at the generation boundary",
			)
		}
		metadata, authority, err := verifyHistoricalBatchAttestation(
			conn,
			state,
			workspaceID,
			genesis,
			attestation,
			identities,
			verifiedAuthority,
		)
		if err != nil {
			return err
		}
		coverage = historicalAttestationCoverage{
			found:       true,
			toResult:    metadata.ToResultIndex,
			stateDigest: metadata.EndProjectionStateDigest,
		}
		verifiedAuthority = &authority
		processed++
		searchAfter = from
	}
	if processed != storedCount {
		return errors.New(
			"historical attestation inventory contains an unvisited row",
		)
	}
	// The active logical-snapshot attestation covers genesis through the
	// installed cut. Retained predecessor attestations are additional audit
	// evidence and may end at any verified contiguous prefix before recovery.
	return nil
}

func nextHistoricalBatchStart(
	conn *sqlite.Conn,
	state consensusState,
	after uint64,
) (uint64, bool, error) {
	var (
		result uint64
		found  bool
		rowErr error
	)
	err := queryOneArgs(
		conn,
		`SELECT min(from_result_index)
		   FROM replication_attestations
		  WHERE attestation_kind = 'batch'
		    AND session_id = ?1 AND recovery_generation = ?2
		    AND from_result_index > ?3;`,
		[]any{string(state.sessionID), state.recoveryGeneration, after},
		func(stmt *sqlite.Stmt) {
			if stmt.ColumnType(0) == sqlite.TypeNull {
				return
			}
			value := stmt.ColumnInt64(0)
			if value < 1 {
				rowErr = errors.New(
					"historical batch has an invalid starting position",
				)
				return
			}
			result = uint64(value)
			found = true
		},
	)
	if err != nil {
		return 0, false, err
	}
	if rowErr != nil {
		return 0, false, rowErr
	}
	return result, found, nil
}

func validateHistoricalAttestationRanges(
	conn *sqlite.Conn,
	state consensusState,
	workspaceID domain.UUIDv4,
	genesis storedGenesisBoundary,
) error {
	var invalid int64
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM replication_attestations
		  WHERE session_id = ?1 AND recovery_generation = ?2
		    AND (
		        workspace_id != ?3
		        OR (
		            attestation_kind = 'batch'
		            AND (
		                from_result_index <= ?4
		                OR to_result_index > ?5
		                OR start_chain_index < ?6
		                OR end_chain_index > ?7
		                OR checkpoint_event_id IS NOT NULL
		            )
		        )
		        OR (
		            attestation_kind = 'snapshot'
		            AND (
		                from_result_index != 0
		                OR to_result_index <= ?4
		                OR to_result_index > ?5
		                OR server_applied_result_index IS NOT NULL
		                OR start_chain_index != 0
		                OR end_chain_index <= ?6
		                OR end_chain_index > ?7
		                OR checkpoint_event_id IS NULL
		            )
		        )
		    );`,
		[]any{
			string(state.sessionID),
			state.recoveryGeneration,
			string(workspaceID),
			genesis.predecessorResultIndex,
			state.resultIndex,
			genesis.predecessorChainIndex,
			state.chainIndex,
		},
		func(stmt *sqlite.Stmt) {
			invalid = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if invalid != 0 {
		return errors.New(
			"historical attestation lies outside its generation",
		)
	}
	return nil
}

func verifyHistoricalLogicalSnapshotAttestation(
	conn *sqlite.Conn,
	state consensusState,
	workspaceID domain.UUIDv4,
	genesis storedGenesisBoundary,
	attestation storedLogicalSnapshotAttestation,
	identities map[domain.DeviceID]device.Device,
) (LogicalSnapshotCut, replicationEvidenceAuthority, error) {
	cut, err := logicalSnapshotCutFromRoot(attestation.root)
	if err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}
	if attestation.sessionID != state.sessionID ||
		attestation.workspaceID != workspaceID ||
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
		cut.WorkspaceID != workspaceID ||
		cut.RecoveryGeneration != state.recoveryGeneration ||
		cut.ResultIndex > state.resultIndex ||
		cut.ChainIndex > state.chainIndex ||
		cut.DigestVersion != state.digestVersion ||
		cut.ProjectionSchemaVersion !=
			state.projectionSchemaVersion {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, errors.New(
			"historical snapshot root and attestation differ",
		)
	}
	start, startDigest, err := logicalSnapshotInitialBoundary(conn)
	if err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}
	if attestation.startResultHash != start.ResultHash ||
		attestation.startChainHash != start.ChainHash ||
		attestation.startProjectionAccumulator !=
			start.ProjectionAccumulator ||
		attestation.startProjectionStateDigest != startDigest {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, errors.New(
			"historical snapshot coverage does not begin at genesis",
		)
	}
	head, err := resultRangeStart(
		conn,
		state,
		genesis,
		cut.ResultIndex,
	)
	if err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}
	accumulator, err := projectionAccumulatorAtResultCut(
		conn,
		state,
		genesis,
		cut.ResultIndex,
	)
	if err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}
	if head.resultHash != cut.ResultHash ||
		head.chainIndex != cut.ChainIndex ||
		head.chainHash != cut.ChainHash ||
		accumulator != cut.ProjectionAccumulator {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, errors.New(
			"historical snapshot endpoint differs from retained commitments",
		)
	}

	authority, err := historicalEvidenceAuthorityAtResultCut(
		conn,
		state,
		cut.ResultIndex,
		cut.SignerDeviceID,
		cut.AuthorityVersion,
		identities,
	)
	if err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}
	rootSigner, err := logicalSnapshotAuthoritySigner(
		authority,
		cut.SignerDeviceID,
	)
	if err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}
	if err := logicalsnapshot.VerifyRoot(
		attestation.root,
		rootSigner.IdentityPublicKey,
	); err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}

	checkpoint, err := verifyLogicalSnapshotCheckpoint(
		conn,
		consensusState{
			sessionID:               state.sessionID,
			recoveryGeneration:      state.recoveryGeneration,
			chainIndex:              cut.ChainIndex,
			chainHash:               cut.ChainHash,
			resultIndex:             cut.ResultIndex,
			resultHash:              cut.ResultHash,
			projectionAccumulator:   cut.ProjectionAccumulator,
			digestVersion:           state.digestVersion,
			projectionSchemaVersion: state.projectionSchemaVersion,
		},
		cut.CheckpointEventID,
		false,
	)
	if err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}
	if checkpoint.WorkspaceID != workspaceID ||
		checkpoint.AuthorityVoterSetVersion != cut.AuthorityVersion {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, errors.New(
			"historical snapshot checkpoint differs from the root",
		)
	}
	if err := verifyLogicalSnapshotCheckpointKeepsAuthority(
		conn,
		checkpoint.CheckpointEventID,
	); err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}
	checkpointSigner, err := logicalSnapshotAuthoritySigner(
		authority,
		checkpoint.SignerDeviceID,
	)
	if err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}
	if err := codecommcrypto.VerifyEd25519(
		checkpointSigner.IdentityPublicKey,
		codec.SignatureCheckpoint,
		checkpoint.CheckpointJSON,
		checkpoint.AuthoritySignature[:],
	); err != nil {
		return LogicalSnapshotCut{}, replicationEvidenceAuthority{}, err
	}
	return cut, authority, nil
}

func verifyHistoricalBatchAttestation(
	conn *sqlite.Conn,
	state consensusState,
	workspaceID domain.UUIDv4,
	genesis storedGenesisBoundary,
	attestation storedReplicationAttestation,
	identities map[domain.DeviceID]device.Device,
	priorAuthority *replicationEvidenceAuthority,
) (replication.BatchMetadata, replicationEvidenceAuthority, error) {
	batch, encodedMutations, err := reconstructAttestedBatch(
		conn,
		state,
		attestation,
	)
	if err != nil {
		return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
	}
	metadata := batch.Unsigned().Metadata()
	if metadata.WorkspaceID != workspaceID ||
		metadata.FromResultIndex < 1 {
		return replication.BatchMetadata{}, replicationEvidenceAuthority{}, errors.New(
			"historical batch lineage is invalid",
		)
	}
	startCut := metadata.FromResultIndex - 1
	startHead, err := resultRangeStart(
		conn,
		state,
		genesis,
		startCut,
	)
	if err != nil {
		return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
	}
	startAccumulator, err := projectionAccumulatorAtResultCut(
		conn,
		state,
		genesis,
		startCut,
	)
	if err != nil {
		return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
	}
	endHead, err := resultRangeStart(
		conn,
		state,
		genesis,
		metadata.ToResultIndex,
	)
	if err != nil {
		return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
	}
	endAccumulator, err := projectionAccumulatorAtResultCut(
		conn,
		state,
		genesis,
		metadata.ToResultIndex,
	)
	if err != nil {
		return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
	}
	if metadata.StartResultHash != chain.Digest(startHead.resultHash) ||
		metadata.StartChainIndex != startHead.chainIndex ||
		metadata.StartChainHash != chain.Digest(startHead.chainHash) ||
		metadata.StartProjectionAccumulator !=
			chain.Digest(startAccumulator) ||
		metadata.EndResultHash != chain.Digest(endHead.resultHash) ||
		metadata.EndChainIndex != endHead.chainIndex ||
		metadata.EndChainHash != chain.Digest(endHead.chainHash) ||
		metadata.EndProjectionAccumulator !=
			chain.Digest(endAccumulator) {
		return replication.BatchMetadata{}, replicationEvidenceAuthority{}, errors.New(
			"historical batch endpoints differ from retained commitments",
		)
	}

	var authority replicationEvidenceAuthority
	if priorAuthority == nil {
		authority, err = historicalEvidenceAuthorityAtResultCut(
			conn,
			state,
			startCut,
			metadata.ServerDeviceID,
			metadata.ServerAuthorityVersion,
			identities,
		)
		if err != nil {
			return replication.BatchMetadata{},
				replicationEvidenceAuthority{},
				err
		}
	} else {
		authority = cloneHistoricalEvidenceAuthority(*priorAuthority)
	}
	input := batch.Unsigned().Input()
	resultHead := metadata.StartResultHash
	accumulator := metadata.StartProjectionAccumulator
	for index, encoded := range encodedMutations {
		mutations, err := chain.DecodeMutations(encoded)
		if err != nil {
			return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
		}
		result, err := chain.DecodeResult(input.Results[index])
		if err != nil {
			return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
		}
		signed, err := authority.verifyProposal(
			result.Proposal,
			state.sessionID,
			workspaceID,
		)
		if err != nil {
			return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
		}
		nextResult, _, err := chain.AppendResult(resultHead, result)
		if err != nil {
			return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
		}
		nextAccumulator, canonical, err := chain.AppendAccumulator(
			accumulator,
			result.ResultIndex,
			nextResult,
			mutations,
		)
		if err != nil || !bytes.Equal(canonical, encoded) {
			return replication.BatchMetadata{}, replicationEvidenceAuthority{}, errors.New(
				"historical batch mutation accumulator differs",
			)
		}
		if err := authority.apply(
			signed,
			result.ChainIndex != nil,
			mutations,
			workspaceID,
			state.recoveryGeneration,
		); err != nil {
			return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
		}
		resultHead = nextResult
		accumulator = nextAccumulator
	}
	if resultHead != metadata.EndResultHash ||
		accumulator != metadata.EndProjectionAccumulator ||
		authority.authority.SessionID != state.sessionID ||
		authority.authority.VoterSetVersion !=
			metadata.ServerAuthorityVersion {
		return replication.BatchMetadata{}, replicationEvidenceAuthority{}, errors.New(
			"historical batch does not end at its signed authority cut",
		)
	}
	signer, err := logicalSnapshotAuthoritySigner(
		authority,
		metadata.ServerDeviceID,
	)
	if err != nil {
		return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
	}
	if err := replication.VerifyBatch(
		batch,
		signer.IdentityPublicKey,
	); err != nil {
		return replication.BatchMetadata{}, replicationEvidenceAuthority{}, err
	}
	return metadata, authority, nil
}

func cloneHistoricalEvidenceAuthority(
	source replicationEvidenceAuthority,
) replicationEvidenceAuthority {
	devices := make(map[domain.DeviceID]device.Device, len(source.devices))
	for id, member := range source.devices {
		devices[id] = cloneHistoricalDevice(member)
	}
	return replicationEvidenceAuthority{
		devices:   devices,
		authority: source.authority,
	}
}

func historicalEvidenceAuthorityAtResultCut(
	conn *sqlite.Conn,
	state consensusState,
	resultCut uint64,
	fallbackSigner domain.DeviceID,
	fallbackVersion uint64,
	identities map[domain.DeviceID]device.Device,
) (replicationEvidenceAuthority, error) {
	if resultCut > state.resultIndex ||
		!fallbackSigner.Valid() ||
		fallbackVersion < 1 {
		return replicationEvidenceAuthority{},
			errors.New("invalid historical authority cut")
	}
	devices := make(map[domain.DeviceID]device.Device, len(identities))
	for id, member := range identities {
		devices[id] = cloneHistoricalDevice(member)
	}
	decidedDevices := make(map[domain.DeviceID]bool)
	var (
		authority      credentialauthority.Authority
		authorityFound bool
		rowErr         error
	)
	err := queryArgs(
		conn,
		`SELECT result_index, projection_mutations_json
		   FROM command_results
		  WHERE session_id = ?1 AND recovery_generation = ?2
		  ORDER BY result_index;`,
		[]any{string(state.sessionID), state.recoveryGeneration},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			storedIndex := stmt.ColumnInt64(0)
			if storedIndex < 1 {
				rowErr = errors.New(
					"historical authority result index is invalid",
				)
				return
			}
			index := uint64(storedIndex)
			encoded := []byte(stmt.ColumnText(1))
			mutations, err := chain.DecodeMutations(encoded)
			if err != nil {
				rowErr = err
				return
			}
			canonical, err := chain.EncodeMutations(mutations)
			if err != nil || !bytes.Equal(canonical, encoded) {
				rowErr = errors.New(
					"historical authority mutations do not round trip",
				)
				return
			}
			authorityMutations := 0
			for _, mutation := range mutations {
				switch mutation.Table {
				case "devices":
					before, after, err := historicalDeviceMutation(
						mutation,
						identities,
					)
					if err != nil {
						rowErr = err
						return
					}
					id := after.ID
					if index <= resultCut {
						devices[id] = after
						decidedDevices[id] = true
					} else if !decidedDevices[id] {
						if before == nil {
							delete(devices, id)
						} else {
							devices[id] = *before
						}
						decidedDevices[id] = true
					}
				case "credential_authority":
					authorityMutations++
					if authorityMutations > 1 ||
						mutation.Before == nil ||
						mutation.After == nil {
						rowErr = errors.New(
							"historical result has an invalid authority mutation",
						)
						return
					}
					before, err := decodeEvidenceAuthority(
						mutation.Before,
					)
					if err != nil {
						rowErr = err
						return
					}
					after, err := decodeEvidenceAuthority(
						mutation.After,
					)
					if err != nil {
						rowErr = err
						return
					}
					if before.SessionID != state.sessionID ||
						after.SessionID != state.sessionID {
						rowErr = errors.New(
							"historical authority changes session",
						)
						return
					}
					if index <= resultCut {
						authority = after
						authorityFound = true
					} else if !authorityFound {
						authority = before
						authorityFound = true
					}
				}
			}
		},
	)
	if err != nil {
		return replicationEvidenceAuthority{}, err
	}
	if rowErr != nil {
		return replicationEvidenceAuthority{}, rowErr
	}
	if !authorityFound {
		if fallbackVersion != 1 {
			return replicationEvidenceAuthority{}, errors.New(
				"historical non-genesis authority lacks a retained transition",
			)
		}
		genesisSigner, err := historicalGenesisAuthoritySigner(
			conn,
			state,
			identities,
		)
		if err != nil {
			return replicationEvidenceAuthority{}, err
		}
		if fallbackSigner != genesisSigner {
			return replicationEvidenceAuthority{}, errors.New(
				"historical signer differs from the genesis authority",
			)
		}
		authority = credentialauthority.Authority{
			SessionID:        state.sessionID,
			VoterDeviceIDs:   []domain.DeviceID{genesisSigner},
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		}
	}
	if err := authority.Validate(); err != nil {
		return replicationEvidenceAuthority{}, err
	}
	if authority.VoterSetVersion != fallbackVersion ||
		!authority.Contains(fallbackSigner) {
		return replicationEvidenceAuthority{}, errors.New(
			"historical signer is outside the retained authority",
		)
	}
	for _, voterID := range authority.VoterDeviceIDs {
		member, found := devices[voterID]
		if !found {
			return replicationEvidenceAuthority{}, errors.New(
				"historical authority voter has no retained identity",
			)
		}
		member.Status = device.StatusActive
		devices[voterID] = member
	}
	return replicationEvidenceAuthority{
		devices:   devices,
		authority: authority,
	}, nil
}

func historicalGenesisAuthoritySigner(
	conn *sqlite.Conn,
	state consensusState,
	identities map[domain.DeviceID]device.Device,
) (domain.DeviceID, error) {
	var (
		proposalJSON []byte
		count        int
	)
	if err := queryArgs(
		conn,
		`SELECT proposal_json
		   FROM command_results
		  WHERE session_id = ?1 AND recovery_generation = ?2
		    AND chain_index IS NOT NULL
		  ORDER BY result_index
		  LIMIT 1;`,
		[]any{string(state.sessionID), state.recoveryGeneration},
		func(stmt *sqlite.Stmt) {
			count++
			proposalJSON = bytes.Clone([]byte(stmt.ColumnText(0)))
		},
	); err != nil {
		return "", err
	}
	if count != 1 {
		return "", errors.New(
			"historical attestation generation has no accepted bootstrap event",
		)
	}
	proposal, err := event.InspectUnverifiedProposal(proposalJSON)
	if err != nil {
		return "", err
	}
	member, found := identities[proposal.Origin.DeviceID()]
	if !found {
		return "", errors.New(
			"historical bootstrap signer has no retained identity",
		)
	}
	workspaceID, err := activeWorkspaceID(conn, state)
	if err != nil {
		return "", err
	}
	if _, err := event.ParseAndVerify(
		proposalJSON,
		event.VerificationContext{
			SessionID:         state.sessionID,
			WorkspaceID:       workspaceID,
			IdentityPublicKey: member.IdentityPublicKey,
		},
	); err != nil {
		return "", err
	}
	return member.ID, nil
}

func historicalDeviceMutation(
	mutation chain.Mutation,
	identities map[domain.DeviceID]device.Device,
) (*device.Device, device.Device, error) {
	if mutation.After == nil {
		return nil, device.Device{},
			errors.New("historical device projection was deleted")
	}
	after, err := decodeEvidenceDevice(mutation.After)
	if err != nil {
		return nil, device.Device{}, err
	}
	retained, found := identities[after.ID]
	if !found ||
		!bytes.Equal(
			retained.IdentityPublicKey,
			after.IdentityPublicKey,
		) {
		return nil, device.Device{},
			errors.New("historical device identity is not retained")
	}
	if mutation.Before == nil {
		return nil, after, nil
	}
	before, err := decodeEvidenceDevice(mutation.Before)
	if err != nil {
		return nil, device.Device{}, err
	}
	if before.ID != after.ID ||
		!bytes.Equal(
			before.IdentityPublicKey,
			after.IdentityPublicKey,
		) {
		return nil, device.Device{},
			errors.New("historical device mutation changes identity")
	}
	return &before, after, nil
}
