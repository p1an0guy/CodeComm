package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const (
	MaxResultRangeItems = 256
	MaxResultRangeBytes = 64 << 20
)

var (
	ErrResultRangeNotCovered = errors.New(
		"store: result range is not covered by the active generation",
	)
	ErrResultRangeSnapshotRequired = errors.New(
		"store: result range requires a generation snapshot",
	)
	ErrResultRangeAuthorityNotCovered = errors.New(
		"store: result range cannot end at the required authority",
	)
	ErrResultRangeTooLarge = errors.New(
		"store: first result exceeds the requested range byte limit",
	)
)

// ResultRangeOptions bounds one immutable result export. MaxBytes measures
// the encoded JSON results array, including brackets and commas.
type ResultRangeOptions struct {
	AfterResultIndex          uint64
	MaxResults                int
	MaxBytes                  int
	RequiredAuthorityDeviceID domain.DeviceID
}

func (options ResultRangeOptions) validate() error {
	if !domain.ValidUnsignedInteger(options.AfterResultIndex) ||
		options.MaxResults < 1 ||
		options.MaxResults > MaxResultRangeItems ||
		options.MaxBytes < 2 ||
		options.MaxBytes > MaxResultRangeBytes ||
		options.RequiredAuthorityDeviceID != "" &&
			!options.RequiredAuthorityDeviceID.Valid() {
		return fmt.Errorf("%w: invalid result-range options", ErrInvalidOptions)
	}
	return nil
}

// ResultRange is a contiguous, integrity-verified range from the active
// generation. Authority is the credential authority in effect at the end
// position and is intentionally not part of the wire results array.
type ResultRange struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64

	FromResultIndex uint64
	ToResultIndex   uint64
	StartResultHash Digest
	EndResultHash   Digest
	StartChainIndex uint64
	StartChainHash  Digest
	EndChainIndex   uint64
	EndChainHash    Digest
	Results         [][]byte

	ServerAppliedResultIndex uint64
	Authority                voterset.Set
}

// ExportResultRange returns the next nonempty bounded result range after the
// supplied dense result position. A current cursor returns found=false.
// Before returning records, it replays the active generation's complete
// retained commitments in the same read transaction.
func (store *Store) ExportResultRange(
	ctx context.Context,
	options ResultRangeOptions,
) (ResultRange, bool, error) {
	if ctx == nil {
		return ResultRange{}, false, fmt.Errorf(
			"%w: nil context",
			ErrInvalidOptions,
		)
	}
	if err := ctx.Err(); err != nil {
		return ResultRange{}, false, err
	}
	if err := options.validate(); err != nil {
		return ResultRange{}, false, err
	}

	var (
		exported ResultRange
		found    bool
	)
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)

		end := sqlitex.Transaction(conn)
		defer end(&err)

		state, hasState, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !hasState {
			return fmt.Errorf(
				"%w: active generation is missing",
				ErrResultRangeNotCovered,
			)
		}
		genesis, err := readGenesisBoundary(
			conn,
			state.recoveryGeneration,
			state.sessionID,
		)
		if err != nil {
			return err
		}
		if options.AfterResultIndex < genesis.predecessorResultIndex {
			return fmt.Errorf(
				"%w: cursor %d precedes generation boundary %d",
				ErrResultRangeSnapshotRequired,
				options.AfterResultIndex,
				genesis.predecessorResultIndex,
			)
		}
		if options.AfterResultIndex > state.resultIndex {
			return fmt.Errorf(
				"%w: cursor %d outside [%d,%d]",
				ErrResultRangeNotCovered,
				options.AfterResultIndex,
				genesis.predecessorResultIndex,
				state.resultIndex,
			)
		}
		if err := verifyCommitmentHistory(conn, state); err != nil {
			return err
		}
		if options.AfterResultIndex == state.resultIndex {
			return nil
		}

		start, err := resultRangeStart(
			conn,
			state,
			genesis,
			options.AfterResultIndex,
		)
		if err != nil {
			return err
		}
		authorization, err := resultRangeAuthorizationAt(
			conn,
			state,
			options.AfterResultIndex,
			options.RequiredAuthorityDeviceID,
		)
		if err != nil {
			return err
		}
		records, err := resultRangeRecords(
			conn,
			state,
			options.AfterResultIndex,
			options.MaxResults,
		)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			return historyIntegrityError(
				"covered result range is unexpectedly empty",
				nil,
			)
		}

		results := make([][]byte, 0, len(records))
		heads := make([]resultRangeHead, 1, len(records)+1)
		heads[0] = start
		authorizations := make(
			[]resultRangeAuthorization,
			1,
			len(records)+1,
		)
		authorizations[0] = authorization
		resultHead := start.resultHash
		chainIndex := start.chainIndex
		chainHead := start.chainHash
		encodedBytes := 2
		for _, record := range records {
			stored, exists, err := readStoredCommandResult(
				conn,
				record.eventID,
			)
			if err != nil {
				return err
			}
			if !exists ||
				stored.sessionID != state.sessionID ||
				stored.recoveryGeneration != state.recoveryGeneration {
				return historyIntegrityError(
					"result-range position crosses the active lineage",
					nil,
				)
			}
			if err := verifyStoredCommandResult(conn, stored); err != nil {
				return err
			}
			expectedIndex := options.AfterResultIndex +
				uint64(len(results)) + 1
			if stored.resultIndex != expectedIndex ||
				stored.previousResultHash != resultHead {
				return historyIntegrityError(
					"result range is not dense",
					nil,
				)
			}
			resultInput := chain.Result{
				ResultIndex:    stored.resultIndex,
				Proposal:       stored.proposalJSON,
				Outcome:        stored.outcome.JSON,
				ProposalDigest: chain.Digest(stored.proposalDigest),
			}
			nextChainIndex := chainIndex
			nextChainHead := chainHead
			if stored.chainIndex != nil {
				if chainIndex == domain.MaxSafeInteger ||
					*stored.chainIndex != chainIndex+1 ||
					stored.chainHash == nil {
					return historyIntegrityError(
						"event range is not dense",
						nil,
					)
				}
				computed, err := chain.AppendEvent(
					chain.Digest(chainHead),
					stored.proposalJSON,
				)
				if err != nil ||
					computed != chain.Digest(*stored.chainHash) {
					return historyIntegrityError(
						"event range link differs",
						err,
					)
				}
				nextChainIndex = *stored.chainIndex
				nextChainHead = *stored.chainHash
				value := nextChainIndex
				hash := chain.Digest(nextChainHead)
				resultInput.ChainIndex = &value
				resultInput.ChainHash = &hash
			}
			nextResult, encoded, err := chain.AppendResult(
				chain.Digest(resultHead),
				resultInput,
			)
			if err != nil ||
				nextResult != chain.Digest(stored.resultHash) {
				return historyIntegrityError(
					"result range link differs",
					err,
				)
			}

			addedBytes := len(encoded)
			if len(results) != 0 {
				addedBytes++
			}
			if addedBytes > options.MaxBytes-encodedBytes {
				if len(results) == 0 {
					return fmt.Errorf(
						"%w: result %d requires %d bytes, limit %d",
						ErrResultRangeTooLarge,
						stored.resultIndex,
						encodedBytes+addedBytes,
						options.MaxBytes,
					)
				}
				break
			}
			encodedBytes += addedBytes
			results = append(results, bytes.Clone(encoded))
			resultHead = Digest(nextResult)
			chainIndex = nextChainIndex
			chainHead = nextChainHead
			heads = append(heads, resultRangeHead{
				resultHash: resultHead,
				chainIndex: chainIndex,
				chainHash:  chainHead,
			})
			nextAuthorization := authorizations[len(authorizations)-1]
			if record.authorizationChange {
				nextAuthorization, err = resultRangeAuthorizationAt(
					conn,
					state,
					expectedIndex,
					options.RequiredAuthorityDeviceID,
				)
				if err != nil {
					return err
				}
			}
			authorizations = append(authorizations, nextAuthorization)
		}

		authorization = authorizations[len(results)]
		if required := options.RequiredAuthorityDeviceID; required != "" {
			for !authorization.permits(required) {
				if len(results) == 1 {
					return fmt.Errorf(
						"%w: device %s is not an active authority through result %d",
						ErrResultRangeAuthorityNotCovered,
						required,
						options.AfterResultIndex+1,
					)
				}
				results = results[:len(results)-1]
				authorization = authorizations[len(results)]
			}
			selected := heads[len(results)]
			resultHead = selected.resultHash
			chainIndex = selected.chainIndex
			chainHead = selected.chainHash
		}
		workspaceID, err := resultRangeWorkspaceID(
			conn,
			state,
		)
		if err != nil {
			return err
		}
		exported = ResultRange{
			SessionID:                state.sessionID,
			WorkspaceID:              workspaceID,
			RecoveryGeneration:       state.recoveryGeneration,
			FromResultIndex:          options.AfterResultIndex + 1,
			ToResultIndex:            options.AfterResultIndex + uint64(len(results)),
			StartResultHash:          start.resultHash,
			EndResultHash:            resultHead,
			StartChainIndex:          start.chainIndex,
			StartChainHash:           start.chainHash,
			EndChainIndex:            chainIndex,
			EndChainHash:             chainHead,
			Results:                  results,
			ServerAppliedResultIndex: state.resultIndex,
			Authority:                authorization.authority,
		}
		found = true
		return nil
	})
	if err != nil {
		return ResultRange{}, false, err
	}
	return exported, found, nil
}

// ExportResultRange exposes verified result history through the restricted
// local-state capability without exposing Store lifecycle or SQLite access.
func (state LocalState) ExportResultRange(
	ctx context.Context,
	options ResultRangeOptions,
) (ResultRange, bool, error) {
	if state.store == nil {
		return ResultRange{}, false, ErrInvalidLocalState
	}
	return state.store.ExportResultRange(ctx, options)
}

type resultRangeHead struct {
	resultHash Digest
	chainIndex uint64
	chainHash  Digest
}

func resultRangeStart(
	conn *sqlite.Conn,
	state consensusState,
	genesis storedGenesisBoundary,
	afterResultIndex uint64,
) (resultRangeHead, error) {
	genesisDigest, err := chain.GenesisDigest(genesis.genesisJSON)
	if err != nil ||
		genesisDigest != chain.Digest(genesis.genesisDigest) {
		return resultRangeHead{},
			historyIntegrityError("result-range generation boundary", err)
	}
	boundary := chain.Boundary{
		Genesis:     genesisDigest,
		Generation:  state.recoveryGeneration,
		ChainIndex:  genesis.predecessorChainIndex,
		ResultIndex: genesis.predecessorResultIndex,
		ChainHash:   chain.Digest(genesis.predecessorChainHash),
		ResultHash:  chain.Digest(genesis.predecessorResultHash),
	}
	eventSeed, err := chain.EventSeed(boundary)
	if err != nil {
		return resultRangeHead{}, historyIntegrityError("event seed", err)
	}
	resultSeed, err := chain.ResultSeed(boundary)
	if err != nil {
		return resultRangeHead{}, historyIntegrityError("result seed", err)
	}
	start := resultRangeHead{
		resultHash: Digest(resultSeed),
		chainIndex: genesis.predecessorChainIndex,
		chainHash:  Digest(eventSeed),
	}
	if afterResultIndex > genesis.predecessorResultIndex {
		stored, err := storedResultAtResultIndex(conn, afterResultIndex)
		if err != nil {
			return resultRangeHead{}, err
		}
		if stored.sessionID != state.sessionID ||
			stored.recoveryGeneration != state.recoveryGeneration {
			return resultRangeHead{},
				historyIntegrityError("result cursor crosses generation", nil)
		}
		start.resultHash = stored.resultHash
	}

	var (
		acceptedID string
		count      int
	)
	if err := queryArgs(
		conn,
		`SELECT event_id
		   FROM command_results
		  WHERE session_id = ?1
		    AND recovery_generation = ?2
		    AND result_index <= ?3
		    AND chain_index IS NOT NULL
		  ORDER BY result_index DESC
		  LIMIT 1;`,
		[]any{
			string(state.sessionID),
			state.recoveryGeneration,
			afterResultIndex,
		},
		func(stmt *sqlite.Stmt) {
			count++
			acceptedID = stmt.ColumnText(0)
		},
	); err != nil {
		return resultRangeHead{}, err
	}
	if count > 1 {
		return resultRangeHead{},
			historyIntegrityError("duplicate event cursor row", nil)
	}
	if count == 1 {
		stored, exists, err := readStoredCommandResult(
			conn,
			domain.UUIDv7(acceptedID),
		)
		if err != nil {
			return resultRangeHead{}, err
		}
		if !exists ||
			stored.chainIndex == nil ||
			stored.chainHash == nil ||
			stored.sessionID != state.sessionID ||
			stored.recoveryGeneration != state.recoveryGeneration {
			return resultRangeHead{},
				historyIntegrityError("invalid event cursor row", nil)
		}
		start.chainIndex = *stored.chainIndex
		start.chainHash = *stored.chainHash
	}
	return start, nil
}

type resultRangeRecord struct {
	eventID             domain.UUIDv7
	authorizationChange bool
}

func resultRangeRecords(
	conn *sqlite.Conn,
	state consensusState,
	afterResultIndex uint64,
	limit int,
) ([]resultRangeRecord, error) {
	result := make([]resultRangeRecord, 0, limit)
	var rowErr error
	err := queryArgs(
		conn,
		`SELECT r.event_id,
		        EXISTS (
		            SELECT 1
		              FROM json_each(r.projection_mutations_json) AS mutation
		             WHERE json_extract(mutation.value, '$.table')
		                   IN ('devices', 'credential_authority')
		        )
		   FROM command_results AS r
		  WHERE r.session_id = ?1
		    AND r.recovery_generation = ?2
		    AND r.result_index > ?3
		  ORDER BY r.result_index
		  LIMIT ?4;`,
		[]any{
			string(state.sessionID),
			state.recoveryGeneration,
			afterResultIndex,
			limit,
		},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			eventID := domain.UUIDv7(stmt.ColumnText(0))
			if !eventID.Valid() {
				rowErr = errors.New("invalid result event ID")
				return
			}
			result = append(result, resultRangeRecord{
				eventID:             eventID,
				authorizationChange: stmt.ColumnBool(1),
			})
		},
	)
	if err != nil {
		return nil, err
	}
	if rowErr != nil {
		return nil, historyIntegrityError("result-range IDs", rowErr)
	}
	return result, nil
}

func resultRangeWorkspaceID(
	conn *sqlite.Conn,
	state consensusState,
) (domain.UUIDv4, error) {
	var workspaceID domain.UUIDv4
	if err := queryOneArgs(
		conn,
		`SELECT workspace_id
		   FROM genesis_records
		  WHERE recovery_generation = ?1 AND session_id = ?2;`,
		[]any{state.recoveryGeneration, string(state.sessionID)},
		func(stmt *sqlite.Stmt) {
			workspaceID = domain.UUIDv4(stmt.ColumnText(0))
		},
	); err != nil {
		return "", err
	}
	if !workspaceID.Valid() {
		return "", historyIntegrityError("invalid result-range workspace", nil)
	}
	return workspaceID, nil
}

type resultRangeAuthorization struct {
	authority    voterset.Set
	signerActive bool
}

func (authorization resultRangeAuthorization) permits(
	deviceID domain.DeviceID,
) bool {
	return deviceID == "" ||
		authorization.signerActive &&
			authorization.authority.Contains(deviceID)
}

func resultRangeAuthorizationAt(
	conn *sqlite.Conn,
	state consensusState,
	resultIndex uint64,
	requiredDeviceID domain.DeviceID,
) (resultRangeAuthorization, error) {
	rows, err := projectionRowsAtResultCut(conn, state, resultIndex)
	if err != nil {
		return resultRangeAuthorization{},
			historyIntegrityError("reconstruct result-range authority", err)
	}
	var (
		authorization  resultRangeAuthorization
		authorityFound bool
		deviceFound    bool
	)
	for _, row := range rows {
		switch row.Table {
		case "credential_authority":
			if authorityFound {
				return resultRangeAuthorization{},
					historyIntegrityError(
						"duplicate credential authority",
						nil,
					)
			}
			var wire struct {
				SessionID       string   `json:"session_id"`
				VoterDeviceIDs  []string `json:"voter_device_ids"`
				VoterSetVersion uint64   `json:"voter_set_version"`
			}
			if err := json.Unmarshal(row.Row, &wire); err != nil {
				return resultRangeAuthorization{},
					historyIntegrityError(
						"decode credential authority",
						err,
					)
			}
			if domain.UUIDv7(wire.SessionID) != state.sessionID {
				return resultRangeAuthorization{},
					historyIntegrityError(
						"credential authority session differs",
						nil,
					)
			}
			voters := make(
				[]domain.DeviceID,
				len(wire.VoterDeviceIDs),
			)
			for index, encoded := range wire.VoterDeviceIDs {
				voters[index] = domain.DeviceID(encoded)
			}
			authorization.authority, err = voterset.New(
				state.sessionID,
				voters,
				wire.VoterSetVersion,
			)
			if err != nil {
				return resultRangeAuthorization{},
					historyIntegrityError(
						"invalid credential authority",
						err,
					)
			}
			authorityFound = true
		case "devices":
			if requiredDeviceID == "" {
				continue
			}
			var wire struct {
				DeviceID string `json:"device_id"`
				Status   string `json:"status"`
			}
			if err := json.Unmarshal(row.Row, &wire); err != nil {
				return resultRangeAuthorization{},
					historyIntegrityError("decode authority device", err)
			}
			deviceID := domain.DeviceID(wire.DeviceID)
			status := device.Status(wire.Status)
			if !deviceID.Valid() || !status.Valid() {
				return resultRangeAuthorization{},
					historyIntegrityError("invalid authority device", nil)
			}
			if deviceID != requiredDeviceID {
				continue
			}
			if deviceFound {
				return resultRangeAuthorization{},
					historyIntegrityError("duplicate authority device", nil)
			}
			deviceFound = true
			authorization.signerActive = status == device.StatusActive
		}
	}
	if !authorityFound {
		return resultRangeAuthorization{},
			historyIntegrityError("credential authority is missing", nil)
	}
	if requiredDeviceID != "" &&
		authorization.authority.Contains(requiredDeviceID) &&
		!deviceFound {
		return resultRangeAuthorization{},
			historyIntegrityError("authority device is missing", nil)
	}
	return authorization, nil
}
