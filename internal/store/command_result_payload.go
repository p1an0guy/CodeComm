package store

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

const (
	commandResultPayloadCodecVersion = uint32(1)
	commandResultPayloadHeaderBytes  = 20
	maxCommandResultPayloadBytes     = 36 << 20
	maxCommandResultCompressedBytes  = 36 << 20
	maxCommandResultProposalBytes    = 1 << 20
	maxCommandResultOutcomeBytes     = 1 << 20
	maxCommandResultMutationsBytes   = 32 << 20
	commandResultObjectSentinel      = "{}"
	commandResultMutationsSentinel   = "[]"
)

var commandResultPayloadMagic = [4]byte{'C', 'C', 'R', 'P'}

type commandResultPayload struct {
	proposal  []byte
	outcome   []byte
	mutations []byte
}

type storedCommandResultPayload struct {
	codecVersion     uint32
	uncompressedSize int
	checksum         Digest
	compressed       []byte
}

type commandResultPayloadInventoryRow struct {
	resultIndex    uint64
	eventID        domain.UUIDv7
	proposalDigest Digest
	outcomeStatus  OutcomeStatus
	outcomeCode    string
	payload        commandResultPayload
}

func encodeCommandResultPayload(
	payload commandResultPayload,
) (storedCommandResultPayload, error) {
	if err := validateCommandResultPayload(payload); err != nil {
		return storedCommandResultPayload{}, err
	}
	size := commandResultPayloadHeaderBytes +
		len(payload.proposal) +
		len(payload.outcome) +
		len(payload.mutations)
	if size > maxCommandResultPayloadBytes {
		return storedCommandResultPayload{}, commandResultPayloadError(
			"uncompressed frame exceeds limit",
			nil,
		)
	}
	frame := make([]byte, commandResultPayloadHeaderBytes, size)
	copy(frame[:4], commandResultPayloadMagic[:])
	binary.BigEndian.PutUint32(frame[4:8], commandResultPayloadCodecVersion)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload.proposal)))
	binary.BigEndian.PutUint32(frame[12:16], uint32(len(payload.outcome)))
	binary.BigEndian.PutUint32(frame[16:20], uint32(len(payload.mutations)))
	frame = append(frame, payload.proposal...)
	frame = append(frame, payload.outcome...)
	frame = append(frame, payload.mutations...)

	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		return storedCommandResultPayload{}, commandResultPayloadError(
			"initialize compressor",
			err,
		)
	}
	if _, err := writer.Write(frame); err != nil {
		_ = writer.Close()
		return storedCommandResultPayload{}, commandResultPayloadError(
			"compress frame",
			err,
		)
	}
	if err := writer.Close(); err != nil {
		return storedCommandResultPayload{}, commandResultPayloadError(
			"finish compressed frame",
			err,
		)
	}
	if compressed.Len() < 1 ||
		compressed.Len() > maxCommandResultCompressedBytes {
		return storedCommandResultPayload{}, commandResultPayloadError(
			"compressed frame exceeds limit",
			nil,
		)
	}
	return storedCommandResultPayload{
		codecVersion:     commandResultPayloadCodecVersion,
		uncompressedSize: len(frame),
		checksum:         Digest(sha256.Sum256(frame)),
		compressed:       bytes.Clone(compressed.Bytes()),
	}, nil
}

func decodeCommandResultPayload(
	stored storedCommandResultPayload,
) (commandResultPayload, error) {
	if stored.codecVersion != commandResultPayloadCodecVersion {
		return commandResultPayload{}, commandResultPayloadError(
			"unsupported codec version",
			nil,
		)
	}
	if stored.uncompressedSize < commandResultPayloadHeaderBytes+6 ||
		stored.uncompressedSize > maxCommandResultPayloadBytes ||
		len(stored.compressed) < 1 ||
		len(stored.compressed) > maxCommandResultCompressedBytes {
		return commandResultPayload{}, commandResultPayloadError(
			"invalid stored payload size",
			nil,
		)
	}

	source := bytes.NewReader(stored.compressed)
	reader := flate.NewReader(source)
	frame, readErr := io.ReadAll(io.LimitReader(
		reader,
		int64(stored.uncompressedSize)+1,
	))
	closeErr := reader.Close()
	if readErr != nil {
		return commandResultPayload{}, commandResultPayloadError(
			"decompress frame",
			readErr,
		)
	}
	if closeErr != nil {
		return commandResultPayload{}, commandResultPayloadError(
			"close decompressor",
			closeErr,
		)
	}
	if len(frame) != stored.uncompressedSize {
		return commandResultPayload{}, commandResultPayloadError(
			"decompressed size differs",
			nil,
		)
	}
	if source.Len() != 0 {
		return commandResultPayload{}, commandResultPayloadError(
			"compressed frame has trailing bytes",
			nil,
		)
	}
	if Digest(sha256.Sum256(frame)) != stored.checksum {
		return commandResultPayload{}, commandResultPayloadError(
			"uncompressed checksum differs",
			nil,
		)
	}
	if len(frame) < commandResultPayloadHeaderBytes ||
		!bytes.Equal(frame[:4], commandResultPayloadMagic[:]) ||
		binary.BigEndian.Uint32(frame[4:8]) !=
			commandResultPayloadCodecVersion {
		return commandResultPayload{}, commandResultPayloadError(
			"invalid frame header",
			nil,
		)
	}
	proposalSize := int(binary.BigEndian.Uint32(frame[8:12]))
	outcomeSize := int(binary.BigEndian.Uint32(frame[12:16]))
	mutationsSize := int(binary.BigEndian.Uint32(frame[16:20]))
	if proposalSize > maxCommandResultProposalBytes ||
		outcomeSize > maxCommandResultOutcomeBytes ||
		mutationsSize > maxCommandResultMutationsBytes ||
		proposalSize < 2 ||
		outcomeSize < 2 ||
		mutationsSize < 2 ||
		commandResultPayloadHeaderBytes+
			proposalSize+outcomeSize+mutationsSize != len(frame) {
		return commandResultPayload{}, commandResultPayloadError(
			"invalid frame component lengths",
			nil,
		)
	}
	offset := commandResultPayloadHeaderBytes
	payload := commandResultPayload{
		proposal: bytes.Clone(frame[offset : offset+proposalSize]),
	}
	offset += proposalSize
	payload.outcome = bytes.Clone(frame[offset : offset+outcomeSize])
	offset += outcomeSize
	payload.mutations = bytes.Clone(frame[offset : offset+mutationsSize])
	if err := validateCommandResultPayload(payload); err != nil {
		return commandResultPayload{}, err
	}
	return payload, nil
}

func validateCommandResultPayload(payload commandResultPayload) error {
	if len(payload.proposal) > maxCommandResultProposalBytes ||
		len(payload.outcome) > maxCommandResultOutcomeBytes ||
		len(payload.mutations) > maxCommandResultMutationsBytes {
		return commandResultPayloadError("component exceeds limit", nil)
	}
	canonical, err := codec.CanonicalizeSignedObject(payload.proposal)
	if err != nil || !bytes.Equal(canonical, payload.proposal) {
		return commandResultPayloadError("proposal is not canonical", err)
	}
	canonical, err = codec.CanonicalizeSignedObject(payload.outcome)
	if err != nil || !bytes.Equal(canonical, payload.outcome) {
		return commandResultPayloadError("outcome is not canonical", err)
	}
	mutations, err := chain.DecodeMutations(payload.mutations)
	if err != nil {
		return commandResultPayloadError("decode mutations", err)
	}
	canonical, err = chain.EncodeMutations(mutations)
	if err != nil || !bytes.Equal(canonical, payload.mutations) {
		return commandResultPayloadError("mutations do not round trip", err)
	}
	return nil
}

func commandResultPayloadError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: command-result payload %s", ErrCommandResultCorrupt, detail)
	}
	return fmt.Errorf(
		"%w: command-result payload %s: %w",
		ErrCommandResultCorrupt,
		detail,
		cause,
	)
}

func writeCommandResultPayload(
	conn *sqlite.Conn,
	resultIndex uint64,
	payload commandResultPayload,
) error {
	encoded, err := encodeCommandResultPayload(payload)
	if err != nil {
		return err
	}
	return execute(
		conn,
		`INSERT INTO command_result_payloads(
		    result_index, codec_version, uncompressed_size,
		    uncompressed_sha256, compressed_payload
		) VALUES (?1, ?2, ?3, ?4, ?5);`,
		resultIndex,
		uint64(encoded.codecVersion),
		encoded.uncompressedSize,
		encoded.checksum[:],
		encoded.compressed,
	)
}

func readCompactedCommandResultPayload(
	conn *sqlite.Conn,
	resultIndex uint64,
) (commandResultPayload, bool, error) {
	var (
		stored storedCommandResultPayload
		count  int
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT codec_version, uncompressed_size, uncompressed_sha256,
		        compressed_payload
		   FROM command_result_payloads
		  WHERE result_index = ?1;`,
		[]any{resultIndex},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				return
			}
			version := stmt.ColumnInt64(0)
			size := stmt.ColumnInt64(1)
			if version < 1 || version > int64(^uint32(0)) ||
				size < 0 || size > maxCommandResultPayloadBytes {
				rowErr = errors.New("invalid payload metadata")
				return
			}
			stored.codecVersion = uint32(version)
			stored.uncompressedSize = int(size)
			if rowErr = copyDigestColumn(&stored.checksum, stmt, 2); rowErr != nil {
				return
			}
			if stmt.ColumnType(3) != sqlite.TypeBlob {
				rowErr = errors.New("compressed payload is not a blob")
				return
			}
			stored.compressed = bytes.Clone(columnBytes(stmt, 3))
		},
	)
	if err != nil {
		return commandResultPayload{}, false, err
	}
	if rowErr != nil {
		return commandResultPayload{}, false,
			commandResultPayloadError("invalid storage row", rowErr)
	}
	if count > 1 {
		return commandResultPayload{}, false,
			commandResultPayloadError("duplicate storage rows", nil)
	}
	if count == 0 {
		return commandResultPayload{}, false, nil
	}
	payload, err := decodeCommandResultPayload(stored)
	if err != nil {
		return commandResultPayload{}, false, err
	}
	return payload, true, nil
}

func readCommandResultPayload(
	conn *sqlite.Conn,
	resultIndex uint64,
) (commandResultPayload, bool, error) {
	var (
		payload commandResultPayload
		count   int
		rowErr  error
	)
	err := queryArgs(
		conn,
		`SELECT proposal_json, outcome_json, projection_mutations_json
		   FROM command_results
		  WHERE result_index = ?1;`,
		[]any{resultIndex},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				return
			}
			payload = commandResultPayload{
				proposal:  bytes.Clone([]byte(stmt.ColumnText(0))),
				outcome:   bytes.Clone([]byte(stmt.ColumnText(1))),
				mutations: bytes.Clone([]byte(stmt.ColumnText(2))),
			}
		},
	)
	if err != nil {
		return commandResultPayload{}, false, err
	}
	if count > 1 {
		return commandResultPayload{}, false,
			commandResultPayloadError("duplicate command-result rows", nil)
	}
	if count == 0 {
		return commandResultPayload{}, false, nil
	}
	compacted, partial := commandResultPayloadSentinels(payload)
	if partial {
		return commandResultPayload{}, false,
			commandResultPayloadError("legacy sentinels are partial", nil)
	}
	if compacted {
		return readCompactedCommandResultPayload(conn, resultIndex)
	}
	if rowErr = validateLegacyCommandResultPayload(
		conn,
		payload,
	); rowErr != nil {
		return commandResultPayload{}, false,
			commandResultPayloadError("invalid legacy payload", rowErr)
	}
	return payload, true, nil
}

func commandResultPayloadSentinels(
	payload commandResultPayload,
) (compacted bool, partial bool) {
	proposal := string(payload.proposal) == commandResultObjectSentinel
	outcome := string(payload.outcome) == commandResultObjectSentinel
	mutations := string(payload.mutations) ==
		commandResultMutationsSentinel
	if proposal && outcome {
		return mutations, !mutations
	}
	return false, proposal != outcome
}

func validateLegacyCommandResultPayload(
	conn *sqlite.Conn,
	payload commandResultPayload,
) error {
	hasCompactedStorage, err := tableExists(
		conn,
		"command_result_payloads",
	)
	if err != nil {
		return err
	}
	if hasCompactedStorage {
		return errors.New(
			"legacy payload remains after compacted storage migration",
		)
	}
	return validateCommandResultPayload(payload)
}

func requireCommandResultPayload(
	conn *sqlite.Conn,
	resultIndex uint64,
) (commandResultPayload, error) {
	payload, found, err := readCommandResultPayload(conn, resultIndex)
	if err != nil {
		return commandResultPayload{}, err
	}
	if !found {
		return commandResultPayload{},
			commandResultPayloadError("payload row is missing", nil)
	}
	return payload, nil
}

func verifyCommandResultPayloadInventory(conn *sqlite.Conn) error {
	if conn == nil {
		return ErrInvalidOptions
	}
	var (
		sourceCount       uint64
		sourceFingerprint Digest
		markerCount       int
		markerErr         error
	)
	if err := query(
		conn,
		`SELECT source_result_count, source_fingerprint
		   FROM command_result_payload_migration
		  WHERE singleton = 1;`,
		func(stmt *sqlite.Stmt) {
			markerCount++
			value := stmt.ColumnInt64(0)
			if markerCount != 1 || value < 0 {
				markerErr = errors.New("invalid migration marker")
				return
			}
			sourceCount = uint64(value)
			markerErr = copyDigestColumn(&sourceFingerprint, stmt, 1)
		},
	); err != nil {
		return err
	}
	if markerErr != nil || markerCount != 1 {
		return commandResultPayloadError(
			"migration marker is missing or invalid",
			markerErr,
		)
	}

	fingerprint := sha256.New()
	writeCommandResultFingerprintPart(
		fingerprint,
		[]byte("codecomm/command-result-payload-migration/v1"),
	)
	var (
		lastIndex uint64
		rowCount  uint64
	)
	for {
		row, found, err := readCompactedCommandResultPayloadSource(
			conn,
			lastIndex,
		)
		if err != nil {
			return err
		}
		if !found {
			break
		}
		if row.resultIndex != rowCount+1 {
			return commandResultPayloadError(
				"inventory indexes are not dense",
				nil,
			)
		}
		if proposalDigestFromBytes(row.payload.proposal) !=
			row.proposalDigest {
			return commandResultPayloadError(
				"inventory proposal digest differs",
				nil,
			)
		}
		if err := (CommandOutcome{
			Status: row.outcomeStatus,
			Code:   row.outcomeCode,
			JSON:   row.payload.outcome,
		}).validate(); err != nil {
			return commandResultPayloadError(
				"inventory outcome differs",
				err,
			)
		}
		if row.outcomeStatus == OutcomeAccepted {
			if err := verifyCompactedAcceptedEvent(conn, row); err != nil {
				return err
			}
		}
		if rowCount < sourceCount {
			writeCommandResultSourceFingerprint(fingerprint, row)
		}
		lastIndex = row.resultIndex
		rowCount++
	}
	if sourceCount > rowCount {
		return commandResultPayloadError(
			"migration marker follows retained results",
			nil,
		)
	}
	var computed Digest
	copy(computed[:], fingerprint.Sum(nil))
	if computed != sourceFingerprint {
		return commandResultPayloadError(
			"migration source fingerprint differs",
			nil,
		)
	}
	var payloadCount int64
	if err := queryOne(
		conn,
		"SELECT count(*) FROM command_result_payloads;",
		func(stmt *sqlite.Stmt) {
			payloadCount = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if payloadCount < 0 || uint64(payloadCount) != rowCount {
		return commandResultPayloadError(
			"payload inventory cardinality differs",
			nil,
		)
	}
	var foreignKeyFailures int64
	if err := query(
		conn,
		"PRAGMA foreign_key_check(command_result_payloads);",
		func(*sqlite.Stmt) {
			foreignKeyFailures++
		},
	); err != nil {
		return err
	}
	if foreignKeyFailures != 0 {
		return commandResultPayloadError(
			"payload foreign-key check failed",
			nil,
		)
	}
	return nil
}

func verifyCommandResultPayloadMetadata(conn *sqlite.Conn) error {
	if conn == nil {
		return ErrInvalidOptions
	}
	var (
		sourceCount       uint64
		sourceFingerprint Digest
		rebuildRequired   bool
		markerCount       int
		markerErr         error
	)
	if err := query(
		conn,
		`SELECT source_result_count, source_fingerprint,
		        sqlite_rebuild_required
		   FROM command_result_payload_migration
		  WHERE singleton = 1;`,
		func(stmt *sqlite.Stmt) {
			markerCount++
			value := stmt.ColumnInt64(0)
			if markerCount != 1 || value < 0 {
				markerErr = errors.New("invalid migration marker")
				return
			}
			sourceCount = uint64(value)
			if markerErr = copyDigestColumn(
				&sourceFingerprint,
				stmt,
				1,
			); markerErr != nil {
				return
			}
			rebuildRequired = stmt.ColumnBool(2)
		},
	); err != nil {
		return err
	}
	if markerErr != nil || markerCount != 1 || rebuildRequired {
		return commandResultPayloadError(
			"migration marker is missing, invalid, or unfinished",
			markerErr,
		)
	}

	var (
		maxResultIndex uint64
		resultCount    int
		resultErr      error
	)
	if err := query(
		conn,
		`SELECT result_index
		   FROM command_results
		  ORDER BY result_index DESC
		  LIMIT 1;`,
		func(stmt *sqlite.Stmt) {
			resultCount++
			value := stmt.ColumnInt64(0)
			if resultCount != 1 || value < 1 {
				resultErr = errors.New("invalid latest result index")
				return
			}
			maxResultIndex = uint64(value)
		},
	); err != nil {
		return err
	}
	if resultErr != nil || resultCount > 1 || sourceCount > maxResultIndex {
		return commandResultPayloadError(
			"migration marker exceeds retained results",
			resultErr,
		)
	}
	if sourceCount == 0 {
		digest := sha256.New()
		writeCommandResultFingerprintPart(
			digest,
			[]byte("codecomm/command-result-payload-migration/v1"),
		)
		var emptyFingerprint Digest
		copy(emptyFingerprint[:], digest.Sum(nil))
		if sourceFingerprint != emptyFingerprint {
			return commandResultPayloadError(
				"empty migration fingerprint differs",
				nil,
			)
		}
	}
	return nil
}

func verifyCompactedAcceptedEvent(
	conn *sqlite.Conn,
	row commandResultPayloadInventoryRow,
) error {
	var matches bool
	if err := queryOneArgs(
		conn,
		`SELECT proposal_json = ?2 AND proposal_digest = ?3
		   FROM events WHERE event_id = ?1;`,
		[]any{
			string(row.eventID),
			commandResultObjectSentinel,
			row.proposalDigest[:],
		},
		func(stmt *sqlite.Stmt) {
			matches = stmt.ColumnBool(0)
		},
	); err != nil {
		return commandResultPayloadError(
			"compacted accepted event is missing",
			err,
		)
	}
	if !matches {
		return commandResultPayloadError(
			"compacted accepted event differs",
			nil,
		)
	}
	return nil
}

func resetCommandResultPayloadMigrationMarker(conn *sqlite.Conn) error {
	digest := sha256.New()
	writeCommandResultFingerprintPart(
		digest,
		[]byte("codecomm/command-result-payload-migration/v1"),
	)
	var fingerprint Digest
	copy(fingerprint[:], digest.Sum(nil))
	return execute(
		conn,
		`UPDATE command_result_payload_migration
		    SET source_result_count = 0, source_fingerprint = ?1,
		        sqlite_rebuild_required = 0
		  WHERE singleton = 1;`,
		fingerprint[:],
	)
}

func compactCommandResultStorageIfRequired(conn *sqlite.Conn) error {
	if conn == nil {
		return ErrInvalidOptions
	}
	var required bool
	if err := queryOne(
		conn,
		`SELECT sqlite_rebuild_required
		   FROM command_result_payload_migration
		  WHERE singleton = 1;`,
		func(stmt *sqlite.Stmt) {
			required = stmt.ColumnBool(0)
		},
	); err != nil {
		return err
	}
	if !required {
		return nil
	}
	var (
		checkpointBusy int64
		checkpointLog  int64
		checkpointDone int64
	)
	if err := queryOne(
		conn,
		"PRAGMA wal_checkpoint(TRUNCATE);",
		func(stmt *sqlite.Stmt) {
			checkpointBusy = stmt.ColumnInt64(0)
			checkpointLog = stmt.ColumnInt64(1)
			checkpointDone = stmt.ColumnInt64(2)
		},
	); err != nil {
		return fmt.Errorf("checkpoint before SQLite rebuild: %w", err)
	}
	if checkpointBusy != 0 || checkpointDone != checkpointLog {
		return fmt.Errorf(
			"checkpoint before SQLite rebuild incomplete: busy=%d log=%d done=%d",
			checkpointBusy,
			checkpointLog,
			checkpointDone,
		)
	}
	if err := setSQLiteJournalMode(conn, "delete"); err != nil {
		return fmt.Errorf("enter SQLite rebuild journal mode: %w", err)
	}
	if err := execute(conn, "PRAGMA page_size = 8192;"); err != nil {
		return fmt.Errorf("set SQLite rebuild page size: %w", err)
	}
	if err := execute(conn, "VACUUM;"); err != nil {
		return fmt.Errorf("rebuild SQLite database: %w", err)
	}
	var pageSize int64
	if err := queryOne(conn, "PRAGMA page_size;", func(stmt *sqlite.Stmt) {
		pageSize = stmt.ColumnInt64(0)
	}); err != nil {
		return err
	}
	if pageSize != 8192 {
		return fmt.Errorf(
			"SQLite rebuild page_size = %d, want 8192",
			pageSize,
		)
	}
	if err := execute(
		conn,
		`UPDATE command_result_payload_migration
		    SET sqlite_rebuild_required = 0
		  WHERE singleton = 1 AND sqlite_rebuild_required = 1;`,
	); err != nil {
		return fmt.Errorf("finish SQLite rebuild marker: %w", err)
	}
	if err := setSQLiteJournalMode(conn, "wal"); err != nil {
		return fmt.Errorf("restore SQLite WAL mode: %w", err)
	}
	return nil
}

func readCompactedCommandResultPayloadSource(
	conn *sqlite.Conn,
	after uint64,
) (commandResultPayloadInventoryRow, bool, error) {
	var (
		row       commandResultPayloadInventoryRow
		count     int
		sentinels bool
		rowErr    error
	)
	err := queryArgs(
		conn,
		`SELECT result_index, event_id, proposal_digest, outcome_status,
		        outcome_code,
		        proposal_json = ?2 AND outcome_json = ?2
		            AND projection_mutations_json = ?3
		   FROM command_results
		  WHERE result_index > ?1
		  ORDER BY result_index
		  LIMIT 1;`,
		[]any{
			after,
			commandResultObjectSentinel,
			commandResultMutationsSentinel,
		},
		func(stmt *sqlite.Stmt) {
			count++
			index := stmt.ColumnInt64(0)
			row.eventID = domain.UUIDv7(stmt.ColumnText(1))
			if index < 1 || !row.eventID.Valid() {
				rowErr = errors.New("invalid compacted result identity")
				return
			}
			row.resultIndex = uint64(index)
			if rowErr = copyDigestColumn(
				&row.proposalDigest,
				stmt,
				2,
			); rowErr != nil {
				return
			}
			row.outcomeStatus = OutcomeStatus(stmt.ColumnText(3))
			row.outcomeCode = stmt.ColumnText(4)
			sentinels = stmt.ColumnBool(5)
		},
	)
	if err != nil {
		return commandResultPayloadInventoryRow{}, false, err
	}
	if rowErr != nil {
		return commandResultPayloadInventoryRow{}, false,
			commandResultPayloadError("invalid compacted result", rowErr)
	}
	if count == 0 {
		return commandResultPayloadInventoryRow{}, false, nil
	}
	if !sentinels {
		return commandResultPayloadInventoryRow{}, false,
			commandResultPayloadError("legacy sentinels differ", nil)
	}
	payload, found, err := readCommandResultPayload(conn, row.resultIndex)
	if err != nil {
		return commandResultPayloadInventoryRow{}, false, err
	}
	if !found {
		return commandResultPayloadInventoryRow{}, false,
			commandResultPayloadError("payload row is missing", nil)
	}
	row.payload = payload
	return row, true, nil
}

func writeCommandResultSourceFingerprint(
	digest hash.Hash,
	row commandResultPayloadInventoryRow,
) {
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], row.resultIndex)
	writeCommandResultFingerprintPart(digest, index[:])
	writeCommandResultFingerprintPart(digest, []byte(row.eventID))
	writeCommandResultFingerprintPart(digest, row.proposalDigest[:])
	writeCommandResultFingerprintPart(digest, []byte(row.outcomeStatus))
	writeCommandResultFingerprintPart(digest, []byte(row.outcomeCode))
	writeCommandResultFingerprintPart(digest, row.payload.proposal)
	writeCommandResultFingerprintPart(digest, row.payload.outcome)
	writeCommandResultFingerprintPart(digest, row.payload.mutations)
}

func writeCommandResultFingerprintPart(digest hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = digest.Write(size[:])
	_, _ = digest.Write(value)
}
