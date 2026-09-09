package store

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

const (
	migration0011PayloadCodecVersion = uint32(1)
	migration0011PayloadHeaderBytes  = 20
	migration0011MaxPayloadBytes     = 36 << 20
	migration0011MaxCompressedBytes  = 36 << 20
	migration0011MaxProposalBytes    = 1 << 20
	migration0011MaxOutcomeBytes     = 1 << 20
	migration0011MaxMutationsBytes   = 32 << 20
	migration0011ObjectSentinel      = "{}"
	migration0011MutationsSentinel   = "[]"
)

var migration0011PayloadMagic = [4]byte{'C', 'C', 'R', 'P'}

type migration0011Payload struct {
	proposal  []byte
	outcome   []byte
	mutations []byte
}

func migrateCommandResultPayloads(conn *sqlite.Conn) error {
	if conn == nil {
		return ErrInvalidOptions
	}
	fingerprint := sha256.New()
	migration0011WriteFingerprintPart(
		fingerprint,
		[]byte("codecomm/command-result-payload-migration/v1"),
	)
	var (
		lastIndex uint64
		rowCount  uint64
	)
	for {
		row, found, err := readLegacyCommandResultPayloadSource(
			conn,
			lastIndex,
		)
		if err != nil {
			return err
		}
		if !found {
			break
		}
		if row.resultIndex <= lastIndex ||
			row.resultIndex != rowCount+1 {
			return migration0011Error(
				"migration source indexes are not dense",
				nil,
			)
		}
		if Digest(sha256.Sum256(row.payload.proposal)) !=
			row.proposalDigest {
			return migration0011Error(
				"migration proposal digest differs",
				nil,
			)
		}
		if err := migration0011ValidateOutcome(
			row.outcomeStatus,
			row.outcomeCode,
			row.payload.outcome,
		); err != nil {
			return migration0011Error(
				"migration outcome differs",
				err,
			)
		}
		if row.outcomeStatus == OutcomeAccepted {
			if err := verifyMigrationAcceptedProposal(conn, row); err != nil {
				return err
			}
		}
		migration0011WriteSourceFingerprint(fingerprint, row)
		if err := migration0011WritePayload(
			conn,
			row.resultIndex,
			row.payload,
		); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE command_results
			    SET proposal_json = ?1, outcome_json = ?1,
			        projection_mutations_json = ?2
			  WHERE result_index = ?3;`,
			migration0011ObjectSentinel,
			migration0011MutationsSentinel,
			row.resultIndex,
		); err != nil {
			return err
		}
		if row.outcomeStatus == OutcomeAccepted {
			if err := execute(
				conn,
				`UPDATE events SET proposal_json = ?1
				  WHERE event_id = ?2;`,
				migration0011ObjectSentinel,
				string(row.eventID),
			); err != nil {
				return err
			}
		}
		lastIndex = row.resultIndex
		rowCount++
	}
	var digest Digest
	copy(digest[:], fingerprint.Sum(nil))
	var pageSize int64
	if err := queryOne(conn, "PRAGMA page_size;", func(stmt *sqlite.Stmt) {
		pageSize = stmt.ColumnInt64(0)
	}); err != nil {
		return err
	}
	if pageSize < 1 {
		return migration0011Error(
			"migration source page size is invalid",
			nil,
		)
	}
	if err := execute(
		conn,
		`INSERT INTO command_result_payload_migration(
		    singleton, source_result_count, source_fingerprint,
		    sqlite_rebuild_required
		) VALUES (1, ?1, ?2, ?3);`,
		rowCount,
		digest[:],
		rowCount > 0 || pageSize != 8192,
	); err != nil {
		return err
	}
	return migration0011VerifyOutput(conn, rowCount)
}

func migration0011ValidatePayload(payload migration0011Payload) error {
	if len(payload.proposal) > migration0011MaxProposalBytes ||
		len(payload.outcome) > migration0011MaxOutcomeBytes ||
		len(payload.mutations) > migration0011MaxMutationsBytes {
		return migration0011Error("component exceeds limit", nil)
	}
	canonical, err := codec.CanonicalizeSignedObject(payload.proposal)
	if err != nil || !bytes.Equal(canonical, payload.proposal) {
		return migration0011Error("proposal is not canonical", err)
	}
	canonical, err = codec.CanonicalizeSignedObject(payload.outcome)
	if err != nil || !bytes.Equal(canonical, payload.outcome) {
		return migration0011Error("outcome is not canonical", err)
	}
	mutations, err := chain.DecodeMutations(payload.mutations)
	if err != nil {
		return migration0011Error("decode mutations", err)
	}
	canonical, err = chain.EncodeMutations(mutations)
	if err != nil || !bytes.Equal(canonical, payload.mutations) {
		return migration0011Error("mutations do not round trip", err)
	}
	return nil
}

func migration0011ValidateOutcome(
	status OutcomeStatus,
	code string,
	encoded []byte,
) error {
	if status != OutcomeAccepted && status != OutcomeRejected {
		return errors.New("invalid outcome status")
	}
	if !migration0011ValidCode(code) {
		return errors.New("invalid outcome code")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		return err
	}
	var encodedStatus, encodedCode string
	if raw, exists := members["status"]; !exists ||
		json.Unmarshal(raw, &encodedStatus) != nil ||
		OutcomeStatus(encodedStatus) != status {
		return errors.New("outcome status does not match JSON")
	}
	if raw, exists := members["code"]; !exists ||
		json.Unmarshal(raw, &encodedCode) != nil ||
		encodedCode != code {
		return errors.New("outcome code does not match JSON")
	}
	return nil
}

func migration0011ValidCode(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '_' {
					return false
				}
			}
		}
	}
	return true
}

func migration0011WritePayload(
	conn *sqlite.Conn,
	resultIndex uint64,
	payload migration0011Payload,
) error {
	if err := migration0011ValidatePayload(payload); err != nil {
		return err
	}
	size := migration0011PayloadHeaderBytes +
		len(payload.proposal) +
		len(payload.outcome) +
		len(payload.mutations)
	if size > migration0011MaxPayloadBytes {
		return migration0011Error(
			"uncompressed frame exceeds limit",
			nil,
		)
	}
	frame := make([]byte, migration0011PayloadHeaderBytes, size)
	copy(frame[:4], migration0011PayloadMagic[:])
	binary.BigEndian.PutUint32(
		frame[4:8],
		migration0011PayloadCodecVersion,
	)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload.proposal)))
	binary.BigEndian.PutUint32(frame[12:16], uint32(len(payload.outcome)))
	binary.BigEndian.PutUint32(
		frame[16:20],
		uint32(len(payload.mutations)),
	)
	frame = append(frame, payload.proposal...)
	frame = append(frame, payload.outcome...)
	frame = append(frame, payload.mutations...)

	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		return migration0011Error("initialize compressor", err)
	}
	if _, err := writer.Write(frame); err != nil {
		_ = writer.Close()
		return migration0011Error("compress frame", err)
	}
	if err := writer.Close(); err != nil {
		return migration0011Error("finish compressed frame", err)
	}
	if compressed.Len() < 1 ||
		compressed.Len() > migration0011MaxCompressedBytes {
		return migration0011Error(
			"compressed frame exceeds limit",
			nil,
		)
	}
	checksum := sha256.Sum256(frame)
	return execute(
		conn,
		`INSERT INTO command_result_payloads(
		    result_index, codec_version, uncompressed_size,
		    uncompressed_sha256, compressed_payload
		) VALUES (?1, ?2, ?3, ?4, ?5);`,
		resultIndex,
		uint64(migration0011PayloadCodecVersion),
		len(frame),
		checksum[:],
		compressed.Bytes(),
	)
}

func migration0011VerifyOutput(conn *sqlite.Conn, wantCount uint64) error {
	var (
		resultCount           int64
		payloadCount          int64
		sentinelCount         int64
		acceptedEventFailures int64
	)
	if err := queryOneArgs(
		conn,
		`SELECT
		    (SELECT count(*) FROM command_results),
		    (SELECT count(*) FROM command_result_payloads),
		    (SELECT count(*) FROM command_results
		      WHERE proposal_json = ?1 AND outcome_json = ?1
		        AND projection_mutations_json = ?2),
		    (SELECT count(*) FROM command_results AS r
		      WHERE r.outcome_status = 'accepted'
		        AND NOT EXISTS (
		            SELECT 1 FROM events AS e
		             WHERE e.event_id = r.event_id
		               AND e.proposal_json = ?1
		               AND e.proposal_digest = r.proposal_digest
		        ));`,
		[]any{
			migration0011ObjectSentinel,
			migration0011MutationsSentinel,
		},
		func(stmt *sqlite.Stmt) {
			resultCount = stmt.ColumnInt64(0)
			payloadCount = stmt.ColumnInt64(1)
			sentinelCount = stmt.ColumnInt64(2)
			acceptedEventFailures = stmt.ColumnInt64(3)
		},
	); err != nil {
		return err
	}
	if resultCount < 0 ||
		uint64(resultCount) != wantCount ||
		payloadCount != resultCount ||
		sentinelCount != resultCount ||
		acceptedEventFailures != 0 {
		return migration0011Error(
			fmt.Sprintf(
				"output inventory differs: results=%d payloads=%d sentinels=%d accepted_event_failures=%d want=%d",
				resultCount,
				payloadCount,
				sentinelCount,
				acceptedEventFailures,
				wantCount,
			),
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
		return migration0011Error(
			"payload foreign-key check failed",
			nil,
		)
	}
	return nil
}

func migration0011Error(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf(
			"%w: migration 0011 %s",
			ErrCommandResultCorrupt,
			detail,
		)
	}
	return fmt.Errorf(
		"%w: migration 0011 %s: %w",
		ErrCommandResultCorrupt,
		detail,
		cause,
	)
}

type migration0011SourceRow struct {
	resultIndex    uint64
	eventID        domain.UUIDv7
	proposalDigest Digest
	outcomeStatus  OutcomeStatus
	outcomeCode    string
	payload        migration0011Payload
}

func readLegacyCommandResultPayloadSource(
	conn *sqlite.Conn,
	after uint64,
) (migration0011SourceRow, bool, error) {
	var (
		row    migration0011SourceRow
		count  int
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT result_index, event_id, proposal_digest, outcome_status,
		        outcome_code, proposal_json, outcome_json,
		        projection_mutations_json
		   FROM command_results
		  WHERE result_index > ?1
		  ORDER BY result_index
		  LIMIT 1;`,
		[]any{after},
		func(stmt *sqlite.Stmt) {
			count++
			index := stmt.ColumnInt64(0)
			row.eventID = domain.UUIDv7(stmt.ColumnText(1))
			if index < 1 || !row.eventID.Valid() {
				rowErr = errors.New("invalid migration source identity")
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
			row.payload = migration0011Payload{
				proposal:  bytes.Clone([]byte(stmt.ColumnText(5))),
				outcome:   bytes.Clone([]byte(stmt.ColumnText(6))),
				mutations: bytes.Clone([]byte(stmt.ColumnText(7))),
			}
			rowErr = migration0011ValidatePayload(row.payload)
		},
	)
	if err != nil {
		return migration0011SourceRow{}, false, err
	}
	if rowErr != nil {
		return migration0011SourceRow{}, false,
			migration0011Error("invalid migration source", rowErr)
	}
	return row, count == 1, nil
}

func verifyMigrationAcceptedProposal(
	conn *sqlite.Conn,
	row migration0011SourceRow,
) error {
	var matches bool
	if err := queryOneArgs(
		conn,
		`SELECT proposal_json = ?2 AND proposal_digest = ?3
		   FROM events WHERE event_id = ?1;`,
		[]any{
			string(row.eventID),
			string(row.payload.proposal),
			row.proposalDigest[:],
		},
		func(stmt *sqlite.Stmt) {
			matches = stmt.ColumnBool(0)
		},
	); err != nil {
		return migration0011Error(
			"migration accepted event is missing",
			err,
		)
	}
	if !matches {
		return migration0011Error(
			"migration accepted event differs",
			nil,
		)
	}
	return nil
}

func migration0011WriteSourceFingerprint(
	digest hash.Hash,
	row migration0011SourceRow,
) {
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], row.resultIndex)
	migration0011WriteFingerprintPart(digest, index[:])
	migration0011WriteFingerprintPart(digest, []byte(row.eventID))
	migration0011WriteFingerprintPart(digest, row.proposalDigest[:])
	migration0011WriteFingerprintPart(digest, []byte(row.outcomeStatus))
	migration0011WriteFingerprintPart(digest, []byte(row.outcomeCode))
	migration0011WriteFingerprintPart(digest, row.payload.proposal)
	migration0011WriteFingerprintPart(digest, row.payload.outcome)
	migration0011WriteFingerprintPart(digest, row.payload.mutations)
}

func migration0011WriteFingerprintPart(digest hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = digest.Write(size[:])
	_, _ = digest.Write(value)
}
