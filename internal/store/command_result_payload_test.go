package store

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

func TestCommandResultPayloadCodecRoundTripsAndRejectsCorruption(t *testing.T) {
	payload := commandResultPayload{
		proposal:  []byte(`{"event":"value"}`),
		outcome:   []byte(`{"code":"accepted","status":"accepted"}`),
		mutations: []byte(`[]`),
	}
	stored, err := encodeCommandResultPayload(payload)
	if err != nil {
		t.Fatalf("encodeCommandResultPayload(): %v", err)
	}
	decoded, err := decodeCommandResultPayload(stored)
	if err != nil {
		t.Fatalf("decodeCommandResultPayload(): %v", err)
	}
	if !reflect.DeepEqual(decoded, payload) {
		t.Fatalf("decoded payload = %#v, want %#v", decoded, payload)
	}

	tests := []struct {
		name   string
		mutate func(*storedCommandResultPayload)
	}{
		{
			name: "codec version",
			mutate: func(value *storedCommandResultPayload) {
				value.codecVersion++
			},
		},
		{
			name: "declared size",
			mutate: func(value *storedCommandResultPayload) {
				value.uncompressedSize--
			},
		},
		{
			name: "global size limit",
			mutate: func(value *storedCommandResultPayload) {
				value.uncompressedSize = maxCommandResultPayloadBytes + 1
			},
		},
		{
			name: "checksum",
			mutate: func(value *storedCommandResultPayload) {
				value.checksum[0] ^= 0xff
			},
		},
		{
			name: "compressed bytes",
			mutate: func(value *storedCommandResultPayload) {
				value.compressed[len(value.compressed)/2] ^= 0xff
			},
		},
		{
			name: "trailing compressed bytes",
			mutate: func(value *storedCommandResultPayload) {
				value.compressed = append(
					bytes.Clone(value.compressed),
					0,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := stored
			candidate.compressed = bytes.Clone(stored.compressed)
			test.mutate(&candidate)
			if _, err := decodeCommandResultPayload(candidate); !errors.Is(
				err,
				ErrCommandResultCorrupt,
			) {
				t.Fatalf(
					"decodeCommandResultPayload() error = %v, want corruption",
					err,
				)
			}
		})
	}

	noncanonical := rawStoredCommandResultPayloadForTest(
		t,
		commandResultPayload{
			proposal:  []byte(`{"z":0,"a":0}`),
			outcome:   payload.outcome,
			mutations: payload.mutations,
		},
	)
	if _, err := decodeCommandResultPayload(noncanonical); !errors.Is(
		err,
		ErrCommandResultCorrupt,
	) {
		t.Fatalf("noncanonical payload error = %v, want corruption", err)
	}
}

func TestCommandResultPayloadSentinelsDistinguishLegacyEmptyMutations(
	t *testing.T,
) {
	tests := []struct {
		name          string
		payload       commandResultPayload
		wantCompacted bool
		wantPartial   bool
	}{
		{
			name: "legacy empty mutations",
			payload: commandResultPayload{
				proposal:  []byte(`{"event":"value"}`),
				outcome:   []byte(`{"code":"accepted","status":"accepted"}`),
				mutations: []byte(`[]`),
			},
		},
		{
			name: "compacted",
			payload: commandResultPayload{
				proposal:  []byte(`{}`),
				outcome:   []byte(`{}`),
				mutations: []byte(`[]`),
			},
			wantCompacted: true,
		},
		{
			name: "proposal only",
			payload: commandResultPayload{
				proposal:  []byte(`{}`),
				outcome:   []byte(`{"code":"accepted","status":"accepted"}`),
				mutations: []byte(`[]`),
			},
			wantPartial: true,
		},
		{
			name: "objects without mutations",
			payload: commandResultPayload{
				proposal:  []byte(`{}`),
				outcome:   []byte(`{}`),
				mutations: []byte(`[{"op":"delete"}]`),
			},
			wantPartial: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compacted, partial := commandResultPayloadSentinels(
				test.payload,
			)
			if compacted != test.wantCompacted ||
				partial != test.wantPartial {
				t.Fatalf(
					"sentinels = (%t, %t), want (%t, %t)",
					compacted,
					partial,
					test.wantCompacted,
					test.wantPartial,
				)
			}
		})
	}
}

func TestCommandResultPayloadInventoryRejectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*sqlite.Conn) error
	}{
		{
			name: "compressed payload",
			tamper: func(conn *sqlite.Conn) error {
				var compressed []byte
				if err := queryOne(
					conn,
					`SELECT compressed_payload
					   FROM command_result_payloads
					  WHERE result_index = 1;`,
					func(stmt *sqlite.Stmt) {
						compressed = columnBytes(stmt, 0)
					},
				); err != nil {
					return err
				}
				compressed = append(compressed, 0)
				return execute(
					conn,
					`UPDATE command_result_payloads
					    SET compressed_payload = ?1
					  WHERE result_index = 1;`,
					compressed,
				)
			},
		},
		{
			name: "checksum",
			tamper: func(conn *sqlite.Conn) error {
				return execute(
					conn,
					`UPDATE command_result_payloads
					    SET uncompressed_sha256 = zeroblob(32)
					  WHERE result_index = 1;`,
				)
			},
		},
		{
			name: "missing payload",
			tamper: func(conn *sqlite.Conn) error {
				return execute(
					conn,
					"DELETE FROM command_result_payloads WHERE result_index = 1;",
				)
			},
		},
		{
			name: "legacy sentinel",
			tamper: func(conn *sqlite.Conn) error {
				return execute(
					conn,
					`UPDATE command_results
					    SET proposal_json = '{"changed":true}'
					  WHERE result_index = 1;`,
				)
			},
		},
		{
			name: "restored legacy payload",
			tamper: func(conn *sqlite.Conn) error {
				payload, found, err := readCompactedCommandResultPayload(
					conn,
					1,
				)
				if err != nil {
					return err
				}
				if !found {
					return errors.New("fixture payload is missing")
				}
				return execute(
					conn,
					`UPDATE command_results
					    SET proposal_json = ?1, outcome_json = ?2,
					        projection_mutations_json = ?3
					  WHERE result_index = 1;`,
					string(payload.proposal),
					string(payload.outcome),
					string(payload.mutations),
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session", "state.db")
			database := openTestStore(t, path, nil)
			initializeTestStore(t, database)
			if _, err := database.Apply(
				context.Background(),
				acceptedApplyRequest(
					t,
					testSignedTaskEvent(t, testEventID, 1),
				),
			); err != nil {
				t.Fatalf("Apply(): %v", err)
			}
			if err := database.LocalState().withImmediate(
				context.Background(),
				test.tamper,
			); err != nil {
				t.Fatalf("tamper payload: %v", err)
			}
			if err := database.Close(); err != nil {
				t.Fatalf("Close(): %v", err)
			}
			if reopened, err := Open(
				context.Background(),
				Options{Path: path},
			); !errors.Is(err, ErrCommandResultCorrupt) {
				if reopened != nil {
					_ = reopened.Close()
				}
				t.Fatalf("Open(tampered) error = %v, want corruption", err)
			}
		})
	}
}

func TestCommandResultPayloadInventoryIdentifiesSentinelMismatch(
	t *testing.T,
) {
	tests := []struct {
		name      string
		column    string
		value     string
		wantField string
	}{
		{
			name:      "proposal",
			column:    "proposal_json",
			value:     `{"changed":true}`,
			wantField: "proposal",
		},
		{
			name:      "outcome",
			column:    "outcome_json",
			value:     `{"changed":true}`,
			wantField: "outcome",
		},
		{
			name:      "mutations",
			column:    "projection_mutations_json",
			value:     `[{}]`,
			wantField: "mutations",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session", "state.db")
			database := openTestStore(t, path, nil)
			initializeTestStore(t, database)
			if _, err := database.Apply(
				context.Background(),
				acceptedApplyRequest(
					t,
					testSignedTaskEvent(t, testEventID, 1),
				),
			); err != nil {
				t.Fatalf("Apply(): %v", err)
			}
			err := database.LocalState().withImmediate(
				context.Background(),
				func(conn *sqlite.Conn) error {
					if err := execute(
						conn,
						"UPDATE command_results SET "+test.column+
							" = ?1 WHERE result_index = 1;",
						test.value,
					); err != nil {
						return err
					}
					return verifyCommandResultPayloadInventory(conn)
				},
			)
			if !errors.Is(err, ErrCommandResultCorrupt) {
				t.Fatalf(
					"verifyCommandResultPayloadInventory() error = %v, want corruption",
					err,
				)
			}
			for _, detail := range []string{
				"result_index 1",
				test.wantField + "(type=SQLITE_TEXT",
				"length=",
				"sha256=",
			} {
				if !strings.Contains(err.Error(), detail) {
					t.Fatalf(
						"inventory error %q does not contain %q",
						err,
						detail,
					)
				}
			}
			if strings.Contains(err.Error(), test.value) {
				t.Fatalf("inventory error exposed payload: %v", err)
			}
		})
	}
}

func TestOpenBoundsPayloadVerificationToCurrentTip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	database := openTestStore(t, path, nil)
	initializeTestStore(t, database)

	first, err := database.Apply(
		context.Background(),
		acceptedApplyRequest(
			t,
			testSignedTaskEvent(t, testEventID, 1),
		),
	)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	secondRequest := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID2, 2),
		first.Heads,
	)
	second, err := database.Apply(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	thirdRequest := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, testAuditEventID, 3),
		second.Heads,
	)
	thirdRequest.LogIndex = 3
	third, err := database.Apply(
		context.Background(),
		thirdRequest,
	)
	if err != nil {
		t.Fatalf("Apply(third): %v", err)
	}
	fourthRequest := nextAcceptedApplyRequest(
		testSignedTaskEvent(t, testCheckpointEventID, 4),
		1,
		4,
		domain.Timestamp("2026-08-10T12:00:03Z"),
	)
	fourthRequest.RecordActivity = true
	fourth, err := database.Apply(context.Background(), fourthRequest)
	if err != nil {
		t.Fatalf("Apply(fourth): %v", err)
	}
	fifthRequest := nextAcceptedApplyRequest(
		testSignedTaskEvent(
			t,
			domain.UUIDv7("01890f47-3e72-7000-8000-000000000014"),
			5,
		),
		1,
		5,
		domain.Timestamp("2026-08-10T12:00:04Z"),
	)
	fifthRequest.RecordActivity = true
	if _, err := database.Apply(
		context.Background(),
		fifthRequest,
	); err != nil {
		t.Fatalf("Apply(fifth): %v", err)
	}
	if third.Heads.ResultIndex != 3 ||
		fourth.Heads.ResultIndex != 4 ||
		fourth.Heads.ChainIndex != 2 {
		t.Fatalf(
			"unexpected fixture heads: third=%+v fourth=%+v",
			third.Heads,
			fourth.Heads,
		)
	}
	if err := database.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE command_result_payloads
				    SET compressed_payload = zeroblob(
				            length(compressed_payload)
				        )
				  WHERE result_index = 1;`,
			)
		},
	); err != nil {
		t.Fatalf("tamper historical payload: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("bounded Open() rejected non-tip history: %v", err)
	}
	defer reopened.Close()
	if err := reopened.VerifyCommitmentHistory(
		context.Background(),
	); !errors.Is(err, ErrCommandResultCorrupt) {
		t.Fatalf(
			"VerifyCommitmentHistory() error = %v, want payload corruption",
			err,
		)
	}
}

func TestMigration0011ChecksumBindsIsolatedPostSQLImplementation(
	t *testing.T,
) {
	t.Parallel()

	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate migration test source")
	}
	sourceDigest := sha256.New()
	const name = "command_result_payload_migration.go"
	source, err := os.ReadFile(filepath.Join(filepath.Dir(testFile), name))
	if err != nil {
		t.Fatalf("read isolated post-SQL implementation source: %v", err)
	}
	writeMigrationChecksumPart(sourceDigest, name)
	writeMigrationChecksumPart(sourceDigest, string(source))
	digest := sourceDigest.Sum(nil)
	want, err := hex.DecodeString(commandResultPayloadMigrationDigest)
	if err != nil {
		t.Fatalf("decode bound implementation digest: %v", err)
	}
	if !bytes.Equal(digest, want) {
		t.Fatalf(
			"migration 0011 post-SQL source digest = %x, want %x; "+
				"review the change and update the bound digest",
			digest,
			want,
		)
	}

	changed := append([]migration(nil), embeddedMigrations...)
	changed[10] = bindMigrationPostSQL(
		changed[10],
		changed[10].postSQLID,
		"0000000000000000000000000000000000000000000000000000000000000000",
		migrateCommandResultPayloads,
	)
	if changed[10].checksum == embeddedMigrations[10].checksum {
		t.Fatal("post-SQL implementation digest did not change the checksum")
	}
	changed[10] = bindMigrationPostSQL(
		embeddedMigrations[10],
		"command_result_payloads/v2",
		commandResultPayloadMigrationDigest,
		migrateCommandResultPayloads,
	)
	if changed[10].checksum == embeddedMigrations[10].checksum {
		t.Fatal("post-SQL hook identity did not change the checksum")
	}
}

func TestMigration0011PreservesSnapshotsRangesAndCommitments(t *testing.T) {
	fixture := newLogicalSnapshotExportFixture(t)
	path := fixture.store.Path()
	beforeView, err := fixture.store.View(context.Background())
	if err != nil {
		t.Fatalf("View(before): %v", err)
	}
	beforeCut, beforeRecords, err := collectLogicalSnapshotRecords(
		context.Background(),
		fixture.store,
		fixture.options,
	)
	if err != nil {
		t.Fatalf("snapshot before migration: %v", err)
	}
	rangeOptions := ResultRangeOptions{
		AfterResultIndex: 0,
		MaxResults:       MaxResultRangeItems,
		MaxBytes:         MaxResultRangeBytes,
	}
	beforeRange, found, err := fixture.store.ExportResultRange(
		context.Background(),
		rangeOptions,
	)
	if err != nil || !found {
		t.Fatalf("result range before migration = (%t, %v)", found, err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("Close(before downgrade): %v", err)
	}

	conn, err := sqlite.OpenConn(
		path,
		sqlite.OpenReadWrite|sqlite.OpenPrivateCache,
	)
	if err != nil {
		t.Fatalf("open downgrade connection: %v", err)
	}
	if err := configurePooledConnection(conn); err != nil {
		_ = conn.Close()
		t.Fatalf("configure downgrade connection: %v", err)
	}
	func() {
		var transactionErr error
		end, beginErr := sqlitex.ImmediateTransaction(conn)
		if beginErr != nil {
			transactionErr = beginErr
		} else {
			transactionErr = downgradeCommandResultPayloadsForTest(conn)
			end(&transactionErr)
		}
		if transactionErr != nil {
			t.Fatalf("downgrade to v10: %v", transactionErr)
		}
	}()
	if err := setSQLiteJournalMode(conn, "delete"); err != nil {
		t.Fatal(err)
	}
	if err := execute(conn, "PRAGMA page_size = 4096;"); err != nil {
		t.Fatal(err)
	}
	if err := execute(conn, "VACUUM;"); err != nil {
		t.Fatal(err)
	}
	assertIntQuery(t, conn, "PRAGMA page_size;", 4096)
	if err := conn.Close(); err != nil {
		t.Fatalf("close downgrade connection: %v", err)
	}

	upgraded, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(v10 upgrade): %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	afterView, err := upgraded.View(context.Background())
	if err != nil {
		t.Fatalf("View(after): %v", err)
	}
	beforeView.AdmissionRevision = 0
	afterView.AdmissionRevision = 0
	if !reflect.DeepEqual(afterView, beforeView) {
		t.Fatal("migration changed the logical store view")
	}
	afterCut, afterRecords, err := collectLogicalSnapshotRecords(
		context.Background(),
		upgraded,
		fixture.options,
	)
	if err != nil {
		t.Fatalf("snapshot after migration: %v", err)
	}
	if !reflect.DeepEqual(afterCut, beforeCut) ||
		!reflect.DeepEqual(afterRecords, beforeRecords) {
		t.Fatal("migration changed logical snapshot bytes or cut")
	}
	afterRange, found, err := upgraded.ExportResultRange(
		context.Background(),
		rangeOptions,
	)
	if err != nil || !found {
		t.Fatalf("result range after migration = (%t, %v)", found, err)
	}
	if !reflect.DeepEqual(afterRange, beforeRange) {
		t.Fatal("migration changed result-batch bytes or heads")
	}
	if err := upgraded.VerifyCommitmentHistory(context.Background()); err != nil {
		t.Fatalf("VerifyCommitmentHistory(): %v", err)
	}
	if err := upgraded.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			assertIntQuery(t, conn, "PRAGMA page_size;", 8192)
			assertIntQuery(
				t,
				conn,
				"SELECT count(*) FROM command_result_payloads;",
				3,
			)
			assertIntQuery(
				t,
				conn,
				`SELECT count(*) FROM events
				  WHERE proposal_json <> '{}';`,
				0,
			)
			assertIntQuery(
				t,
				conn,
				`SELECT count(*) FROM command_results
				  WHERE proposal_json = '{}' AND outcome_json = '{}'
				    AND projection_mutations_json = '[]';`,
				3,
			)
			assertIntQuery(
				t,
				conn,
				`SELECT source_result_count
				   FROM command_result_payload_migration
				  WHERE singleton = 1;`,
				3,
			)
			assertIntQuery(
				t,
				conn,
				`SELECT sqlite_rebuild_required
				   FROM command_result_payload_migration
				  WHERE singleton = 1;`,
				0,
			)
			return verifyCommandResultPayloadInventory(conn)
		},
	); err != nil {
		t.Fatalf("verify upgraded storage: %v", err)
	}
}

func TestMigration0011RebuildsEmptyFourKiBDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	database := openFreshTestStore(t, path, nil)
	if err := database.Close(); err != nil {
		t.Fatalf("Close(fresh store): %v", err)
	}

	conn, err := sqlite.OpenConn(
		path,
		sqlite.OpenReadWrite|sqlite.OpenPrivateCache,
	)
	if err != nil {
		t.Fatalf("open downgrade connection: %v", err)
	}
	if err := configurePooledConnection(conn); err != nil {
		_ = conn.Close()
		t.Fatalf("configure downgrade connection: %v", err)
	}
	var transactionErr error
	end, beginErr := sqlitex.ImmediateTransaction(conn)
	if beginErr != nil {
		transactionErr = beginErr
	} else {
		transactionErr = downgradeCommandResultPayloadsForTest(conn)
		end(&transactionErr)
	}
	if transactionErr != nil {
		_ = conn.Close()
		t.Fatalf("downgrade empty store to v10: %v", transactionErr)
	}
	if err := setSQLiteJournalMode(conn, "delete"); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := execute(conn, "PRAGMA page_size = 4096;"); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := execute(conn, "VACUUM;"); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	assertIntQuery(t, conn, "PRAGMA page_size;", 4096)
	if err := conn.Close(); err != nil {
		t.Fatalf("close downgrade connection: %v", err)
	}

	upgraded, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(empty v10 upgrade): %v", err)
	}
	defer upgraded.Close()
	if err := upgraded.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			assertIntQuery(t, conn, "PRAGMA page_size;", 8192)
			assertIntQuery(
				t,
				conn,
				`SELECT source_result_count
				   FROM command_result_payload_migration
				  WHERE singleton = 1;`,
				0,
			)
			assertIntQuery(
				t,
				conn,
				`SELECT sqlite_rebuild_required
				   FROM command_result_payload_migration
				  WHERE singleton = 1;`,
				0,
			)
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
}

func rawStoredCommandResultPayloadForTest(
	t *testing.T,
	payload commandResultPayload,
) storedCommandResultPayload {
	t.Helper()
	size := commandResultPayloadHeaderBytes +
		len(payload.proposal) +
		len(payload.outcome) +
		len(payload.mutations)
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
		t.Fatal(err)
	}
	if _, err := io.Copy(writer, bytes.NewReader(frame)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return storedCommandResultPayload{
		codecVersion:     commandResultPayloadCodecVersion,
		uncompressedSize: len(frame),
		checksum:         sha256.Sum256(frame),
		compressed:       compressed.Bytes(),
	}
}
