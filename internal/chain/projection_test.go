package chain_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
)

func TestCoveredTableRegistry(t *testing.T) {
	t.Parallel()

	want := []string{
		"origin_scopes",
		"audit_counters",
		"tasks",
		"plan_revisions",
		"plan_current",
		"memory_records",
		"leases",
		"devices",
		"voter_set",
		"credential_authority",
		"agent_sessions",
		"canonical_refs",
		"credential_authorizations",
		"publications",
		"control_file_proposals",
		"merge_conflicts",
		"session_policy",
	}
	got := chain.CoveredTables()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CoveredTables() = %q, want %q", got, want)
	}
	got[0] = "corrupted"
	if next := chain.CoveredTables(); !reflect.DeepEqual(next, want) {
		t.Fatalf("CoveredTables() exposed mutable registry: %q", next)
	}
}

func TestMutationAndAccumulatorGoldenVectors(t *testing.T) {
	t.Parallel()

	mutations := goldenMutations()
	encoded, err := chain.EncodeMutations(mutations)
	if err != nil {
		t.Fatalf("EncodeMutations() error = %v", err)
	}
	const wantMutations = `[{"after":{"accepted_count":2,"credential_epoch":3,"device_id":"device-a"},"before":{"accepted_count":1,"credential_epoch":3,"device_id":"device-a"},"primary_key":["device-a"],"table":"audit_counters"},{"after":null,"before":{"blocked_by":[],"body":"","created_at":"2026-08-10T12:00:00Z","entity_version":1,"intended_device_id":null,"labels":[],"last_release_reason":null,"owner_agent_session_id":null,"owner_device_id":null,"priority":0,"state":"ready","state_reason":null,"task_id":"task-a","title":"old","updated_at":"2026-08-10T12:00:00Z"},"primary_key":["task-a"],"table":"tasks"},{"after":{"blocked_by":[],"body":"","created_at":"2026-08-10T12:00:00Z","entity_version":1,"intended_device_id":null,"labels":[],"last_release_reason":null,"owner_agent_session_id":null,"owner_device_id":null,"priority":0,"state":"ready","state_reason":null,"task_id":"task-b","title":"new","updated_at":"2026-08-10T12:00:00Z"},"before":null,"primary_key":["task-b"],"table":"tasks"}]`
	if string(encoded) != wantMutations {
		t.Errorf("EncodeMutations() = %s, want %s", encoded, wantMutations)
	}

	reversed := slices.Clone(mutations)
	slices.Reverse(reversed)
	reordered, err := chain.EncodeMutations(reversed)
	if err != nil {
		t.Fatalf("EncodeMutations(reversed) error = %v", err)
	}
	if !bytes.Equal(reordered, encoded) {
		t.Errorf("mutation encoding depends on input order:\n%s\n%s", encoded, reordered)
	}

	previous := filledDigest(0x66)
	resultHash := filledDigest(0x77)
	accumulator, accumulated, err := chain.AppendAccumulator(
		previous,
		9,
		resultHash,
		reversed,
	)
	if err != nil {
		t.Fatalf("AppendAccumulator() error = %v", err)
	}
	if !bytes.Equal(accumulated, encoded) {
		t.Fatalf("AppendAccumulator() bytes = %s, want %s", accumulated, encoded)
	}
	assertDigest(
		t,
		"accumulator append",
		accumulator,
		"dc8c9178ecb55019a6dd3936c239f2759cda5e9f5209815e854e3462427ee408",
	)
	if want := manualAccumulator(previous, 9, resultHash, encoded); accumulator != want {
		t.Fatalf("AppendAccumulator() = %x, manual preimage = %x", accumulator, want)
	}

	empty, err := chain.EncodeMutations(nil)
	if err != nil {
		t.Fatalf("EncodeMutations(nil) error = %v", err)
	}
	if string(empty) != "[]" {
		t.Fatalf("EncodeMutations(nil) = %s, want []", empty)
	}
	emptyAccumulator, emptyBytes, err := chain.AppendAccumulator(
		previous,
		10,
		resultHash,
		nil,
	)
	if err != nil {
		t.Fatalf("AppendAccumulator(empty) error = %v", err)
	}
	assertDigest(
		t,
		"empty accumulator append",
		emptyAccumulator,
		"9e0290dd1c8cb873cc533e18c9dbad1689834bbf4961542f9b8e47cda9bda5ef",
	)
	if !bytes.Equal(emptyBytes, empty) {
		t.Fatalf("empty accumulator bytes = %s, want %s", emptyBytes, empty)
	}
	if want := manualAccumulator(
		previous,
		10,
		resultHash,
		[]byte("[]"),
	); emptyAccumulator != want {
		t.Fatalf(
			"AppendAccumulator(empty) = %x, manual preimage = %x",
			emptyAccumulator,
			want,
		)
	}
}

func TestDecodeMutationsRequiresExactCanonicalEncoding(t *testing.T) {
	t.Parallel()

	encoded, err := chain.EncodeMutations(goldenMutations())
	if err != nil {
		t.Fatalf("EncodeMutations(): %v", err)
	}
	decoded, err := chain.DecodeMutations(encoded)
	if err != nil {
		t.Fatalf("DecodeMutations(): %v", err)
	}
	roundTrip, err := chain.EncodeMutations(decoded)
	if err != nil {
		t.Fatalf("EncodeMutations(decoded): %v", err)
	}
	if !bytes.Equal(roundTrip, encoded) {
		t.Fatalf("decoded mutation bytes changed:\n%s\n%s", encoded, roundTrip)
	}

	tests := []struct {
		name  string
		input string
	}{
		{name: "empty input"},
		{name: "object", input: `{}`},
		{
			name: "unknown member",
			input: `[{"after":null,"before":{},"extra":0,` +
				`"primary_key":["task-a"],"table":"tasks"}]`,
		},
		{
			name: "missing member",
			input: `[{"after":null,"primary_key":["task-a"],` +
				`"table":"tasks"}]`,
		},
		{
			name: "noncanonical member order",
			input: `[{"table":"tasks","primary_key":["task-a"],` +
				`"before":{},"after":null}]`,
		},
		{
			name: "duplicate member",
			input: `[{"after":null,"after":null,"before":{},` +
				`"primary_key":["task-a"],"table":"tasks"}]`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := chain.DecodeMutations(
				[]byte(test.input),
			); !errors.Is(err, chain.ErrInvalidMutation) {
				t.Fatalf(
					"DecodeMutations() error = %v, want ErrInvalidMutation",
					err,
				)
			}
		})
	}
}

func TestMutationValidation(t *testing.T) {
	t.Parallel()

	valid := chain.Mutation{
		Table:      "tasks",
		PrimaryKey: []byte(`["task-a"]`),
		After:      testTaskLogicalRow("task-a", "new", 0),
	}
	tests := []struct {
		name      string
		mutations []chain.Mutation
		want      error
		also      error
	}{
		{
			name: "unknown table",
			mutations: []chain.Mutation{{
				Table:      "events",
				PrimaryKey: []byte(`["event-a"]`),
				After:      []byte(`{"event_id":"event-a"}`),
			}},
			want: chain.ErrUnknownTable,
		},
		{
			name: "noncanonical primary key",
			mutations: []chain.Mutation{{
				Table:      "tasks",
				PrimaryKey: []byte(`[ "task-a" ]`),
				After:      valid.After,
			}},
			want: chain.ErrInvalidMutation,
			also: chain.ErrInvalidPrimaryKey,
		},
		{
			name: "null primary key component",
			mutations: []chain.Mutation{{
				Table:      "tasks",
				PrimaryKey: []byte(`[null]`),
				After:      valid.After,
			}},
			want: chain.ErrInvalidMutation,
			also: chain.ErrInvalidPrimaryKey,
		},
		{
			name: "wrong primary key arity",
			mutations: []chain.Mutation{{
				Table:      "tasks",
				PrimaryKey: []byte(`["task-a","extra"]`),
				After:      valid.After,
			}},
			want: chain.ErrInvalidMutation,
			also: chain.ErrInvalidPrimaryKey,
		},
		{
			name: "wrong primary key type",
			mutations: []chain.Mutation{{
				Table:      "tasks",
				PrimaryKey: []byte(`[1]`),
				After:      []byte(`{"task_id":1}`),
			}},
			want: chain.ErrInvalidMutation,
			also: chain.ErrInvalidPrimaryKey,
		},
		{
			name: "zero credential epoch",
			mutations: []chain.Mutation{{
				Table:      "credential_authorizations",
				PrimaryKey: []byte(`["session-a","device-a",0]`),
				After: []byte(
					`{"device_id":"device-a","epoch":0,"session_id":"session-a"}`,
				),
			}},
			want: chain.ErrInvalidMutation,
			also: chain.ErrInvalidPrimaryKey,
		},
		{
			name: "null transition",
			mutations: []chain.Mutation{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
			}},
			want: chain.ErrInvalidMutation,
		},
		{
			name: "explicit JSON null is not an object",
			mutations: []chain.Mutation{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				After:      []byte(`null`),
			}},
			want: chain.ErrInvalidMutation,
		},
		{
			name: "row omits primary key",
			mutations: []chain.Mutation{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				After:      []byte(`{"title":"new"}`),
			}},
			want: chain.ErrInvalidMutation,
		},
		{
			name: "row primary key differs",
			mutations: []chain.Mutation{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				After:      testTaskLogicalRow("task-b", "new", 0),
			}},
			want: chain.ErrInvalidMutation,
		},
		{
			name: "row has extra field",
			mutations: []chain.Mutation{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				After: bytes.Replace(
					valid.After,
					[]byte(`"body":""`),
					[]byte(`"body":"","bogus":1`),
					1,
				),
			}},
			want: chain.ErrInvalidMutation,
		},
		{
			name: "integer field is string",
			mutations: []chain.Mutation{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				After: bytes.Replace(
					valid.After,
					[]byte(`"priority":0`),
					[]byte(`"priority":"0"`),
					1,
				),
			}},
			want: chain.ErrInvalidMutation,
		},
		{
			name: "array field is object",
			mutations: []chain.Mutation{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				After: bytes.Replace(
					valid.After,
					[]byte(`"labels":[]`),
					[]byte(`"labels":{}`),
					1,
				),
			}},
			want: chain.ErrInvalidMutation,
		},
		{
			name: "required field is null",
			mutations: []chain.Mutation{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				After: bytes.Replace(
					valid.After,
					[]byte(`"title":"new"`),
					[]byte(`"title":null`),
					1,
				),
			}},
			want: chain.ErrInvalidMutation,
		},
		{
			name: "noncanonical row",
			mutations: []chain.Mutation{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				After:      []byte(`{"title":"new","task_id":"task-a"}`),
			}},
			want: chain.ErrInvalidMutation,
		},
		{
			name: "no-op update",
			mutations: []chain.Mutation{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				Before:     valid.After,
				After:      valid.After,
			}},
			want: chain.ErrInvalidMutation,
		},
		{
			name:      "duplicate row",
			mutations: []chain.Mutation{valid, valid},
			want:      chain.ErrDuplicateMutation,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := chain.EncodeMutations(test.mutations)
			if !errors.Is(err, test.want) {
				t.Fatalf("EncodeMutations() error = %v, want %v", err, test.want)
			}
			if test.also != nil && !errors.Is(err, test.also) {
				t.Fatalf("EncodeMutations() error = %v, also want %v", err, test.also)
			}
		})
	}

	for _, resultIndex := range []uint64{0, 1 << 53} {
		if _, _, err := chain.AppendAccumulator(
			chain.Digest{},
			resultIndex,
			chain.Digest{},
			nil,
		); !errors.Is(err, chain.ErrInvalidIndex) {
			t.Errorf(
				"AppendAccumulator(resultIndex=%d) error = %v, want ErrInvalidIndex",
				resultIndex,
				err,
			)
		}
	}
}

func TestMaximumLeaseCascadeMutationEncoding(t *testing.T) {
	t.Parallel()

	paths := make([]string, 32)
	for index := range paths {
		prefix := fmt.Sprintf("%02d-", index)
		paths[index] = prefix + strings.Repeat(`"`, 512-len(prefix))
	}
	mutations := make([]chain.Mutation, 256)
	for index := range mutations {
		leaseID := fmt.Sprintf("lease-%03d", index)
		mutations[index] = chain.Mutation{
			Table:      "leases",
			PrimaryKey: testCanonicalJSON(t, []any{leaseID}),
			Before: testCanonicalJSON(t, map[string]any{
				"lease_id":                leaseID,
				"holder_device_id":        "device-a",
				"holder_agent_session_id": "agent-a",
				"scope":                   "path",
				"task_id":                 nil,
				"path_globs":              paths,
				"ttl_seconds":             86_400,
				"status":                  "active",
				"release_reason":          nil,
				"entity_version":          1,
			}),
			After: testCanonicalJSON(t, map[string]any{
				"lease_id":                leaseID,
				"holder_device_id":        "device-a",
				"holder_agent_session_id": "agent-a",
				"scope":                   "path",
				"task_id":                 nil,
				"path_globs":              paths,
				"ttl_seconds":             86_400,
				"status":                  "released",
				"release_reason":          "session_ended",
				"entity_version":          2,
			}),
		}
	}

	encoded, err := chain.EncodeMutations(mutations)
	if err != nil {
		t.Fatalf("EncodeMutations(maximum lease cascade): %v", err)
	}
	if len(encoded) <= 4<<20 {
		t.Fatalf(
			"maximum lease cascade encoded to %d bytes, want proof above generic 4 MiB limit",
			len(encoded),
		)
	}
}

func TestProjectionStateGoldenVectorsAndOrderInvariance(t *testing.T) {
	t.Parallel()

	versions := chain.Versions{Digest: 1, ProjectionSchema: 1}
	empty, err := chain.StateDigest(versions, nil)
	if err != nil {
		t.Fatalf("StateDigest(empty) error = %v", err)
	}
	assertDigest(
		t,
		"empty state",
		empty,
		"d2e8c43183ca113c0876ac0eef25611610b8368d8d9125840a68f3a506e496c0",
	)
	if want := manualEmptyStateDigest(versions); empty != want {
		t.Fatalf("StateDigest(empty) = %x, manual preimage = %x", empty, want)
	}

	rows := goldenRows()
	state, err := chain.StateDigest(versions, rows)
	if err != nil {
		t.Fatalf("StateDigest(rows) error = %v", err)
	}
	assertDigest(
		t,
		"populated state",
		state,
		"7bb9632cd517025c3ad0d1f9c94e7288aaf7dfc8b5e1fbe2f955c7b9d428fad4",
	)

	reversed := slices.Clone(rows)
	slices.Reverse(reversed)
	reordered, err := chain.StateDigest(versions, reversed)
	if err != nil {
		t.Fatalf("StateDigest(reversed) error = %v", err)
	}
	if reordered != state {
		t.Errorf("StateDigest() depends on input order: %x != %x", reordered, state)
	}
	if state == empty {
		t.Fatal("populated and empty state digests match")
	}

	changed := slices.Clone(rows)
	changed[0].Row = testTaskLogicalRow("task-z", "Z", 2)
	changedDigest, err := chain.StateDigest(versions, changed)
	if err != nil {
		t.Fatalf("StateDigest(changed) error = %v", err)
	}
	if changedDigest == state {
		t.Fatal("covered row change did not change state digest")
	}

	versionDigest, err := chain.StateDigest(
		chain.Versions{Digest: 2, ProjectionSchema: 1},
		rows,
	)
	if err != nil {
		t.Fatalf("StateDigest(version change) error = %v", err)
	}
	if versionDigest == state {
		t.Fatal("digest-version change did not change state digest")
	}
}

func TestProjectionStateValidation(t *testing.T) {
	t.Parallel()

	valid := chain.LogicalRow{
		Table:      "tasks",
		PrimaryKey: []byte(`["task-a"]`),
		Row:        testTaskLogicalRow("task-a", "A", 0),
	}
	for _, versions := range []chain.Versions{
		{},
		{Digest: 1, ProjectionSchema: 0},
		{Digest: 1 << 53, ProjectionSchema: 1},
		{Digest: 1, ProjectionSchema: 1 << 53},
	} {
		if _, err := chain.StateDigest(versions, nil); !errors.Is(
			err,
			chain.ErrInvalidVersions,
		) {
			t.Errorf(
				"StateDigest(%+v) error = %v, want ErrInvalidVersions",
				versions,
				err,
			)
		}
	}

	tests := []struct {
		name string
		rows []chain.LogicalRow
		want error
		also error
	}{
		{
			name: "unknown table",
			rows: []chain.LogicalRow{{
				Table:      "events",
				PrimaryKey: []byte(`["event-a"]`),
				Row:        []byte(`{"event_id":"event-a"}`),
			}},
			want: chain.ErrUnknownTable,
		},
		{
			name: "invalid primary key",
			rows: []chain.LogicalRow{{
				Table:      valid.Table,
				PrimaryKey: []byte(`[null]`),
				Row:        valid.Row,
			}},
			want: chain.ErrInvalidLogicalRow,
			also: chain.ErrInvalidPrimaryKey,
		},
		{
			name: "row is array",
			rows: []chain.LogicalRow{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				Row:        []byte(`[]`),
			}},
			want: chain.ErrInvalidLogicalRow,
		},
		{
			name: "row omits primary key",
			rows: []chain.LogicalRow{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				Row:        []byte(`{"title":"A"}`),
			}},
			want: chain.ErrInvalidLogicalRow,
		},
		{
			name: "row primary key differs",
			rows: []chain.LogicalRow{{
				Table:      valid.Table,
				PrimaryKey: valid.PrimaryKey,
				Row:        testTaskLogicalRow("task-b", "A", 0),
			}},
			want: chain.ErrInvalidLogicalRow,
		},
		{
			name: "blob has wrong decoded length",
			rows: []chain.LogicalRow{{
				Table:      "devices",
				PrimaryKey: []byte(`["device-a"]`),
				Row: testCanonicalJSON(t, map[string]any{
					"device_id":           "device-a",
					"role":                "owner",
					"identity_public_key": "AA",
					"daemon_version":      "1.0.0",
					"max_apply_level":     1,
					"status":              "active",
					"entity_version":      1,
				}),
			}},
			want: chain.ErrInvalidLogicalRow,
		},
		{
			name: "object field is array",
			rows: []chain.LogicalRow{{
				Table:      "session_policy",
				PrimaryKey: []byte(`["session-a"]`),
				Row: []byte(
					`{"entity_version":1,"session_id":"session-a","values":[]}`,
				),
			}},
			want: chain.ErrInvalidLogicalRow,
		},
		{
			name: "duplicate row",
			rows: []chain.LogicalRow{valid, valid},
			want: chain.ErrDuplicateLogicalRow,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := chain.StateDigest(
				chain.Versions{Digest: 1, ProjectionSchema: 1},
				test.rows,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("StateDigest() error = %v, want %v", err, test.want)
			}
			if test.also != nil && !errors.Is(err, test.also) {
				t.Fatalf("StateDigest() error = %v, also want %v", err, test.also)
			}
		})
	}
}

func goldenMutations() []chain.Mutation {
	return []chain.Mutation{
		{
			Table:      "tasks",
			PrimaryKey: []byte(`["task-b"]`),
			After:      testTaskLogicalRow("task-b", "new", 0),
		},
		{
			Table:      "audit_counters",
			PrimaryKey: []byte(`["device-a"]`),
			Before: []byte(
				`{"accepted_count":1,"credential_epoch":3,"device_id":"device-a"}`,
			),
			After: []byte(
				`{"accepted_count":2,"credential_epoch":3,"device_id":"device-a"}`,
			),
		},
		{
			Table:      "tasks",
			PrimaryKey: []byte(`["task-a"]`),
			Before:     testTaskLogicalRow("task-a", "old", 0),
		},
	}
}

func goldenRows() []chain.LogicalRow {
	return []chain.LogicalRow{
		{
			Table:      "tasks",
			PrimaryKey: []byte(`["task-z"]`),
			Row:        testTaskLogicalRow("task-z", "Z", 1),
		},
		{
			Table:      "audit_counters",
			PrimaryKey: []byte(`["device-a"]`),
			Row: []byte(
				`{"accepted_count":2,"credential_epoch":4,"device_id":"device-a"}`,
			),
		},
		{
			Table:      "origin_scopes",
			PrimaryKey: []byte(`["device-b","agent","scope-1"]`),
			Row: []byte(
				`{"device_id":"device-b","last_sequence":4,"scope_id":"scope-1","scope_kind":"agent"}`,
			),
		},
		{
			Table:      "tasks",
			PrimaryKey: []byte(`["task-a"]`),
			Row:        testTaskLogicalRow("task-a", "A", 0),
		},
	}
}

func testTaskLogicalRow(taskID, title string, priority uint64) []byte {
	return []byte(fmt.Sprintf(
		`{"blocked_by":[],"body":"","created_at":"2026-08-10T12:00:00Z",`+
			`"entity_version":1,"intended_device_id":null,"labels":[],`+
			`"last_release_reason":null,"owner_agent_session_id":null,`+
			`"owner_device_id":null,"priority":%d,"state":"ready",`+
			`"state_reason":null,"task_id":%q,"title":%q,`+
			`"updated_at":"2026-08-10T12:00:00Z"}`,
		priority,
		taskID,
		title,
	))
}

func testCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil {
		t.Fatalf("codec.Canonicalize(): %v", err)
	}
	return canonical
}

func manualAccumulator(
	previous chain.Digest,
	resultIndex uint64,
	resultHash chain.Digest,
	mutations []byte,
) chain.Digest {
	digester := sha256.New()
	writeTestBytes(digester, []byte("codecomm/v1/projection-accumulator"))
	writeTestBytes(digester, []byte{0})
	writeTestBytes(digester, previous[:])
	writeTestBytes(digester, testUint64(resultIndex))
	writeTestBytes(digester, resultHash[:])
	writeTestBytes(digester, testUint64(uint64(len(mutations))))
	writeTestBytes(digester, mutations)
	return sumTestDigest(digester)
}

func manualEmptyStateDigest(versions chain.Versions) chain.Digest {
	state := sha256.New()
	writeTestBytes(state, []byte("codecomm/v1/projection-state"))
	writeTestBytes(state, []byte{0})
	writeTestBytes(state, testUint64(versions.Digest))
	writeTestBytes(state, testUint64(versions.ProjectionSchema))
	for _, table := range chain.CoveredTables() {
		tableDigester := sha256.New()
		writeTestBytes(tableDigester, []byte("codecomm/v1/projection-table"))
		writeTestBytes(tableDigester, []byte{0})
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(table)))
		writeTestBytes(tableDigester, length[:])
		writeTestBytes(tableDigester, []byte(table))
		writeTestBytes(tableDigester, make([]byte, 8))
		tableDigest := tableDigester.Sum(nil)
		writeTestBytes(state, tableDigest)
	}
	return sumTestDigest(state)
}
