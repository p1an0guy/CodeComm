package consensus

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	decodeTestSessionID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-012345678901",
	)
	decodeTestWorkspaceID = domain.UUIDv4(
		"550e8400-e29b-41d4-a716-446655440000",
	)
	decodeTestAgentID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-012345678902",
	)
	decodeTestWorkingRootID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-012345678903",
	)
	decodeTestTaskID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-012345678904",
	)
	decodeTestPlanID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-012345678905",
	)
	decodeTestMemoryID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-012345678906",
	)
	decodeTestLeaseID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-012345678907",
	)
	decodeTestPublicationID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-012345678908",
	)
	decodeTestPublicationEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-012345678909",
	)
	decodeTestControlEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-01234567890a",
	)
	decodeTestNewTaskID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-01234567890b",
	)
	decodeTestEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-01234567890c",
	)
	decodeTestOtherSessionID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-01234567890d",
	)
	decodeTestMissingTaskID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-01234567890e",
	)
	decodeTestTimestamp = domain.Timestamp("2026-08-11T12:00:00Z")
)

type decodeFixture struct {
	view               store.StateView
	deviceID           domain.DeviceID
	identityPrivateKey ed25519.PrivateKey
	identityPublicKey  ed25519.PublicKey
	recoveryPublicKey  ed25519.PublicKey
}

func TestDecodeStateViewReconstructsAllProjectionTypes(t *testing.T) {
	t.Parallel()

	fixture := newDecodeFixture(t)
	if len(fixture.view.ProjectionRows) != 17 {
		t.Fatalf(
			"projection row count = %d, want one row for each of 17 tables",
			len(fixture.view.ProjectionRows),
		)
	}
	seen := make(map[string]bool, len(fixture.view.ProjectionRows))
	for _, row := range fixture.view.ProjectionRows {
		seen[row.Table] = true
	}
	for _, table := range chain.CoveredTables() {
		if !seen[table] {
			t.Fatalf("fixture omits covered table %q", table)
		}
	}

	decoded, err := decodeStateView(fixture.view)
	if err != nil {
		t.Fatalf("decodeStateView(): %v", err)
	}
	recoveryKey, err := recoveryPublicKeyFromGenesis(fixture.view)
	if err != nil {
		t.Fatalf("recoveryPublicKeyFromGenesis(): %v", err)
	}
	if !bytes.Equal(recoveryKey, fixture.recoveryPublicKey) {
		t.Fatalf(
			"recovery key = %x, want %x",
			recoveryKey,
			fixture.recoveryPublicKey,
		)
	}

	identityKey, exists := decoded.IdentityPublicKey(fixture.deviceID)
	if !exists || !bytes.Equal(identityKey, fixture.identityPublicKey) {
		t.Fatalf("IdentityPublicKey() = (%x, %t)", identityKey, exists)
	}
	if _, exists := decoded.IdentityPublicKey(
		domain.DeviceID("cc1" + strings.Repeat("f", 64)),
	); exists {
		t.Fatal("IdentityPublicKey() resolved an unknown device")
	}

	signed := decodeTestSignedTask(t, fixture)
	verified, err := event.ParseAndVerify(
		signed.CanonicalBytes(),
		event.VerificationContext{
			SessionID:         decodeTestSessionID,
			WorkspaceID:       decodeTestWorkspaceID,
			IdentityPublicKey: identityKey,
		},
	)
	if err != nil {
		t.Fatalf("ParseAndVerify(resolved key): %v", err)
	}
	outcome, err := reducer.Reduce(decoded.Reducer, verified)
	if err != nil {
		t.Fatalf("decoded reducer Reduce(): %v", err)
	}
	if !outcome.Accepted() {
		t.Fatalf("decoded reducer outcome = %#v, want accepted", outcome)
	}
}

func TestDecodedStateDoesNotAliasViewOrReturnedKeys(t *testing.T) {
	t.Parallel()

	fixture := newDecodeFixture(t)
	decoded, err := decodeStateView(fixture.view)
	if err != nil {
		t.Fatalf("decodeStateView(): %v", err)
	}
	first, exists := decoded.IdentityPublicKey(fixture.deviceID)
	if !exists {
		t.Fatal("IdentityPublicKey() did not resolve fixture device")
	}
	first[0] ^= 0xff
	second, exists := decoded.IdentityPublicKey(fixture.deviceID)
	if !exists || !bytes.Equal(second, fixture.identityPublicKey) {
		t.Fatal("IdentityPublicKey() aliases a prior returned key")
	}

	for index := range fixture.view.GenesisJSON {
		fixture.view.GenesisJSON[index] = 0
	}
	for rowIndex := range fixture.view.ProjectionRows {
		for index := range fixture.view.ProjectionRows[rowIndex].PrimaryKey {
			fixture.view.ProjectionRows[rowIndex].PrimaryKey[index] = 0
		}
		for index := range fixture.view.ProjectionRows[rowIndex].Row {
			fixture.view.ProjectionRows[rowIndex].Row[index] = 0
		}
	}
	third, exists := decoded.IdentityPublicKey(fixture.deviceID)
	if !exists || !bytes.Equal(third, fixture.identityPublicKey) {
		t.Fatal("decoded identity key aliases StateView storage")
	}
	outcome, err := reducer.Reduce(
		decoded.Reducer,
		decodeTestSignedTask(t, fixture),
	)
	if err != nil {
		t.Fatalf("Reduce() after input mutation: %v", err)
	}
	if !outcome.Accepted() {
		t.Fatalf("outcome after input mutation = %#v", outcome)
	}
}

func TestDecodeStateViewRejectsMalformedProjectionFraming(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, *store.StateView)
		want   error
	}{
		{
			name: "unknown table",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				view.ProjectionRows[0].Table = "unknown_projection"
			},
			want: chain.ErrUnknownTable,
		},
		{
			name: "primary key differs from row",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				row := findDecodeRow(t, view, "tasks")
				row.PrimaryKey = canonicalJSON(t, []any{
					string(decodeTestMissingTaskID),
				})
			},
			want: chain.ErrInvalidLogicalRow,
		},
		{
			name: "row has unknown field",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				row := findDecodeRow(t, view, "tasks")
				members := decodeObject(t, row.Row)
				members["unexpected"] = json.RawMessage("true")
				row.Row = canonicalJSON(t, members)
			},
			want: chain.ErrInvalidLogicalRow,
		},
		{
			name: "duplicate logical key",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				row := findDecodeRow(t, view, "tasks")
				view.ProjectionRows = append(
					view.ProjectionRows,
					chain.LogicalRow{
						Table:      row.Table,
						PrimaryKey: bytes.Clone(row.PrimaryKey),
						Row:        bytes.Clone(row.Row),
					},
				)
			},
			want: chain.ErrDuplicateLogicalRow,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newDecodeFixture(t)
			test.mutate(t, &fixture.view)
			if _, err := decodeStateView(fixture.view); !errors.Is(err, test.want) {
				t.Fatalf(
					"decodeStateView() error = %v, want %v",
					err,
					test.want,
				)
			}
		})
	}
}

func TestDecodeStateViewEnforcesSingletonCardinality(t *testing.T) {
	t.Parallel()

	t.Run("missing", func(t *testing.T) {
		fixture := newDecodeFixture(t)
		removeDecodeRow(t, &fixture.view, "canonical_refs")
		refreshDecodeDigest(t, &fixture.view)
		if _, err := decodeStateView(fixture.view); !errors.Is(
			err,
			ErrInvalidStateView,
		) {
			t.Fatalf("decodeStateView() error = %v", err)
		}
	})

	t.Run("duplicate distinct keys", func(t *testing.T) {
		fixture := newDecodeFixture(t)
		fixture.view.ProjectionRows = append(
			fixture.view.ProjectionRows,
			decodeLogicalRow(t, "plan_current", []any{
				string(decodeTestOtherSessionID),
			}, map[string]any{
				"session_id":       decodeTestOtherSessionID,
				"plan_revision_id": decodeTestPlanID,
				"entity_version":   uint64(1),
			}),
		)
		refreshDecodeDigest(t, &fixture.view)
		if _, err := decodeStateView(fixture.view); !errors.Is(
			err,
			ErrInvalidStateView,
		) {
			t.Fatalf("decodeStateView() error = %v", err)
		}
	})
}

func TestDecodeStateViewRejectsStrictNestedAndDomainCorruption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, *store.StateView)
	}{
		{
			name: "null scalar array element",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				setDecodeRowField(t, view, "tasks", "labels", []any{nil})
			},
		},
		{
			name: "unknown endorsement field",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				row := findDecodeRow(t, view, "credential_authorizations")
				members := decodeObject(t, row.Row)
				var endorsements []map[string]any
				if err := json.Unmarshal(
					members["clock_endorsements"],
					&endorsements,
				); err != nil {
					t.Fatal(err)
				}
				endorsements[0]["unexpected"] = true
				members["clock_endorsements"] =
					json.RawMessage(canonicalJSON(t, endorsements))
				row.Row = canonicalJSON(t, members)
			},
		},
		{
			name: "invalid device domain value",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				setDecodeRowField(
					t,
					view,
					"devices",
					"daemon_version",
					"not semver",
				)
			},
		},
		{
			name: "missing cross row reference",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				setDecodeRowField(
					t,
					view,
					"plan_revisions",
					"task_ids",
					[]domain.UUIDv7{decodeTestMissingTaskID},
				)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newDecodeFixture(t)
			test.mutate(t, &fixture.view)
			refreshDecodeDigest(t, &fixture.view)
			if _, err := decodeStateView(fixture.view); !errors.Is(
				err,
				ErrInvalidStateView,
			) {
				t.Fatalf("decodeStateView() error = %v", err)
			}
		})
	}
}

func TestDecodeStateViewRejectsInvalidGenesisRecoveryKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, *store.StateView)
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				members := decodeObject(t, view.GenesisJSON)
				delete(members, "recovery_public_key")
				view.GenesisJSON = canonicalJSON(t, members)
			},
		},
		{
			name: "null",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				members := decodeObject(t, view.GenesisJSON)
				members["recovery_public_key"] = json.RawMessage("null")
				view.GenesisJSON = canonicalJSON(t, members)
			},
		},
		{
			name: "padded base64",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				setDecodeGenesisField(
					t,
					view,
					"recovery_public_key",
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				)
			},
		},
		{
			name: "wrong length",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				setDecodeGenesisField(
					t,
					view,
					"recovery_public_key",
					codec.EncodeBase64URL(make([]byte, 31)),
				)
			},
		},
		{
			name: "noncanonical genesis",
			mutate: func(t *testing.T, view *store.StateView) {
				t.Helper()
				view.GenesisJSON = append(
					[]byte(nil),
					append(view.GenesisJSON, '\n')...,
				)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newDecodeFixture(t)
			test.mutate(t, &fixture.view)
			if _, err := decodeStateView(fixture.view); !errors.Is(
				err,
				ErrInvalidStateView,
			) {
				t.Fatalf("decodeStateView() error = %v", err)
			}
		})
	}
}

func TestDecodeStateViewRejectsProjectionDigestMismatch(t *testing.T) {
	t.Parallel()

	fixture := newDecodeFixture(t)
	fixture.view.ProjectionStateDigest[0] ^= 0xff
	if _, err := decodeStateView(fixture.view); !errors.Is(
		err,
		ErrInvalidStateView,
	) {
		t.Fatalf("decodeStateView() error = %v", err)
	}
}

func TestDecodeStateViewRejectsPartialRaftProvenance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*store.StateView)
	}{
		{
			name: "term only",
			mutate: func(view *store.StateView) {
				value := uint64(1)
				view.CurrentTerm = &value
			},
		},
		{
			name: "index only",
			mutate: func(view *store.StateView) {
				value := uint64(1)
				view.LastRaftAppliedLogIndex = &value
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newDecodeFixture(t)
			test.mutate(&fixture.view)
			if _, err := decodeStateView(fixture.view); !errors.Is(
				err,
				ErrInvalidStateView,
			) {
				t.Fatalf("decodeStateView() error = %v", err)
			}
		})
	}
}

func newDecodeFixture(t *testing.T) decodeFixture {
	t.Helper()

	identityPrivateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x11}, ed25519.SeedSize),
	)
	identityPublicKey := append(
		ed25519.PublicKey(nil),
		identityPrivateKey.Public().(ed25519.PublicKey)...,
	)
	deviceIDText, err := codec.DeriveDeviceID(identityPublicKey)
	if err != nil {
		t.Fatalf("DeriveDeviceID(): %v", err)
	}
	deviceID := domain.DeviceID(deviceIDText)
	recoveryPrivateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x22}, ed25519.SeedSize),
	)
	recoveryPublicKey := append(
		ed25519.PublicKey(nil),
		recoveryPrivateKey.Public().(ed25519.PublicKey)...,
	)

	epochPrivateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x33}, ed25519.SeedSize),
	)
	epochPublicKey := epochPrivateKey.Public().(ed25519.PublicKey)
	epochDigest := sha256.Sum256(epochPublicKey)
	bindingPreimage := canonicalJSON(t, map[string]any{
		"device_id":        deviceID,
		"epoch":            uint64(1),
		"epoch_public_key": codec.EncodeBase64URL(epochPublicKey),
		"session_id":       decodeTestSessionID,
	})
	bindingSignature := signDecodeInput(
		t,
		identityPrivateKey,
		codec.SignatureCredentialBinding,
		bindingPreimage,
	)
	endorsementPreimage := canonicalJSON(t, map[string]any{
		"authority_voter_set_version": uint64(1),
		"epoch":                       uint64(1),
		"issued_at":                   string(decodeTestTimestamp),
		"key_digest":                  codec.EncodeBase64URL(epochDigest[:]),
		"session_id":                  decodeTestSessionID,
		"subject_device_id":           deviceID,
	})
	endorsementSignature := signDecodeInput(
		t,
		identityPrivateKey,
		codec.SignatureCredentialTimeEndorsement,
		endorsementPreimage,
	)

	canonicalCommit := domain.GitOID("sha1:" + strings.Repeat("1", 40))
	candidateCommit := domain.GitOID("sha1:" + strings.Repeat("2", 40))
	treeOID := domain.GitOID("sha1:" + strings.Repeat("3", 40))
	mergeBase := domain.GitOID("sha1:" + strings.Repeat("0", 40))
	publicationPath := domain.RepositoryPath("src/main.go")
	conflictID := decodeConflictID(
		t,
		decodeTestPublicationID,
		[]domain.GitOID{mergeBase},
		canonicalCommit,
		candidateCommit,
	)
	artifactDigest := sha256.Sum256([]byte("artifact"))
	values := policy.DefaultValues()

	rows := []chain.LogicalRow{
		decodeLogicalRow(t, "origin_scopes", []any{
			string(deviceID),
			"agent",
			string(decodeTestAgentID),
		}, map[string]any{
			"device_id":     deviceID,
			"scope_kind":    "agent",
			"scope_id":      decodeTestAgentID,
			"last_sequence": uint64(1),
		}),
		decodeLogicalRow(t, "audit_counters", []any{
			string(deviceID),
		}, map[string]any{
			"device_id":        deviceID,
			"credential_epoch": uint64(1),
			"accepted_count":   uint64(0),
		}),
		decodeLogicalRow(t, "tasks", []any{
			string(decodeTestTaskID),
		}, map[string]any{
			"task_id":                decodeTestTaskID,
			"title":                  "Restart projection decoder",
			"body":                   "Decode every covered table.",
			"state":                  "ready",
			"state_reason":           nil,
			"priority":               uint64(2),
			"blocked_by":             []domain.UUIDv7{},
			"labels":                 []string{"phase2"},
			"owner_device_id":        nil,
			"owner_agent_session_id": nil,
			"intended_device_id":     nil,
			"last_release_reason":    nil,
			"entity_version":         uint64(1),
			"created_at":             decodeTestTimestamp,
			"updated_at":             decodeTestTimestamp,
		}),
		decodeLogicalRow(t, "plan_revisions", []any{
			string(decodeTestPlanID),
		}, map[string]any{
			"plan_revision_id":      decodeTestPlanID,
			"supersedes":            nil,
			"title":                 "Phase 2",
			"body":                  "Restore reducer state.",
			"task_ids":              []domain.UUIDv7{decodeTestTaskID},
			"proposed_by_device_id": deviceID,
			"created_at":            decodeTestTimestamp,
		}),
		decodeLogicalRow(t, "plan_current", []any{
			string(decodeTestSessionID),
		}, map[string]any{
			"session_id":       decodeTestSessionID,
			"plan_revision_id": decodeTestPlanID,
			"entity_version":   uint64(1),
		}),
		decodeLogicalRow(t, "memory_records", []any{
			string(decodeTestMemoryID),
		}, map[string]any{
			"memory_id":  decodeTestMemoryID,
			"scope":      "task",
			"task_id":    decodeTestTaskID,
			"key":        "decoder",
			"body":       "Projection rows are canonical.",
			"supersedes": nil,
			"created_at": decodeTestTimestamp,
		}),
		decodeLogicalRow(t, "leases", []any{
			string(decodeTestLeaseID),
		}, map[string]any{
			"lease_id":                decodeTestLeaseID,
			"holder_device_id":        deviceID,
			"holder_agent_session_id": decodeTestAgentID,
			"scope":                   "path",
			"task_id":                 nil,
			"path_globs":              []string{"src/**"},
			"ttl_seconds":             uint64(30),
			"status":                  "active",
			"release_reason":          nil,
			"entity_version":          uint64(1),
		}),
		decodeLogicalRow(t, "devices", []any{
			string(deviceID),
		}, map[string]any{
			"device_id":           deviceID,
			"role":                "owner",
			"identity_public_key": codec.EncodeBase64URL(identityPublicKey),
			"daemon_version":      "1.0.0",
			"max_apply_level":     uint64(1),
			"status":              "active",
			"entity_version":      uint64(1),
		}),
		decodeLogicalRow(t, "voter_set", []any{
			string(decodeTestSessionID),
		}, map[string]any{
			"session_id":        decodeTestSessionID,
			"voter_device_ids":  []domain.DeviceID{deviceID},
			"voter_set_version": uint64(1),
		}),
		decodeLogicalRow(t, "credential_authority", []any{
			string(decodeTestSessionID),
		}, map[string]any{
			"session_id":                     decodeTestSessionID,
			"voter_device_ids":               []domain.DeviceID{deviceID},
			"voter_set_version":              uint64(1),
			"activation_source":              "genesis",
			"activation_checkpoint_event_id": nil,
			"activation_proofs":              []json.RawMessage{},
			"prior_authority_signer":         nil,
			"prior_authority_handoff":        nil,
		}),
		decodeLogicalRow(t, "agent_sessions", []any{
			string(decodeTestAgentID),
		}, map[string]any{
			"agent_session_id": decodeTestAgentID,
			"device_id":        deviceID,
			"client_kind":      "codex",
			"agent_profile_id": nil,
			"state":            "idle",
			"resume_state":     nil,
			"working_root_id":  decodeTestWorkingRootID,
			"end_reason":       nil,
			"entity_version":   uint64(1),
		}),
		decodeLogicalRow(t, "canonical_refs", []any{
			"refs/codecomm/canonical",
		}, map[string]any{
			"ref_name":       "refs/codecomm/canonical",
			"commit_oid":     canonicalCommit,
			"entity_version": uint64(1),
		}),
		decodeLogicalRow(t, "credential_authorizations", []any{
			string(decodeTestSessionID),
			string(deviceID),
			uint64(1),
		}, map[string]any{
			"session_id":                  decodeTestSessionID,
			"device_id":                   deviceID,
			"epoch":                       uint64(1),
			"epoch_public_key":            codec.EncodeBase64URL(epochPublicKey),
			"key_digest":                  codec.EncodeBase64URL(epochDigest[:]),
			"role":                        "owner",
			"issued_at":                   string(decodeTestTimestamp),
			"not_before":                  string(decodeTestTimestamp),
			"validity_seconds":            uint64(1_800),
			"authority_voter_set_version": uint64(1),
			"clock_endorsements": []map[string]any{{
				"device_id": deviceID,
				"signature": codec.EncodeBase64URL(
					endorsementSignature,
				),
			}},
			"binding_signature": codec.EncodeBase64URL(
				bindingSignature,
			),
			"authorization_chain_index": uint64(1),
		}),
		decodeLogicalRow(t, "publications", []any{
			string(decodeTestPublicationID),
		}, map[string]any{
			"publication_id":            decodeTestPublicationID,
			"proposal_event_id":         decodeTestPublicationEventID,
			"supersedes_publication_id": nil,
			"task_id":                   decodeTestTaskID,
			"author_device_id":          deviceID,
			"author_agent_session_id":   decodeTestAgentID,
			"base_commit":               canonicalCommit,
			"commit_oid":                candidateCommit,
			"tree_oid":                  treeOID,
			"parent_oids":               []domain.GitOID{canonicalCommit},
			"paths":                     []domain.RepositoryPath{publicationPath},
			"artifact_digest": codec.EncodeBase64URL(
				artifactDigest[:],
			),
			"resolves_conflict_ids":     []domain.ConflictID{},
			"working_root_id":           decodeTestWorkingRootID,
			"staging_receipts":          []map[string]any{},
			"state":                     "proposed",
			"terminal_source":           nil,
			"canonical_lineage_member":  false,
			"review_verdict":            nil,
			"reviewer_device_id":        nil,
			"reviewer_agent_session_id": nil,
			"review_actor_type":         nil,
			"decision_reason":           nil,
			"entity_version":            uint64(1),
		}),
		decodeLogicalRow(t, "control_file_proposals", []any{
			string(decodeTestControlEventID),
		}, map[string]any{
			"proposal_event_id":     decodeTestControlEventID,
			"session_id":            decodeTestSessionID,
			"path":                  ".codecommignore",
			"operation":             "delete",
			"content_digest":        nil,
			"content_size":          uint64(0),
			"diff":                  "remove generated rule",
			"proposed_by_device_id": deviceID,
			"chain_index":           uint64(2),
		}),
		decodeLogicalRow(t, "merge_conflicts", []any{
			string(conflictID),
		}, map[string]any{
			"conflict_id":               conflictID,
			"publication_id":            decodeTestPublicationID,
			"merge_kind":                "merge",
			"replay_commit_oid":         nil,
			"merge_base_oids":           []domain.GitOID{mergeBase},
			"canonical_commit":          canonicalCommit,
			"candidate_commit":          candidateCommit,
			"paths":                     []domain.RepositoryPath{publicationPath},
			"status":                    "unresolved",
			"resolution_kind":           nil,
			"resolution_publication_id": nil,
			"force_reason":              nil,
			"resolved_by_device_id":     nil,
			"entity_version":            uint64(1),
		}),
		decodeLogicalRow(t, "session_policy", []any{
			string(decodeTestSessionID),
		}, map[string]any{
			"session_id": decodeTestSessionID,
			"values": map[string]any{
				"checkpoint_events":                values.CheckpointEvents,
				"checkpoint_interval_seconds":      values.CheckpointIntervalSeconds,
				"lease_min_ttl_seconds":            values.LeaseMinTTLSeconds,
				"lease_default_ttl_seconds":        values.LeaseDefaultTTLSeconds,
				"lease_max_ttl_seconds":            values.LeaseMaxTTLSeconds,
				"agent_claim_limit":                values.AgentClaimLimit,
				"agent_lease_limit":                values.AgentLeaseLimit,
				"device_claim_limit":               values.DeviceClaimLimit,
				"device_lease_limit":               values.DeviceLeaseLimit,
				"advertisement_interval_seconds":   values.AdvertisementIntervalSeconds,
				"audit_depth_per_device_per_epoch": values.AuditDepthPerDevicePerEpoch,
				"max_member_devices":               values.MaxMemberDevices,
				"max_active_agent_sessions":        values.MaxActiveAgentSessions,
				"cluster_min_apply_level":          values.ClusterMinApplyLevel,
			},
			"entity_version": uint64(1),
		}),
	}

	view := store.StateView{
		SessionID:          decodeTestSessionID,
		WorkspaceID:        decodeTestWorkspaceID,
		RecoveryGeneration: 0,
		GenesisJSON: canonicalJSON(t, map[string]any{
			"recovery_generation": uint64(0),
			"recovery_public_key": codec.EncodeBase64URL(
				recoveryPublicKey,
			),
			"session_id":   decodeTestSessionID,
			"workspace_id": decodeTestWorkspaceID,
		}),
		Heads: store.ApplyHeads{
			ChainIndex:              2,
			ResultIndex:             2,
			DigestVersion:           1,
			ProjectionSchemaVersion: 1,
		},
		ProjectionRows: rows,
	}
	refreshDecodeDigest(t, &view)
	return decodeFixture{
		view:               view,
		deviceID:           deviceID,
		identityPrivateKey: identityPrivateKey,
		identityPublicKey:  identityPublicKey,
		recoveryPublicKey:  recoveryPublicKey,
	}
}

func decodeTestSignedTask(
	t *testing.T,
	fixture decodeFixture,
) event.SignedEvent {
	t.Helper()
	binding, err := event.NewMCPBinding(
		fixture.deviceID,
		decodeTestAgentID,
		nil,
	)
	if err != nil {
		t.Fatalf("NewMCPBinding(): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindTaskCreated,
			EntityID: event.StringEntityID(string(decodeTestNewTaskID)),
			Actions:  []event.Action{},
			Payload:  json.RawMessage(`{"priority":2,"title":"after restart"}`),
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        decodeTestEventID,
			SessionID:      decodeTestSessionID,
			WorkspaceID:    decodeTestWorkspaceID,
			CreatedAt:      decodeTestTimestamp,
			OriginSequence: 2,
		},
	)
	if err != nil {
		t.Fatalf("BuildProposal(): %v", err)
	}
	signed, err := event.Sign(proposal, fixture.identityPrivateKey)
	if err != nil {
		t.Fatalf("event.Sign(): %v", err)
	}
	return signed
}

func decodeLogicalRow(
	t *testing.T,
	table string,
	primaryKey []any,
	row map[string]any,
) chain.LogicalRow {
	t.Helper()
	return chain.LogicalRow{
		Table:      table,
		PrimaryKey: canonicalJSON(t, primaryKey),
		Row:        canonicalJSON(t, row),
	}
}

func canonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T): %v", value, err)
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil {
		t.Fatalf("codec.Canonicalize(%s): %v", encoded, err)
	}
	return canonical
}

func signDecodeInput(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	label codec.SignatureLabel,
	preimage []byte,
) []byte {
	t.Helper()
	input, err := codec.BuildSignedInput(label, preimage)
	if err != nil {
		t.Fatalf("BuildSignedInput(%q): %v", label, err)
	}
	return ed25519.Sign(privateKey, input)
}

func decodeConflictID(
	t *testing.T,
	publicationID domain.UUIDv7,
	mergeBaseOIDs []domain.GitOID,
	canonicalCommit domain.GitOID,
	candidateCommit domain.GitOID,
) domain.ConflictID {
	t.Helper()
	canonical := canonicalJSON(t, map[string]any{
		"workspace_id":         decodeTestWorkspaceID,
		"merge_inputs_version": uint64(1),
		"merge_kind":           "merge",
		"publication_id":       publicationID,
		"replay_commit_oid":    nil,
		"merge_base_oids":      mergeBaseOIDs,
		"canonical_commit":     canonicalCommit,
		"candidate_commit":     candidateCommit,
	})
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("codecomm/v1/conflict-id"))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(canonical)
	return domain.ConflictID("ccf1" + hex.EncodeToString(hasher.Sum(nil)))
}

func findDecodeRow(
	t *testing.T,
	view *store.StateView,
	table string,
) *chain.LogicalRow {
	t.Helper()
	for index := range view.ProjectionRows {
		if view.ProjectionRows[index].Table == table {
			return &view.ProjectionRows[index]
		}
	}
	t.Fatalf("projection row %q not found", table)
	return nil
}

func removeDecodeRow(
	t *testing.T,
	view *store.StateView,
	table string,
) {
	t.Helper()
	for index := range view.ProjectionRows {
		if view.ProjectionRows[index].Table != table {
			continue
		}
		view.ProjectionRows = append(
			view.ProjectionRows[:index],
			view.ProjectionRows[index+1:]...,
		)
		return
	}
	t.Fatalf("projection row %q not found", table)
}

func decodeObject(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatalf("json.Unmarshal(%s): %v", raw, err)
	}
	return members
}

func setDecodeRowField(
	t *testing.T,
	view *store.StateView,
	table string,
	field string,
	value any,
) {
	t.Helper()
	row := findDecodeRow(t, view, table)
	members := decodeObject(t, row.Row)
	members[field] = json.RawMessage(canonicalJSON(t, value))
	row.Row = canonicalJSON(t, members)
}

func setDecodeGenesisField(
	t *testing.T,
	view *store.StateView,
	field string,
	value any,
) {
	t.Helper()
	members := decodeObject(t, view.GenesisJSON)
	members[field] = json.RawMessage(canonicalJSON(t, value))
	view.GenesisJSON = canonicalJSON(t, members)
}

func refreshDecodeDigest(t *testing.T, view *store.StateView) {
	t.Helper()
	digest, err := chain.StateDigest(
		chain.Versions{
			Digest:           view.Heads.DigestVersion,
			ProjectionSchema: view.Heads.ProjectionSchemaVersion,
		},
		view.ProjectionRows,
	)
	if err != nil {
		t.Fatalf("chain.StateDigest(): %v", err)
	}
	view.ProjectionStateDigest = store.Digest(digest)
}
