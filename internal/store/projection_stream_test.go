package store

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"zombiezen.com/go/sqlite"
)

func TestProjectionStreamUsesCanonicalLogicalPrimaryKeyOrder(t *testing.T) {
	fixture := newProjectionFixture(t)
	base := fixture.initialWrites.CredentialAuthorizations[0]
	epoch2 := base
	epoch2.Epoch = 2
	epoch2.AuthorizationChainIndex = 2
	epoch10 := base
	epoch10.Epoch = 10
	epoch10.AuthorizationChainIndex = 10
	fixture.initialWrites.CredentialAuthorizations =
		[]CredentialAuthorizationRow{base, epoch2, epoch10}

	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initial := commitmentInitialState(
		t,
		domain.UUIDv7(testSessionID),
		0,
		fixture.initialWrites,
	)
	if _, err := database.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}

	err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			counts, err := projectionTableRowCounts(conn)
			if err != nil {
				return err
			}
			var authorizationCount uint64
			for _, count := range counts {
				if count.Table == "credential_authorizations" {
					authorizationCount = count.Count
				}
			}
			if authorizationCount != 3 {
				t.Fatalf(
					"credential authorization count = %d, want 3",
					authorizationCount,
				)
			}

			var (
				rows              []chain.LogicalRow
				authorizationKeys []string
			)
			if err := streamProjectionLogicalRows(
				conn,
				func(row chain.LogicalRow) error {
					rows = append(rows, row)
					if row.Table == "credential_authorizations" {
						authorizationKeys = append(
							authorizationKeys,
							string(row.PrimaryKey),
						)
					}
					return nil
				},
			); err != nil {
				return err
			}
			wantKeys := []string{
				string(canonicalProjectionValue(t, []any{
					base.SessionID,
					base.DeviceID,
					uint64(10),
				})),
				string(canonicalProjectionValue(t, []any{
					base.SessionID,
					base.DeviceID,
					uint64(2),
				})),
				string(canonicalProjectionValue(t, []any{
					base.SessionID,
					base.DeviceID,
					uint64(7),
				})),
			}
			if !slices.Equal(authorizationKeys, wantKeys) {
				t.Fatalf(
					"authorization key order = %q, want %q",
					authorizationKeys,
					wantKeys,
				)
			}

			streamed, err := projectionStateDigest(
				conn,
				chain.Versions{Digest: 1, ProjectionSchema: 1},
			)
			if err != nil {
				return err
			}
			batch, err := chain.StateDigest(
				chain.Versions{Digest: 1, ProjectionSchema: 1},
				rows,
			)
			if err != nil {
				return err
			}
			if chain.Digest(streamed) != batch {
				t.Fatalf(
					"streamed projection digest = %x, batch = %x",
					streamed,
					batch,
				)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("projection stream: %v", err)
	}
}

func TestProjectionAuthorityRewindIgnoresUnrelatedRevokedDevices(
	t *testing.T,
) {
	t.Parallel()

	devices := projectionDevices(t, 10)
	authorityID := devices[0].ID
	for index := 1; index < len(devices); index++ {
		devices[index].Status = device.StatusRevoked
	}
	initial := commitmentInitialState(
		t,
		domain.UUIDv7(testSessionID),
		0,
		ProjectionWrites{
			Devices: devices,
			CredentialAuthority: []CredentialAuthorityRow{{
				SessionID:        domain.UUIDv7(testSessionID),
				VoterDeviceIDs:   []domain.DeviceID{authorityID},
				VoterSetVersion:  1,
				ActivationSource: CredentialAuthorityGenesis,
			}},
		},
	)
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	if _, err := database.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}

	err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			state, found, err := readConsensusState(conn)
			if err != nil {
				return err
			}
			if !found {
				t.Fatal("initialized store has no consensus state")
			}
			genesis, err := readGenesisBoundary(
				conn,
				state.recoveryGeneration,
				state.sessionID,
			)
			if err != nil {
				return err
			}
			rows, digest, err := projectionAuthorityRowsAtResultCut(
				conn,
				state,
				genesis,
				state.resultIndex,
			)
			if err != nil {
				return err
			}
			if len(rows) != 2 {
				t.Fatalf(
					"bounded authority rows = %d, want authority plus active device",
					len(rows),
				)
			}
			var retainedDevice domain.DeviceID
			for _, row := range rows {
				if row.Table != "devices" {
					continue
				}
				member, err := decodeEvidenceDevice(row.Row)
				if err != nil {
					return err
				}
				retainedDevice = member.ID
			}
			if retainedDevice != authorityID {
				t.Fatalf(
					"retained authority device = %s, want %s",
					retainedDevice,
					authorityID,
				)
			}
			current, err := projectionStateDigest(
				conn,
				chain.Versions{
					Digest:           state.digestVersion,
					ProjectionSchema: state.projectionSchemaVersion,
				},
			)
			if err != nil {
				return err
			}
			if digest != current {
				t.Fatalf(
					"rewound state digest = %x, current = %x",
					digest,
					current,
				)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("projection authority rewind: %v", err)
	}
}
