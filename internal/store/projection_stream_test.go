package store

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
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
