package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"zombiezen.com/go/sqlite"
)

func TestRebootstrapInstallMarkerClearRequiresExactBinding(
	t *testing.T,
) {
	t.Parallel()

	state, marker, _ := newRebootstrapInstallMarkerTestFixture(t)
	changed := marker
	changed.InstalledAt = "2026-08-20T01:00:01Z"
	if err := state.ClearRebootstrapInstallMarker(
		t.Context(),
		changed,
	); !errors.Is(err, ErrRebootstrapInstallMarker) {
		t.Fatalf("ClearRebootstrapInstallMarker(mismatch) error = %v", err)
	}
	got, found, err := state.RebootstrapInstallMarker(t.Context())
	if err != nil || !found || got != marker {
		t.Fatalf("marker after mismatched clear = (%+v, %t, %v)", got, found, err)
	}
	if err := state.ClearRebootstrapInstallMarker(
		t.Context(),
		marker,
	); err != nil {
		t.Fatalf("ClearRebootstrapInstallMarker(exact): %v", err)
	}
	if _, found, err := state.RebootstrapInstallMarker(
		t.Context(),
	); err != nil || found {
		t.Fatalf("marker after exact clear = (found %t, err %v)", found, err)
	}
}

func TestRebootstrapInstallMarkerRejectsCorrelatedStateCorruption(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(
			*sqlite.Conn,
			RebootstrapInstallMarker,
			domain.DeviceID,
		) error
	}{
		{
			name: "settled generation",
			mutate: func(
				conn *sqlite.Conn,
				_ RebootstrapInstallMarker,
				_ domain.DeviceID,
			) error {
				return execute(
					conn,
					`UPDATE rebootstrap_install_marker
					    SET recovery_generation = recovery_generation + 1;`,
				)
			},
		},
		{
			name: "session",
			mutate: func(
				conn *sqlite.Conn,
				_ RebootstrapInstallMarker,
				_ domain.DeviceID,
			) error {
				return execute(
					conn,
					`UPDATE rebootstrap_install_marker
					    SET session_id =
					        '01890f47-3e72-7000-8000-000000000099';`,
				)
			},
		},
		{
			name: "workspace",
			mutate: func(
				conn *sqlite.Conn,
				_ RebootstrapInstallMarker,
				_ domain.DeviceID,
			) error {
				return execute(
					conn,
					`UPDATE rebootstrap_install_marker
					    SET workspace_id =
					        '550e8400-e29b-41d4-a716-446655440099';`,
				)
			},
		},
		{
			name: "attestation generation",
			mutate: func(
				conn *sqlite.Conn,
				marker RebootstrapInstallMarker,
				_ domain.DeviceID,
			) error {
				return execute(
					conn,
					`UPDATE replication_attestations
					    SET recovery_generation = recovery_generation + 1
					  WHERE attestation_id = ?1;`,
					marker.SnapshotAttestationID,
				)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			state, marker, authorityID :=
				newRebootstrapInstallMarkerTestFixture(t)
			if err := state.withImmediate(
				t.Context(),
				func(conn *sqlite.Conn) error {
					return test.mutate(conn, marker, authorityID)
				},
			); err != nil {
				t.Fatalf("corrupt marker fixture: %v", err)
			}
			if _, found, err := state.RebootstrapInstallMarker(
				t.Context(),
			); !errors.Is(err, ErrRebootstrapInstallMarker) || found {
				t.Fatalf(
					"corrupt marker read = (found %t, err %v), want integrity failure",
					found,
					err,
				)
			}
		})
	}
}

func TestRebootstrapInstallMarkerCanClearAfterMembershipChanges(
	t *testing.T,
) {
	t.Parallel()

	state, marker, _ := newRebootstrapInstallMarkerTestFixture(t)
	if err := state.withImmediate(
		t.Context(),
		func(conn *sqlite.Conn) error {
			voters := `["` + string(marker.DeviceID) + `"]`
			if err := execute(
				conn,
				`UPDATE devices SET status = 'revoked'
				  WHERE device_id = ?1;`,
				string(marker.DeviceID),
			); err != nil {
				return err
			}
			if err := execute(
				conn,
				`UPDATE voter_set
				    SET voter_device_ids_json = ?1,
				        voter_set_version = voter_set_version + 1;`,
				voters,
			); err != nil {
				return err
			}
			return execute(
				conn,
				`UPDATE credential_authority
				    SET voter_device_ids_json = ?1;`,
				voters,
			)
		},
	); err != nil {
		t.Fatalf("change membership after installation: %v", err)
	}
	got, found, err := state.RebootstrapInstallMarker(t.Context())
	if err != nil || !found || got != marker {
		t.Fatalf(
			"marker after membership change = (%+v, %t, %v)",
			got,
			found,
			err,
		)
	}
	if err := state.ClearRebootstrapInstallMarker(
		t.Context(),
		marker,
	); err != nil {
		t.Fatalf("clear marker after membership change: %v", err)
	}
}

func newRebootstrapInstallMarkerTestFixture(
	t *testing.T,
) (LocalState, RebootstrapInstallMarker, domain.DeviceID) {
	t.Helper()

	fixture, stage, _, cut := logicalSnapshotInstallFixture(t)
	installedAt := domain.Timestamp("2026-08-20T01:00:00Z")
	installed, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions(installedAt),
	)
	if err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(): %v", err)
	}
	privateKey := resultBatchPrivateKey(2)
	defer clear(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	state := fixture.target.LocalState()
	if err := state.withImmediate(
		t.Context(),
		func(conn *sqlite.Conn) error {
			if err := execute(
				conn,
				`INSERT INTO devices(
				    device_id, role, identity_public_key, daemon_version,
				    max_apply_level, status, entity_version
				) VALUES (?1, 'editor', ?2, '0.1.0', 1, 'active', 1);`,
				string(deviceID),
				[]byte(publicKey),
			); err != nil {
				return err
			}
			return writeRebootstrapInstallMarker(
				conn,
				cut,
				deviceID,
				installed.AttestationID,
				installedAt,
			)
		},
	); err != nil {
		t.Fatalf("writeRebootstrapInstallMarker(): %v", err)
	}
	marker, found, err := state.RebootstrapInstallMarker(t.Context())
	if err != nil || !found {
		t.Fatalf("RebootstrapInstallMarker() = (%+v, %t, %v)", marker, found, err)
	}
	return state, marker, cut.SignerDeviceID
}
