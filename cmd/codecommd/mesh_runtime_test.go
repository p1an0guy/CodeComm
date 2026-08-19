package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestInspectDaemonMeshStateRejectsIdentityKeyMismatch(t *testing.T) {
	statePath, identityPrivateKey, deviceID := initializeDaemonMeshTestState(
		t,
		nil,
	)
	wrongPrivateKey := ed25519.NewKeyFromSeed(
		make([]byte, ed25519.SeedSize),
	)

	_, err := inspectDaemonMeshState(
		context.Background(),
		daemonMeshTestOptions(statePath),
		deviceID,
		wrongPrivateKey.Public().(ed25519.PublicKey),
	)
	if !errors.Is(err, errDaemonIdentityMismatch) {
		t.Fatalf(
			"inspectDaemonMeshState(identity mismatch) error = %v, want %v",
			err,
			errDaemonIdentityMismatch,
		)
	}
	clear(identityPrivateKey)
}

func TestInspectDaemonMeshStateRejectsInactiveLocalIdentity(t *testing.T) {
	for _, status := range []device.Status{
		device.StatusRequiresReadmission,
		device.StatusRevoked,
	} {
		t.Run(string(status), func(t *testing.T) {
			statePath, identityPrivateKey, deviceID :=
				initializeDaemonMeshTestState(
					t,
					func(initial *store.InitialState) {
						initial.Projections.Devices[0].Status = status
					},
				)
			t.Cleanup(func() { clear(identityPrivateKey) })

			_, err := inspectDaemonMeshState(
				context.Background(),
				daemonMeshTestOptions(statePath),
				deviceID,
				identityPrivateKey.Public().(ed25519.PublicKey),
			)
			if !errors.Is(err, errDaemonIdentityMismatch) {
				t.Fatalf(
					"inspectDaemonMeshState(%s) error = %v, want %v",
					status,
					err,
					errDaemonIdentityMismatch,
				)
			}
		})
	}
}

func TestInspectDaemonMeshStateDerivesInterruptedBootstrapVotersOnlyBeforeRaftProgress(
	t *testing.T,
) {
	tests := []struct {
		name                  string
		storeConfiguration    bool
		applyRaftEntry        bool
		wantBootstrapVoterIDs bool
	}{
		{
			name:                  "no committed configuration or applied entry",
			wantBootstrapVoterIDs: true,
		},
		{
			name:               "committed configuration",
			storeConfiguration: true,
		},
		{
			name:           "applied Raft entry",
			applyRaftEntry: true,
		},
		{
			name:               "committed configuration and applied Raft entry",
			storeConfiguration: true,
			applyRaftEntry:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statePath, identityPrivateKey, deviceID :=
				initializeDaemonMeshTestState(t, nil)
			t.Cleanup(func() { clear(identityPrivateKey) })
			database := openDaemonMeshTestStore(t, statePath)
			if test.storeConfiguration {
				storeDaemonMeshTestConfiguration(t, database, deviceID)
			}
			if test.applyRaftEntry {
				applyDaemonMeshTestEntry(
					t,
					database,
					identityPrivateKey,
					deviceID,
				)
			}
			if err := database.Close(); err != nil {
				t.Fatalf("Close(): %v", err)
			}

			preflight, err := inspectDaemonMeshState(
				context.Background(),
				daemonMeshTestOptions(statePath),
				deviceID,
				identityPrivateKey.Public().(ed25519.PublicKey),
			)
			if err != nil {
				t.Fatalf("inspectDaemonMeshState(): %v", err)
			}
			if test.wantBootstrapVoterIDs {
				if len(preflight.bootstrapVoterIDs) != 1 ||
					preflight.bootstrapVoterIDs[0] != deviceID {
					t.Fatalf(
						"bootstrap voters = %v, want [%s]",
						preflight.bootstrapVoterIDs,
						deviceID,
					)
				}
			} else if len(preflight.bootstrapVoterIDs) != 0 {
				t.Fatalf(
					"bootstrap voters = %v, want none",
					preflight.bootstrapVoterIDs,
				)
			}
		})
	}
}

func TestInspectDaemonMeshStateReopensMatureNonvoterWithoutBootstrap(
	t *testing.T,
) {
	var peerID domain.DeviceID
	statePath, identityPrivateKey, deviceID :=
		initializeDaemonMeshTestState(
			t,
			func(initial *store.InitialState) {
				peerPrivateKey := ed25519.NewKeyFromSeed(
					[]byte("22222222222222222222222222222222"),
				)
				peerPublicKey := peerPrivateKey.Public().(ed25519.PublicKey)
				var err error
				peerID, err = device.DeriveID(peerPublicKey)
				if err != nil {
					t.Fatalf("device.DeriveID(peer): %v", err)
				}
				initial.Projections.Devices = append(
					initial.Projections.Devices,
					device.Device{
						ID:                peerID,
						Role:              device.RoleEditor,
						IdentityPublicKey: peerPublicKey,
						DaemonVersion:     "0.1.0",
						MaxApplyLevel:     1,
						Status:            device.StatusActive,
						EntityVersion:     1,
					},
				)
				initial.Projections.AuditCounters = append(
					initial.Projections.AuditCounters,
					auditcounter.Counter{DeviceID: peerID},
				)
				target, err := voterset.New(
					daemonTestSessionID,
					[]domain.DeviceID{peerID},
					1,
				)
				if err != nil {
					t.Fatalf("voterset.New(peer): %v", err)
				}
				initial.Projections.VoterSet = []voterset.Set{target}
				initial.Projections.CredentialAuthority =
					[]store.CredentialAuthorityRow{{
						SessionID:        daemonTestSessionID,
						VoterDeviceIDs:   []domain.DeviceID{peerID},
						VoterSetVersion:  1,
						ActivationSource: credentialauthority.ActivationGenesis,
					}}
			},
		)
	t.Cleanup(func() { clear(identityPrivateKey) })
	if peerID == deviceID {
		t.Fatal("nonvoter fixture peer unexpectedly matches local device")
	}
	database := openDaemonMeshTestStore(t, statePath)
	applyDaemonMeshTestEntry(t, database, identityPrivateKey, deviceID)
	if err := database.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	preflight, err := inspectDaemonMeshState(
		context.Background(),
		daemonMeshTestOptions(statePath),
		deviceID,
		identityPrivateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("inspectDaemonMeshState(): %v", err)
	}
	if len(preflight.bootstrapVoterIDs) != 0 {
		t.Fatalf(
			"mature nonvoter bootstrap voters = %v, want none",
			preflight.bootstrapVoterIDs,
		)
	}
}

func TestOpenDaemonPeerListenersClosesEarlierListenersAfterBindFailure(
	t *testing.T,
) {
	bindErr := errors.New("bind failed")
	first := &daemonMeshTestListener{}
	second := &daemonMeshTestListener{}
	endpoints := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:41001"),
		netip.MustParseAddrPort("192.0.2.2:41002"),
		netip.MustParseAddrPort("192.0.2.3:41003"),
	}
	call := 0
	_, err := openDaemonPeerListeners(
		context.Background(),
		endpoints,
		func(
			_ context.Context,
			got netip.AddrPort,
		) (net.Listener, error) {
			if got != endpoints[call] {
				t.Fatalf(
					"listen endpoint[%d] = %s, want %s",
					call,
					got,
					endpoints[call],
				)
			}
			call++
			switch call {
			case 1:
				return first, nil
			case 2:
				return second, nil
			default:
				return nil, bindErr
			}
		},
	)
	if !errors.Is(err, errDaemonMeshConstruction) ||
		!strings.Contains(err.Error(), bindErr.Error()) {
		t.Fatalf(
			"openDaemonPeerListeners() error = %v, want construction error containing %q",
			err,
			bindErr,
		)
	}
	if call != len(endpoints) {
		t.Fatalf("listen calls = %d, want %d", call, len(endpoints))
	}
	if first.closeCalls != 1 || second.closeCalls != 1 {
		t.Fatalf(
			"listener close calls = (%d, %d), want (1, 1)",
			first.closeCalls,
			second.closeCalls,
		)
	}
}

func initializeDaemonMeshTestState(
	t *testing.T,
	mutate func(*store.InitialState),
) (string, ed25519.PrivateKey, domain.DeviceID) {
	t.Helper()
	initial, identityPrivateKey, deviceID := daemonTestInitialState(t)
	if mutate != nil {
		mutate(&initial)
	}
	statePath := filepath.Join(t.TempDir(), "state", "state.db")
	database := openDaemonMeshTestStore(t, statePath)
	if _, err := database.Initialize(context.Background(), initial); err != nil {
		_ = database.Close()
		t.Fatalf("Initialize(): %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close(initialized store): %v", err)
	}
	return statePath, identityPrivateKey, deviceID
}

func openDaemonMeshTestStore(t *testing.T, statePath string) *store.Store {
	t.Helper()
	database, err := store.Open(
		context.Background(),
		store.Options{Path: statePath},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	return database
}

func daemonMeshTestOptions(statePath string) daemonOptions {
	return daemonOptions{
		statePath:   statePath,
		sessionID:   daemonTestSessionID,
		workspaceID: daemonTestWorkspaceID,
	}
}

func storeDaemonMeshTestConfiguration(
	t *testing.T,
	database *store.Store,
	deviceID domain.DeviceID,
) {
	t.Helper()
	configuration := []byte(fmt.Sprintf(
		`{"servers":[{"address":%q,"id":%q,"suffrage":"voter"}]}`,
		deviceID,
		deviceID,
	))
	stored, err := database.StoreCommittedRaftConfiguration(
		context.Background(),
		1,
		configuration,
	)
	if err != nil || !stored {
		t.Fatalf(
			"StoreCommittedRaftConfiguration() = (%t, %v)",
			stored,
			err,
		)
	}
}

func applyDaemonMeshTestEntry(
	t *testing.T,
	database *store.Store,
	identityPrivateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
) {
	t.Helper()
	_, err := database.Apply(context.Background(), store.ApplyRequest{
		Term:               1,
		LogIndex:           1,
		AppliedAt:          daemonTestTimestamp,
		RecoveryGeneration: 0,
		Proposal: daemonTestTaskEvent(
			t,
			identityPrivateKey,
			deviceID,
		),
		Outcome: store.CommandOutcome{
			Status: store.OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		},
	})
	if err != nil {
		t.Fatalf("Apply(): %v", err)
	}
}

type daemonMeshTestListener struct {
	closeCalls int
}

func (*daemonMeshTestListener) Accept() (net.Conn, error) {
	return nil, errors.New("unexpected Accept")
}

func (listener *daemonMeshTestListener) Close() error {
	listener.closeCalls++
	return nil
}

func (*daemonMeshTestListener) Addr() net.Addr {
	return daemonMeshTestAddr("daemon-mesh-test")
}

type daemonMeshTestAddr string

func (daemonMeshTestAddr) Network() string {
	return "test"
}

func (address daemonMeshTestAddr) String() string {
	return string(address)
}

var _ net.Listener = (*daemonMeshTestListener)(nil)
var _ net.Addr = daemonMeshTestAddr("")
