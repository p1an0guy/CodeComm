package reducer

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

func TestNewStateRejectsMalformedMembershipTopology(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, reducerFixture, *Snapshot)
	}{
		{
			name: "recovery key length",
			mutate: func(_ *testing.T, _ reducerFixture, snapshot *Snapshot) {
				snapshot.RecoveryPublicKey = []byte{1}
			},
		},
		{
			name: "missing audit counter",
			mutate: func(_ *testing.T, fixture reducerFixture, snapshot *Snapshot) {
				delete(snapshot.AuditCounters, fixture.targetDevice)
			},
		},
		{
			name: "inactive voter target",
			mutate: func(_ *testing.T, fixture reducerFixture, snapshot *Snapshot) {
				member := snapshot.Devices[fixture.ownerDevice]
				member.Status = device.StatusRequiresReadmission
				snapshot.Devices[fixture.ownerDevice] = member
			},
		},
		{
			name: "no active owner",
			mutate: func(t *testing.T, fixture reducerFixture, snapshot *Snapshot) {
				owner := snapshot.Devices[fixture.ownerDevice]
				owner.Role = device.RoleEditor
				snapshot.Devices[fixture.ownerDevice] = owner
				target, err := voterset.New(
					testSessionID,
					[]domain.DeviceID{fixture.editorDevice},
					2,
				)
				if err != nil {
					t.Fatalf("voterset.New() error = %v", err)
				}
				snapshot.VoterSet = target
			},
		},
		{
			name: "authority ahead of target",
			mutate: func(_ *testing.T, _ reducerFixture, snapshot *Snapshot) {
				snapshot.CredentialAuthority.VoterSetVersion = 2
			},
		},
		{
			name: "equal-version target mismatch",
			mutate: func(t *testing.T, fixture reducerFixture, snapshot *Snapshot) {
				target, err := voterset.New(
					testSessionID,
					[]domain.DeviceID{fixture.editorDevice},
					1,
				)
				if err != nil {
					t.Fatalf("voterset.New() error = %v", err)
				}
				snapshot.VoterSet = target
			},
		},
		{
			name: "noncanonical activation proof",
			mutate: func(t *testing.T, fixture reducerFixture, snapshot *Snapshot) {
				target, err := voterset.New(
					testSessionID,
					[]domain.DeviceID{fixture.ownerDevice},
					2,
				)
				if err != nil {
					t.Fatalf("voterset.New() error = %v", err)
				}
				signature := [ed25519.SignatureSize]byte{1}
				snapshot.VoterSet = target
				snapshot.CredentialAuthority =
					credentialauthority.Authority{
						SessionID:                   testSessionID,
						VoterDeviceIDs:              []domain.DeviceID{fixture.ownerDevice},
						VoterSetVersion:             2,
						ActivationSource:            credentialauthority.ActivationHandoff,
						ActivationCheckpointEventID: activationCheckpointEventID,
						ActivationProofs: []credentialauthority.ActivationProof{{
							VoterDeviceID: fixture.ownerDevice,
							CanonicalJSON: []byte(`{"z":1,"a":2}`),
						}},
						PriorAuthoritySigner:  fixture.ownerDevice,
						PriorAuthorityHandoff: &signature,
					}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			snapshot := snapshotFromState(fixture.state)
			test.mutate(t, fixture, &snapshot)
			if _, err := NewState(snapshot); !errors.Is(
				err,
				ErrInvalidCommittedState,
			) {
				t.Fatalf(
					"NewState() error = %v, want invalid committed state",
					err,
				)
			}
		})
	}
}

func TestNewStateRejectsCredentialAuthorityWithoutActiveMajority(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	ids := []domain.DeviceID{
		fixture.editorDevice,
		fixture.ownerDevice,
		fixture.targetDevice,
	}
	sortDeviceIDs(ids)
	target, err := voterset.New(
		testSessionID,
		[]domain.DeviceID{fixture.ownerDevice},
		2,
	)
	if err != nil {
		t.Fatalf("voterset.New() error = %v", err)
	}
	snapshot.VoterSet = target
	snapshot.CredentialAuthority = credentialauthority.Authority{
		SessionID:        testSessionID,
		VoterDeviceIDs:   ids,
		VoterSetVersion:  1,
		ActivationSource: credentialauthority.ActivationGenesis,
	}
	for _, id := range []domain.DeviceID{
		fixture.editorDevice,
		fixture.targetDevice,
	} {
		member := snapshot.Devices[id]
		member.Status = device.StatusRequiresReadmission
		snapshot.Devices[id] = member
	}
	if _, err := NewState(snapshot); !errors.Is(
		err,
		ErrInvalidCommittedState,
	) {
		t.Fatalf("NewState() error = %v, want invalid committed state", err)
	}
}

func TestStateApplyRejectsAdmissionWithoutCounterAtomically(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	member, _ := testDevice(t, 4, device.RoleEditor)
	beforeDevices := len(fixture.state.devices)
	err := fixture.state.Apply(Changes{Devices: []device.Device{member}})
	if !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("State.Apply() error = %v, want invalid committed state", err)
	}
	if len(fixture.state.devices) != beforeDevices {
		t.Fatal("failed admission apply mutated devices")
	}
	if _, exists := fixture.state.devices[member.ID]; exists {
		t.Fatal("failed admission apply retained new device")
	}
}

func TestStateApplyRejectsGenericVoterChangeDuringRevocationAtomically(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	replacement, _ := testDevice(t, 4, device.RoleEditor)
	fixture.state.devices[replacement.ID] = replacement
	fixture.state.auditCounters[replacement.ID] = auditcounter.Counter{
		DeviceID: replacement.ID,
	}

	currentIDs := []domain.DeviceID{
		fixture.editorDevice,
		fixture.ownerDevice,
		fixture.targetDevice,
	}
	sortDeviceIDs(currentIDs)
	currentTarget, err := voterset.New(testSessionID, currentIDs, 1)
	if err != nil {
		t.Fatalf("voterset.New(current) error = %v", err)
	}
	fixture.state.voterSet = currentTarget
	fixture.state.credentialAuthority = credentialauthority.Authority{
		SessionID:        testSessionID,
		VoterDeviceIDs:   append([]domain.DeviceID(nil), currentIDs...),
		VoterSetVersion:  1,
		ActivationSource: credentialauthority.ActivationGenesis,
	}

	revoked := fixture.state.devices[fixture.targetDevice]
	revoked.Status = device.StatusRevoked
	revoked.EntityVersion++
	replacementTargetIDs := []domain.DeviceID{
		fixture.editorDevice,
		fixture.ownerDevice,
		replacement.ID,
	}
	sortDeviceIDs(replacementTargetIDs)
	replacementTarget, err := voterset.New(
		testSessionID,
		replacementTargetIDs,
		2,
	)
	if err != nil {
		t.Fatalf("voterset.New(replacement) error = %v", err)
	}

	err = fixture.state.Apply(Changes{
		Devices:  []device.Device{revoked},
		VoterSet: []voterset.Set{replacementTarget},
	})
	if !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("State.Apply() error = %v, want invalid committed state", err)
	}
	if fixture.state.devices[fixture.targetDevice].Status != device.StatusActive ||
		!fixture.state.voterSet.SameTarget(currentTarget) {
		t.Fatal("failed revocation apply mutated committed membership")
	}
}
