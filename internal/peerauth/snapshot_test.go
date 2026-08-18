package peerauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const snapshotTestSessionID = domain.UUIDv7(
	"018f47de-89ab-7def-8123-0123456789ab",
)

func TestSnapshotDefensivelyCopiesAndBoundsCredentialHistory(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 3)
	snapshot, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}

	fixture.input.Devices[fixture.deviceID].IdentityPublicKey[0] ^= 0xff
	authorization := fixture.input.CredentialAuthorizations[credentialauthorization.Key{
		SessionID: snapshotTestSessionID,
		DeviceID:  fixture.deviceID,
		Epoch:     3,
	}]
	authorization.ClockEndorsements[0].Signature[0] = 1

	member, found := snapshot.Member(fixture.deviceID)
	if !found || !bytes.Equal(member.IdentityPublicKey, fixture.identityKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("Member() = (%+v, %t)", member, found)
	}
	member.IdentityPublicKey[0] ^= 0xff
	again, found := snapshot.Member(fixture.deviceID)
	if !found || bytes.Equal(member.IdentityPublicKey, again.IdentityPublicKey) {
		t.Fatal("mutating Member() result changed the snapshot")
	}

	for epoch, want := range map[uint64]bool{1: false, 2: true, 3: true} {
		_, found := snapshot.Authorization(credentialauthorization.Key{
			SessionID: snapshotTestSessionID,
			DeviceID:  fixture.deviceID,
			Epoch:     epoch,
		})
		if found != want {
			t.Errorf("Authorization(epoch %d) found = %t, want %t", epoch, found, want)
		}
	}

	next, err := snapshot.Advance(Changes{AdvancesEventChain: true})
	if err != nil {
		t.Fatalf("Advance() error = %v", err)
	}
	if index, valid := next.AppliedChainIndex(); !valid || index != 4 {
		t.Fatalf("AppliedChainIndex() = (%d, %t), want (4, true)", index, valid)
	}
	if index, _ := snapshot.AppliedChainIndex(); index != 3 {
		t.Fatalf("advancing successor mutated prior index to %d", index)
	}
}

func TestSnapshotAdvanceAppliesCredentialAndMembershipChanges(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 1)
	snapshot, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	secondKey := snapshotPrivateKey(22)
	second := snapshotAuthorization(
		fixture.deviceID,
		2,
		2,
		secondKey,
	)
	member := fixture.input.Devices[fixture.deviceID]
	member.Role = device.RoleEditor
	member.EntityVersion++
	next, err := snapshot.Advance(Changes{
		AdvancesEventChain: true,
		Devices:            []device.Device{member},
		AuditCounters: []auditcounter.Counter{{
			DeviceID:        fixture.deviceID,
			CredentialEpoch: 2,
		}},
		CredentialAuthorizations: []credentialauthorization.Authorization{
			second,
		},
	})
	if err != nil {
		t.Fatalf("Advance() error = %v", err)
	}
	gotMember, found := next.Member(fixture.deviceID)
	if !found || gotMember.Role != device.RoleEditor {
		t.Fatalf("Member() = (%+v, %t), want editor", gotMember, found)
	}
	if epoch, found := next.CurrentCredentialEpoch(fixture.deviceID); !found || epoch != 2 {
		t.Fatalf("CurrentCredentialEpoch() = (%d, %t), want (2, true)", epoch, found)
	}
	if _, found := next.Authorization(second.PrimaryKey()); !found {
		t.Fatal("successor authorization was not published")
	}
}

func TestSnapshotActiveCredentialAuthorizationAt(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 1)
	snapshot, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	authorization, found := snapshot.ActiveCredentialAuthorizationAt(
		fixture.deviceID,
		snapshotTestNow(),
	)
	if !found || authorization.Epoch != 1 {
		t.Fatalf(
			"ActiveCredentialAuthorizationAt() = (%+v, %t), want epoch 1",
			authorization,
			found,
		)
	}
	authorization.ClockEndorsements[0].Signature[0] ^= 0xff
	again, found := snapshot.ActiveCredentialAuthorizationAt(
		fixture.deviceID,
		snapshotTestNow(),
	)
	if !found || again.ClockEndorsements[0].Signature[0] != 0 {
		t.Fatal("mutating returned authorization changed snapshot state")
	}
}

func TestSnapshotUsesOverlapPredecessorUntilSuccessorActivates(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 2)
	successorKey := credentialauthorization.Key{
		SessionID: snapshotTestSessionID,
		DeviceID:  fixture.deviceID,
		Epoch:     2,
	}
	successor := fixture.input.CredentialAuthorizations[successorKey]
	successor.IssuedAt = domain.WholeSecondTimestamp(
		"2026-08-14T12:25:00Z",
	)
	successor.NotBefore = domain.WholeSecondTimestamp(
		"2026-08-14T12:28:00Z",
	)
	fixture.input.CredentialAuthorizations[successorKey] = successor
	snapshot, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}

	beforeActivation := time.Date(
		2026, 8, 14, 12, 27, 59, 0, time.UTC,
	)
	authorization, found := snapshot.ActiveCredentialAuthorizationAt(
		fixture.deviceID,
		beforeActivation,
	)
	if !found || authorization.Epoch != 1 {
		t.Fatalf(
			"authorization before successor activation = (%+v, %t), want epoch 1",
			authorization,
			found,
		)
	}
	atActivation := time.Date(2026, 8, 14, 12, 28, 0, 0, time.UTC)
	authorization, found = snapshot.ActiveCredentialAuthorizationAt(
		fixture.deviceID,
		atActivation,
	)
	if !found || authorization.Epoch != 2 {
		t.Fatalf(
			"authorization at successor activation = (%+v, %t), want epoch 2",
			authorization,
			found,
		)
	}
}

func TestSnapshotActiveCredentialAuthorizationAtFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		epoch  uint64
		at     time.Time
		mutate func(*snapshotFixture, *Snapshot)
	}{
		{
			name:  "zero epoch",
			epoch: 0,
			at:    snapshotTestNow(),
		},
		{
			name:  "absent member",
			epoch: 1,
			at:    snapshotTestNow(),
			mutate: func(fixture *snapshotFixture, _ *Snapshot) {
				fixture.deviceID = domain.DeviceID(
					"cc1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				)
			},
		},
		{
			name:  "inactive member",
			epoch: 1,
			at:    snapshotTestNow(),
			mutate: func(fixture *snapshotFixture, snapshot *Snapshot) {
				member := snapshot.devices[fixture.deviceID]
				member.Status = device.StatusRevoked
				snapshot.devices[fixture.deviceID] = member
			},
		},
		{
			name:  "before activation",
			epoch: 1,
			at: time.Date(
				2026, 8, 14, 11, 59, 59, 999_999_999, time.UTC,
			),
		},
		{
			name:  "at expiry",
			epoch: 1,
			at: time.Date(
				2026, 8, 14, 12, 30, 0, 0, time.UTC,
			),
		},
		{
			name:  "zero time",
			epoch: 1,
			at:    time.Time{},
		},
		{
			name:  "missing current row",
			epoch: 1,
			at:    snapshotTestNow(),
			mutate: func(fixture *snapshotFixture, snapshot *Snapshot) {
				delete(snapshot.authorizations, credentialauthorization.Key{
					SessionID: snapshotTestSessionID,
					DeviceID:  fixture.deviceID,
					Epoch:     1,
				})
			},
		},
		{
			name:  "corrupt current row",
			epoch: 1,
			at:    snapshotTestNow(),
			mutate: func(fixture *snapshotFixture, snapshot *Snapshot) {
				key := credentialauthorization.Key{
					SessionID: snapshotTestSessionID,
					DeviceID:  fixture.deviceID,
					Epoch:     1,
				}
				authorization := snapshot.authorizations[key]
				authorization.KeyDigest[0] ^= 0xff
				snapshot.authorizations[key] = authorization
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSnapshotFixture(t, test.epoch)
			snapshot, err := NewSnapshot(fixture.input)
			if err != nil {
				t.Fatalf("NewSnapshot() error = %v", err)
			}
			if test.mutate != nil {
				test.mutate(&fixture, snapshot)
			}
			if authorization, found :=
				snapshot.ActiveCredentialAuthorizationAt(
					fixture.deviceID,
					test.at,
				); found {
				t.Fatalf(
					"ActiveCredentialAuthorizationAt() = (%+v, true), want false",
					authorization,
				)
			}
		})
	}
}

func TestSnapshotRejectsInconsistentOrUnappliedState(t *testing.T) {
	t.Parallel()

	fixture := newSnapshotFixture(t, 1)
	currentKey := credentialauthorization.Key{
		SessionID: snapshotTestSessionID,
		DeviceID:  fixture.deviceID,
		Epoch:     1,
	}
	future := fixture.input
	future.CredentialAuthorizations[currentKey] =
		future.CredentialAuthorizations[currentKey].Clone()
	value := future.CredentialAuthorizations[currentKey]
	value.AuthorizationChainIndex = future.AppliedChainIndex + 1
	future.CredentialAuthorizations[currentKey] = value
	if _, err := NewSnapshot(future); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("NewSnapshot(future authorization) error = %v", err)
	}

	fixture = newSnapshotFixture(t, 1)
	missingCounter := fixture.input
	missingCounter.AuditCounters = map[domain.DeviceID]auditcounter.Counter{}
	if _, err := NewSnapshot(missingCounter); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("NewSnapshot(missing counter) error = %v", err)
	}

	fixture = newSnapshotFixture(t, 1)
	snapshot, err := NewSnapshot(fixture.input)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	member := fixture.input.Devices[fixture.deviceID]
	if _, err := snapshot.Advance(Changes{
		AdvancesEventChain: true,
		Devices:            []device.Device{member, member},
	}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("Advance(duplicate member) error = %v", err)
	}
	if _, err := snapshot.Advance(Changes{
		Devices: []device.Device{member},
	}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("Advance(change without chain advance) error = %v", err)
	}
}

type snapshotFixture struct {
	input       SnapshotInput
	deviceID    domain.DeviceID
	identityKey ed25519.PrivateKey
}

func newSnapshotFixture(t *testing.T, currentEpoch uint64) snapshotFixture {
	t.Helper()
	identityKey := snapshotPrivateKey(11)
	deviceID, err := device.DeriveID(identityKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("device.DeriveID() error = %v", err)
	}
	member := device.Device{
		ID:                deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: bytes.Clone(identityKey.Public().(ed25519.PublicKey)),
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	authorizations := make(
		map[credentialauthorization.Key]credentialauthorization.Authorization,
		currentEpoch,
	)
	for epoch := uint64(1); epoch <= currentEpoch; epoch++ {
		authorization := snapshotAuthorization(
			deviceID,
			epoch,
			epoch,
			snapshotPrivateKey(byte(20+epoch)),
		)
		authorizations[authorization.PrimaryKey()] = authorization
	}
	return snapshotFixture{
		input: SnapshotInput{
			SessionID:          snapshotTestSessionID,
			RecoveryGeneration: 4,
			AppliedChainIndex:  currentEpoch,
			Devices: map[domain.DeviceID]device.Device{
				deviceID: member,
			},
			AuditCounters: map[domain.DeviceID]auditcounter.Counter{
				deviceID: {
					DeviceID:        deviceID,
					CredentialEpoch: currentEpoch,
				},
			},
			CredentialAuthorizations: authorizations,
		},
		deviceID:    deviceID,
		identityKey: identityKey,
	}
}

func snapshotAuthorization(
	deviceID domain.DeviceID,
	epoch uint64,
	chainIndex uint64,
	epochKey ed25519.PrivateKey,
) credentialauthorization.Authorization {
	publicKey := epochKey.Public().(ed25519.PublicKey)
	authorization := credentialauthorization.Authorization{
		SessionID:                snapshotTestSessionID,
		DeviceID:                 deviceID,
		Epoch:                    epoch,
		Role:                     credentialauthorization.RoleOwner,
		IssuedAt:                 domain.WholeSecondTimestamp("2026-08-14T12:00:00Z"),
		NotBefore:                domain.WholeSecondTimestamp("2026-08-14T12:00:00Z"),
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{{
			DeviceID: deviceID,
		}},
		AuthorizationChainIndex: chainIndex,
	}
	copy(authorization.EpochPublicKey[:], publicKey)
	authorization.KeyDigest = sha256.Sum256(publicKey)
	return authorization
}

func snapshotPrivateKey(value byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, ed25519.SeedSize))
}

func snapshotTestNow() time.Time {
	return time.Date(2026, 8, 14, 12, 5, 0, 0, time.UTC)
}
