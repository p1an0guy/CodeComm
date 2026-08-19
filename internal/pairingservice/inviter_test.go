package pairingservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestInviterCreateListAndRevoke(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	inviter := newTestInviter(
		t,
		fixture,
		serviceTestUUID(720),
		fixture.secrets,
	)
	issued, err := inviter.Create(
		context.Background(),
		CreateInviteRequest{
			Mode: pairing.ModeNew, Role: device.RoleEditor,
			InitialCredentialEpoch: 1,
		},
	)
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}
	parsed, err := pairing.ParseInviteCode(issued.Invite.Code())
	if err != nil || parsed.Digest() != issued.Invite.Digest() ||
		issued.Record.State != store.PairingInviteOutstanding {
		t.Fatalf("issued invite = (%+v, %v)", issued.Record, err)
	}
	value := issued.Invite.Invite()
	reference, err := credentialstore.InviteReference(
		value.SessionID,
		value.InviteID,
	)
	clear(value.Secret[:])
	if err != nil || !fixture.secrets.contains(reference) {
		t.Fatalf("native secret = (%v, %v), want present", reference, err)
	}
	records, err := inviter.List(context.Background())
	if err != nil || len(records) != 2 ||
		records[1].InviteID != issued.Record.InviteID {
		t.Fatalf("List() = (%+v, %v)", records, err)
	}
	revoked, duplicate, err := inviter.Revoke(
		context.Background(),
		issued.Record.InviteID,
	)
	if err != nil || duplicate ||
		revoked.State != store.PairingInviteRevoked {
		t.Fatalf("Revoke() = (%+v, %t, %v)", revoked, duplicate, err)
	}
	again, duplicate, err := inviter.Revoke(
		context.Background(),
		issued.Record.InviteID,
	)
	if err != nil || !duplicate || again.State != store.PairingInviteRevoked {
		t.Fatalf("Revoke(retry) = (%+v, %t, %v)", again, duplicate, err)
	}
	records, err = inviter.List(context.Background())
	if err != nil || len(records) != 1 ||
		records[0].InviteID == issued.Record.InviteID {
		t.Fatalf("List(after revoke) = (%+v, %v)", records, err)
	}
	if err := fixture.service.drainSecretCleanup(context.Background()); err != nil {
		t.Fatalf("drainSecretCleanup(): %v", err)
	}
	if fixture.secrets.contains(reference) {
		t.Fatal("revoked invite secret remains in native store")
	}
}

func TestInviterAbandonsReservationWhenSecretCreateFails(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	fixture.secrets.setCreateError(credentialstore.ErrLocked)
	inviteID := serviceTestUUID(721)
	inviter := newTestInviter(t, fixture, inviteID, fixture.secrets)
	if _, err := inviter.Create(
		context.Background(),
		CreateInviteRequest{
			Mode: pairing.ModeNew, Role: device.RoleEditor,
			InitialCredentialEpoch: 1,
		},
	); !errors.Is(err, ErrInviteIssuance) {
		t.Fatalf("Create() error = %v, want %v", err, ErrInviteIssuance)
	}
	record, found, err := fixture.state.PairingInvite(
		context.Background(),
		inviteID,
	)
	if err != nil || !found || record.State != store.PairingInviteAbandoned {
		t.Fatalf("abandoned record = (%+v, %t, %v)", record, found, err)
	}
	reference, err := credentialstore.InviteReference(
		serviceTestSessionID,
		inviteID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.secrets.contains(reference) {
		t.Fatal("failed invite left a native secret")
	}
}

func TestInviterRejectsNoncanonicalEndpointsAndModes(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	genesisDigest, err := chain.GenesisDigest([]byte(serviceTestGenesis))
	if err != nil {
		t.Fatal(err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], genesisDigest[:])
	key := testPrivateKey(1)
	value := fixture.invite.Invite()
	defer clear(value.Secret[:])
	if _, err := NewInviter(InviterOptions{
		State: fixture.state, Secrets: fixture.secrets,
		SessionID: serviceTestSessionID, WorkspaceID: serviceTestWorkspaceID,
		IssuerDeviceID:      value.InviterDeviceID,
		IdentityPublicKey:   value.InviterIdentityPublicKey[:],
		SignedGenesisDigest: digest,
		Endpoints: []pairing.Endpoint{
			{IP: netip.MustParseAddr("192.0.2.20"), Port: 47831},
			{IP: netip.MustParseAddr("192.0.2.10"), Port: 47831},
		},
		Sign: func(invite pairing.Invite) (pairing.SignedInvite, error) {
			return pairing.SignInvite(invite, key)
		},
	}); !errors.Is(err, ErrInvalidInviter) {
		t.Fatalf("NewInviter(unsorted endpoints) error = %v", err)
	}
	inviter := newTestInviter(
		t,
		fixture,
		serviceTestUUID(722),
		fixture.secrets,
	)
	subject := value.InviterDeviceID
	if _, err := inviter.Create(
		context.Background(),
		CreateInviteRequest{
			Mode: pairing.ModeNew, SubjectDeviceID: &subject,
			Role: device.RoleEditor, InitialCredentialEpoch: 1,
		},
	); !errors.Is(err, ErrInvalidInviter) {
		t.Fatalf("Create(invalid new mode) error = %v", err)
	}
}

func newTestInviter(
	t *testing.T,
	fixture serviceFixture,
	inviteID domain.UUIDv7,
	secrets InviteSecretStore,
) *Inviter {
	t.Helper()
	genesisDigest, err := chain.GenesisDigest([]byte(serviceTestGenesis))
	if err != nil {
		t.Fatal(err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], genesisDigest[:])
	key := testPrivateKey(1)
	value := fixture.invite.Invite()
	defer clear(value.Secret[:])
	inviter, err := NewInviter(InviterOptions{
		State: fixture.state, Secrets: secrets,
		SessionID: serviceTestSessionID, WorkspaceID: serviceTestWorkspaceID,
		RecoveryGeneration: 0, IssuerDeviceID: value.InviterDeviceID,
		IdentityPublicKey:   value.InviterIdentityPublicKey[:],
		SignedGenesisDigest: digest,
		Endpoints: []pairing.Endpoint{{
			IP: netip.MustParseAddr("192.0.2.10"), Port: 47831,
		}},
		Sign: func(invite pairing.Invite) (pairing.SignedInvite, error) {
			return pairing.SignInvite(invite, key)
		},
		Clock: func() time.Time {
			return time.Date(2026, 8, 13, 12, 1, 0, 0, time.UTC)
		},
		GenerateID: func() (domain.UUIDv7, error) {
			return inviteID, nil
		},
	})
	if err != nil {
		t.Fatalf("NewInviter(): %v", err)
	}
	return inviter
}
