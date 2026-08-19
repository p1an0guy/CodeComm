package pairingservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestAdmissionAuthorizerCloseClearsOwnedKeyIdempotently(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x91}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	bootID := serviceTestUUID(991)
	authority, err := event.NewLocalAuthority(deviceID, bootID)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := authority.OperatorBinding()
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewAdmissionAuthorizer(AdmissionAuthorizerOptions{
		DeviceID:           deviceID,
		OriginBootID:       bootID,
		IdentityPrivateKey: privateKey,
		OperatorOrigin:     operator,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownedKey := authorizer.privateKey
	wantOwnedKey := bytes.Clone(ownedKey)
	clear(privateKey)
	if !bytes.Equal(ownedKey, wantOwnedKey) {
		t.Fatal("authorizer private key aliases caller-owned key")
	}

	const closers = 16
	var wait sync.WaitGroup
	errorsSeen := make(chan error, closers)
	for range closers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- authorizer.Close()
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	if authorizer.privateKey != nil {
		t.Fatal("Close() retained the private-key slice")
	}
	if !bytes.Equal(ownedKey, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("Close() did not clear the owned private-key bytes")
	}
	if _, err := authorizer.PreparePairing(
		context.Background(),
		AttemptDetails{},
		domain.Timestamp("2026-08-13T12:01:01Z"),
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("PreparePairing() after Close error = %v, want %v", err, ErrClosed)
	}
}

func TestAdmissionReservationCannotSignAfterAuthorizerClose(t *testing.T) {
	ownerKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x92}, ed25519.SeedSize),
	)
	ownerID, err := device.DeriveID(ownerKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	details, authorization, authorizer := finalizerAdmissionAuthorization(
		t,
		ownerKey,
		ownerID,
		serviceTestUUID(992),
	)
	if authorization.Admission == nil {
		t.Fatal("authorization omitted admission reservation")
	}
	if err := authorizer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := authorization.Admission.Build(serviceTestUUID(998), 1); !errors.Is(
		err,
		ErrClosed,
	) {
		t.Fatalf("Build() after Close error = %v, want %v", err, ErrClosed)
	}
	if _, err := authorizer.PreparePairing(
		context.Background(),
		details,
		domain.Timestamp("2026-08-13T12:01:02Z"),
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("PreparePairing() after Close error = %v, want %v", err, ErrClosed)
	}
}

func TestPairingServiceCloseClearsAdmissionAuthorizer(t *testing.T) {
	fixture := newServiceFixture(t)
	ownedKey := fixture.authorizer.privateKey
	if err := fixture.service.Close(); err != nil {
		t.Fatal(err)
	}
	if fixture.authorizer.privateKey != nil ||
		!bytes.Equal(ownedKey, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("service Close() did not clear its admission authorizer")
	}
	if err := fixture.service.Close(); err != nil {
		t.Fatalf("second service Close() error = %v", err)
	}
}
