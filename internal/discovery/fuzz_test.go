package discovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net/netip"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func FuzzParseAdvertisement(f *testing.F) {
	publicKey, _, valid := fuzzAdvertisementFixture(f, 31)
	for _, seed := range [][]byte{
		valid,
		nil,
		[]byte(`{}`),
		[]byte(`{"magic":"codecomm","protocol":1}`),
		bytes.Repeat([]byte{'x'}, MaxDatagramBytes+1),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		original := bytes.Clone(input)
		unverified, err := ParseAdvertisement(input, testSessionID)
		if !bytes.Equal(input, original) {
			t.Fatal("ParseAdvertisement() mutated its input")
		}
		if err != nil {
			return
		}
		if len(input) == 0 || len(input) > MaxDatagramBytes {
			t.Fatalf("accepted invalid input length %d", len(input))
		}
		verified, err := unverified.Verify(publicKey)
		if err != nil {
			return
		}
		if !bytes.Equal(verified.CanonicalBytes(), input) {
			t.Fatal("verified advertisement changed canonical bytes")
		}
	})
}

func FuzzParseEndpointSet(f *testing.F) {
	_, privateKey, member := fuzzIdentityFixture(f, 32)
	valid, err := signEndpointSet(
		validEndpointSet(member.ID),
		privateKey,
		endpointTestInterval,
	)
	if err != nil {
		f.Fatalf("signEndpointSet() error = %v", err)
	}
	for _, seed := range [][]byte{
		valid,
		nil,
		[]byte(`{}`),
		[]byte(`{"schema_version":1}`),
		bytes.Repeat([]byte{'x'}, MaxEndpointSetBytes+1),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		original := bytes.Clone(input)
		unverified, err := ParseEndpointSet(input)
		if !bytes.Equal(input, original) {
			t.Fatal("ParseEndpointSet() mutated its input")
		}
		if err != nil {
			return
		}
		if len(input) == 0 || len(input) > MaxEndpointSetBytes {
			t.Fatalf("accepted invalid input length %d", len(input))
		}
		verified, err := unverified.Verify(endpointExpectation(member))
		if err != nil {
			return
		}
		if !bytes.Equal(verified.CanonicalBytes(), input) {
			t.Fatal("verified endpoint set changed canonical bytes")
		}
	})
}

func FuzzReceiverRejectsHostileDatagrams(f *testing.F) {
	publicKey, _, valid := fuzzAdvertisementFixture(f, 33)
	_, _, member := fuzzIdentityFixture(f, 33)
	record := CredentialRecord{
		DeviceID:       member.ID,
		Epoch:          1,
		PublicKey:      publicKey,
		NotBefore:      "2026-08-13T11:30:00Z",
		NotAfter:       "2026-08-13T12:00:30Z",
		MemberActive:   true,
		LatestRetained: true,
	}
	f.Add(valid, []byte{192, 0, 2, 1}, uint16(50000))
	f.Add([]byte(`{}`), []byte{0, 0, 0, 0}, uint16(0))

	f.Fuzz(func(
		t *testing.T,
		input []byte,
		sourceBytes []byte,
		port uint16,
	) {
		receiver := testReceiver(t, endpointTestNow, func(
			_ context.Context,
			_ domain.UUIDv7,
			_ uint64,
			_ [sha256.Size]byte,
		) (CredentialRecord, bool, error) {
			return record, true, nil
		})
		var addressBytes [4]byte
		copy(addressBytes[:], sourceBytes)
		address := netip.AddrFrom4(addressBytes)
		_, _ = receiver.Accept(
			context.Background(),
			input,
			netip.AddrPortFrom(address, port),
		)
		stats := receiver.Stats()
		if stats.TrackedSources > TrackedSourcesMax ||
			stats.CachedNonces > NonceCacheEntries ||
			stats.AccountedBytes > DiscoveryStateMaxBytes {
			t.Fatalf("receiver exceeded bounds: %#v", stats)
		}
	})
}

func fuzzAdvertisementFixture(
	tb testing.TB,
	fill byte,
) (ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	tb.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{fill}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	value, err := newAdvertisement(
		testSessionID,
		DefaultMulticastPort,
		1,
		sha256.Sum256(publicKey),
		"2026-08-13T12:00:20Z",
		bytes.NewReader(bytes.Repeat(
			[]byte{fill},
			AdvertisementNonceSize,
		)),
	)
	if err != nil {
		tb.Fatalf("newAdvertisement() error = %v", err)
	}
	encoded, err := SignAdvertisement(value, privateKey)
	if err != nil {
		tb.Fatalf("SignAdvertisement() error = %v", err)
	}
	return publicKey, privateKey, encoded
}

func fuzzIdentityFixture(
	tb testing.TB,
	fill byte,
) (ed25519.PublicKey, ed25519.PrivateKey, device.Device) {
	tb.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{fill}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		tb.Fatalf("device.DeriveID() error = %v", err)
	}
	return publicKey, privateKey, device.Device{
		ID:                deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: bytes.Clone(publicKey),
		DaemonVersion:     "1.0.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
}
