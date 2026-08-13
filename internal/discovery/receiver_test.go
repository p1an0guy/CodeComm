package discovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestReceiverAcceptsCurrentAndRetainedExpiredSigner(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := advertisementKey(t, 7)
	deviceID := domain.DeviceID(
		"cc1" + fmt.Sprintf("%064x", 7),
	)
	currentRecord := CredentialRecord{
		DeviceID:       deviceID,
		Epoch:          4,
		PublicKey:      publicKey,
		NotBefore:      "2026-08-13T11:30:00Z",
		NotAfter:       "2026-08-13T12:00:30Z",
		MemberActive:   true,
		LatestRetained: true,
	}
	record := currentRecord
	resolverCalls := 0
	receiver := testReceiver(t, now, func(
		_ context.Context,
		sessionID domain.UUIDv7,
		epoch uint64,
		digest [sha256.Size]byte,
	) (CredentialRecord, bool, error) {
		resolverCalls++
		if sessionID != testSessionID ||
			epoch != record.Epoch ||
			digest != sha256.Sum256(record.PublicKey) {
			return CredentialRecord{}, false, nil
		}
		return record, true, nil
	})
	source := netip.MustParseAddrPort("192.0.2.8:60123")

	encoded := signedReceiverAdvertisement(
		t,
		publicKey,
		privateKey,
		record.Epoch,
		1,
		domain.Timestamp(now.Add(20*time.Second).Format(time.RFC3339Nano)),
	)
	hint, err := receiver.Accept(context.Background(), encoded, source)
	if err != nil {
		t.Fatalf("Accept(current) error = %v", err)
	}
	if hint.ExpectedDeviceID != deviceID ||
		hint.Destination != netip.MustParseAddrPort("192.0.2.8:47831") ||
		!hint.SignerCurrentlyAuthorized {
		t.Fatalf("current hint = %#v", hint)
	}

	record.NotAfter = "2026-08-13T11:59:59Z"
	encoded = signedReceiverAdvertisement(
		t,
		publicKey,
		privateKey,
		record.Epoch,
		2,
		domain.Timestamp(now.Add(20*time.Second).Format(time.RFC3339Nano)),
	)
	hint, err = receiver.Accept(context.Background(), encoded, source)
	if err != nil {
		t.Fatalf("Accept(expired retained) error = %v", err)
	}
	if hint.SignerCurrentlyAuthorized {
		t.Fatalf("expired hint = %#v, want hint-only signer", hint)
	}
	if resolverCalls != 2 {
		t.Fatalf("resolver calls = %d, want 2", resolverCalls)
	}

	record.LatestRetained = false
	encoded = signedReceiverAdvertisement(
		t,
		publicKey,
		privateKey,
		record.Epoch,
		3,
		domain.Timestamp(now.Add(20*time.Second).Format(time.RFC3339Nano)),
	)
	if _, err := receiver.Accept(
		context.Background(),
		encoded,
		source,
	); !errors.Is(err, ErrCredentialInactive) {
		t.Fatalf("Accept(expired unretained) error = %v, want %v", err, ErrCredentialInactive)
	}
}

func TestReceiverCachesNonceBeforeCredentialAndSignatureWork(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := advertisementKey(t, 8)
	calls := 0
	receiver := testReceiver(t, now, func(
		context.Context,
		domain.UUIDv7,
		uint64,
		[sha256.Size]byte,
	) (CredentialRecord, bool, error) {
		calls++
		return CredentialRecord{}, false, nil
	})
	encoded := signedReceiverAdvertisement(
		t,
		publicKey,
		privateKey,
		1,
		1,
		"2026-08-13T12:00:20Z",
	)
	source := netip.MustParseAddrPort("192.0.2.10:50000")
	if _, err := receiver.Accept(
		context.Background(),
		encoded,
		source,
	); !errors.Is(err, ErrCredentialUnknown) {
		t.Fatalf("first Accept() error = %v, want %v", err, ErrCredentialUnknown)
	}
	if _, err := receiver.Accept(
		context.Background(),
		encoded,
		source,
	); !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("second Accept() error = %v, want %v", err, ErrNonceReplay)
	}
	if calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", calls)
	}
}

func TestReceiverSiblingSessionAllocatesNothing(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := advertisementKey(t, 9)
	calls := 0
	receiver := testReceiver(t, now, func(
		context.Context,
		domain.UUIDv7,
		uint64,
		[sha256.Size]byte,
	) (CredentialRecord, bool, error) {
		calls++
		return CredentialRecord{}, false, nil
	})
	otherSession := domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000002",
	)
	value, err := newAdvertisement(
		otherSession,
		47831,
		1,
		sha256.Sum256(publicKey),
		"2026-08-13T12:00:20Z",
		bytes.NewReader(bytes.Repeat([]byte{1}, AdvertisementNonceSize)),
	)
	if err != nil {
		t.Fatalf("newAdvertisement() error = %v", err)
	}
	encoded, err := SignAdvertisement(value, privateKey)
	if err != nil {
		t.Fatalf("SignAdvertisement() error = %v", err)
	}
	if _, err := receiver.Accept(
		context.Background(),
		encoded,
		netip.MustParseAddrPort("192.0.2.11:50000"),
	); !errors.Is(err, ErrSessionMismatch) {
		t.Fatalf("Accept() error = %v, want %v", err, ErrSessionMismatch)
	}
	if stats := receiver.Stats(); stats != (ReceiverStats{}) {
		t.Fatalf("Stats() = %#v, want zero", stats)
	}
	if calls != 0 {
		t.Fatalf("resolver calls = %d, want 0", calls)
	}
}

func TestReceiverChargesMalformedAndExpiredDatagramsBeforeExpensiveWork(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	receiver, err := newReceiver(receiverOptions{
		sessionID: testSessionID,
		resolve: func(
			context.Context,
			domain.UUIDv7,
			uint64,
			[sha256.Size]byte,
		) (CredentialRecord, bool, error) {
			t.Fatal("malformed input reached credential resolution")
			return CredentialRecord{}, false, nil
		},
		now:           func() time.Time { return now },
		ratePerMinute: 2,
		sourceMax:     4,
		stateMaxBytes: 64 << 10,
	})
	if err != nil {
		t.Fatalf("newReceiver() error = %v", err)
	}
	source := netip.MustParseAddrPort("192.0.2.111:50000")
	for _, input := range [][]byte{
		[]byte(`{"magic":"codecomm"`),
		[]byte(`{"magic":"codecomm","protocol":1,"session_id":"01890f47-3e72-7000-8000-000000000001"}`),
	} {
		if _, err := receiver.Accept(context.Background(), input, source); err == nil {
			t.Fatal("Accept(malformed) succeeded")
		}
	}
	if _, err := receiver.Accept(
		context.Background(),
		[]byte(`{"magic":"codecomm"`),
		source,
	); !errors.Is(err, ErrDatagramRateLimited) {
		t.Fatalf("third Accept() error = %v, want %v", err, ErrDatagramRateLimited)
	}
	if stats := receiver.Stats(); stats.TrackedSources != 1 {
		t.Fatalf("Stats() = %#v, want one bounded source", stats)
	}
}

func TestReceiverRateLimitAndNonceTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	current := now
	publicKey, privateKey := advertisementKey(t, 10)
	record := validCredentialRecord(t, publicKey, 1)
	receiver, err := newReceiver(receiverOptions{
		sessionID: testSessionID,
		resolve: func(
			context.Context,
			domain.UUIDv7,
			uint64,
			[sha256.Size]byte,
		) (CredentialRecord, bool, error) {
			return record, true, nil
		},
		now:           func() time.Time { return current },
		ratePerMinute: 2,
		sourceMax:     4,
		stateMaxBytes: 64 << 10,
	})
	if err != nil {
		t.Fatalf("newReceiver() error = %v", err)
	}
	source := netip.MustParseAddrPort("192.0.2.12:50000")
	for nonce := byte(1); nonce <= 2; nonce++ {
		encoded := signedReceiverAdvertisement(
			t,
			publicKey,
			privateKey,
			1,
			nonce,
			"2026-08-13T12:00:20Z",
		)
		if _, err := receiver.Accept(context.Background(), encoded, source); err != nil {
			t.Fatalf("Accept(nonce %d) error = %v", nonce, err)
		}
	}
	third := signedReceiverAdvertisement(
		t,
		publicKey,
		privateKey,
		1,
		3,
		"2026-08-13T12:00:20Z",
	)
	if _, err := receiver.Accept(
		context.Background(),
		third,
		source,
	); !errors.Is(err, ErrDatagramRateLimited) {
		t.Fatalf("third Accept() error = %v, want %v", err, ErrDatagramRateLimited)
	}

	current = now.Add(NonceCacheTTL + time.Second)
	replayed := signedReceiverAdvertisement(
		t,
		publicKey,
		privateKey,
		1,
		1,
		"2026-08-13T12:05:21Z",
	)
	if _, err := receiver.Accept(context.Background(), replayed, source); err != nil {
		t.Fatalf("Accept(after nonce TTL) error = %v", err)
	}
}

func TestReceiverEvictsOldestSourceAtCountAndMemoryBounds(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	current := now
	publicKey, privateKey := advertisementKey(t, 11)
	record := validCredentialRecord(t, publicKey, 1)
	receiver, err := newReceiver(receiverOptions{
		sessionID: testSessionID,
		resolve: func(
			context.Context,
			domain.UUIDv7,
			uint64,
			[sha256.Size]byte,
		) (CredentialRecord, bool, error) {
			return record, true, nil
		},
		now:           func() time.Time { return current },
		ratePerMinute: DiscoveryRatePerMinute,
		sourceMax:     2,
		stateMaxBytes: 2 * (sourceStateAccountBytes +
			4*attemptAccountBytes +
			16*nonceAccountBytes),
	})
	if err != nil {
		t.Fatalf("newReceiver() error = %v", err)
	}
	encoded := signedReceiverAdvertisement(
		t,
		publicKey,
		privateKey,
		1,
		1,
		"2026-08-13T12:00:30Z",
	)
	for index := 1; index <= 3; index++ {
		source := netip.MustParseAddrPort(
			fmt.Sprintf("192.0.2.%d:50000", index),
		)
		if _, err := receiver.Accept(context.Background(), encoded, source); err != nil {
			t.Fatalf("Accept(source %d) error = %v", index, err)
		}
		current = current.Add(time.Second)
	}
	stats := receiver.Stats()
	if stats.TrackedSources != 2 ||
		stats.AccountedBytes > receiver.stateMaxBytes {
		t.Fatalf("Stats() = %#v, max bytes %d", stats, receiver.stateMaxBytes)
	}
}

func TestReceiverPreservesIPv6LinkLocalZoneAndIgnoresSourcePort(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := advertisementKey(t, 12)
	record := validCredentialRecord(t, publicKey, 1)
	receiver := testReceiver(t, now, func(
		context.Context,
		domain.UUIDv7,
		uint64,
		[sha256.Size]byte,
	) (CredentialRecord, bool, error) {
		return record, true, nil
	})
	encoded := signedReceiverAdvertisement(
		t,
		publicKey,
		privateKey,
		1,
		1,
		"2026-08-13T12:00:20Z",
	)
	hint, err := receiver.Accept(
		context.Background(),
		encoded,
		netip.MustParseAddrPort("[fe80::1%en7]:65000"),
	)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if want := netip.MustParseAddrPort("[fe80::1%en7]:47831"); hint.Destination != want {
		t.Fatalf("Destination = %v, want %v", hint.Destination, want)
	}
}

func TestReceiverRejectsInvalidSourcesBeforeAllocation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := advertisementKey(t, 13)
	receiver := testReceiver(t, now, func(
		context.Context,
		domain.UUIDv7,
		uint64,
		[sha256.Size]byte,
	) (CredentialRecord, bool, error) {
		t.Fatal("resolver called for invalid source")
		return CredentialRecord{}, false, nil
	})
	encoded := signedReceiverAdvertisement(
		t,
		publicKey,
		privateKey,
		1,
		1,
		"2026-08-13T12:00:20Z",
	)
	for _, source := range []string{
		"127.0.0.1:1",
		"0.0.0.0:1",
		"224.0.0.1:1",
		"255.255.255.255:1",
		"[::1]:1",
		"[::]:1",
		"[ff02::1]:1",
		"[fe80::1]:1",
		"[::ffff:192.0.2.1]:1",
	} {
		source := source
		t.Run(source, func(t *testing.T) {
			if _, err := receiver.Accept(
				context.Background(),
				encoded,
				netip.MustParseAddrPort(source),
			); !errors.Is(err, ErrInvalidSource) {
				t.Fatalf("Accept() error = %v, want %v", err, ErrInvalidSource)
			}
		})
	}
	if stats := receiver.Stats(); stats != (ReceiverStats{}) {
		t.Fatalf("Stats() = %#v, want zero", stats)
	}
}

func testReceiver(
	t *testing.T,
	now time.Time,
	resolver CredentialResolver,
) *Receiver {
	t.Helper()
	receiver, err := newReceiver(receiverOptions{
		sessionID:     testSessionID,
		resolve:       resolver,
		now:           func() time.Time { return now },
		ratePerMinute: DiscoveryRatePerMinute,
		sourceMax:     TrackedSourcesMax,
		stateMaxBytes: DiscoveryStateMaxBytes,
	})
	if err != nil {
		t.Fatalf("newReceiver() error = %v", err)
	}
	return receiver
}

func validCredentialRecord(
	t *testing.T,
	publicKey ed25519.PublicKey,
	epoch uint64,
) CredentialRecord {
	t.Helper()
	return CredentialRecord{
		DeviceID: domain.DeviceID(
			"cc1" + fmt.Sprintf("%064x", epoch),
		),
		Epoch:          epoch,
		PublicKey:      append(ed25519.PublicKey(nil), publicKey...),
		NotBefore:      "2026-08-13T11:30:00Z",
		NotAfter:       "2026-08-13T12:00:30Z",
		MemberActive:   true,
		LatestRetained: true,
	}
}

func signedReceiverAdvertisement(
	t *testing.T,
	publicKey ed25519.PublicKey,
	privateKey ed25519.PrivateKey,
	epoch uint64,
	nonceByte byte,
	expiresAt domain.Timestamp,
) []byte {
	t.Helper()
	value, err := newAdvertisement(
		testSessionID,
		47831,
		epoch,
		sha256.Sum256(publicKey),
		expiresAt,
		bytes.NewReader(bytes.Repeat(
			[]byte{nonceByte},
			AdvertisementNonceSize,
		)),
	)
	if err != nil {
		t.Fatalf("newAdvertisement() error = %v", err)
	}
	encoded, err := SignAdvertisement(value, privateKey)
	if err != nil {
		t.Fatalf("SignAdvertisement() error = %v", err)
	}
	return encoded
}
