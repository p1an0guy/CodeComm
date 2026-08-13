package discovery

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestEndpointCacheEnforcesSequenceAndByteIdentity(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 31)
	member := endpointMember(t, publicKey)
	cache, err := NewEndpointCache(2)
	if err != nil {
		t.Fatalf("NewEndpointCache() error = %v", err)
	}
	expected := endpointExpectation(member)
	first := validEndpointSet(member.ID)
	first.EndpointSequence = 100
	firstBytes, err := signEndpointSet(first, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet(first) error = %v", err)
	}
	_, update, err := cache.Accept(firstBytes, expected)
	if err != nil || update != EndpointSetStored {
		t.Fatalf("Accept(first) = (%v, %v), want stored", update, err)
	}
	_, update, err = cache.Accept(firstBytes, expected)
	if err != nil || update != EndpointSetIdempotent {
		t.Fatalf("Accept(replay) = (%v, %v), want idempotent", update, err)
	}

	conflict := first
	conflict.Endpoints = append([]Endpoint(nil), first.Endpoints...)
	conflict.ExpiresAt = "2026-08-13T12:02:39Z"
	conflictBytes, err := signEndpointSet(conflict, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet(conflict) error = %v", err)
	}
	if _, _, err := cache.Accept(conflictBytes, expected); !errors.Is(
		err,
		ErrEndpointSequenceConflict,
	) {
		t.Fatalf("Accept(conflict) error = %v, want %v", err, ErrEndpointSequenceConflict)
	}

	rollback := first
	rollback.EndpointSequence = 99
	rollbackBytes, err := signEndpointSet(rollback, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet(rollback) error = %v", err)
	}
	if _, _, err := cache.Accept(rollbackBytes, expected); !errors.Is(
		err,
		ErrEndpointSequenceRollback,
	) {
		t.Fatalf("Accept(rollback) error = %v, want %v", err, ErrEndpointSequenceRollback)
	}

	successor := first
	successor.EndpointSequence = 101
	successorBytes, err := signEndpointSet(successor, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet(successor) error = %v", err)
	}
	got, update, err := cache.Accept(successorBytes, expected)
	if err != nil || update != EndpointSetReplaced {
		t.Fatalf("Accept(successor) = (%v, %v), want replaced", update, err)
	}
	if !bytes.Equal(got.CanonicalBytes(), successorBytes) {
		t.Fatal("cache returned different canonical bytes")
	}
}

func TestEndpointCacheExpiresHighWaterAndPurgesAuthority(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 32)
	member := endpointMember(t, publicKey)
	cache, err := NewEndpointCache(1)
	if err != nil {
		t.Fatalf("NewEndpointCache() error = %v", err)
	}
	expected := endpointExpectation(member)
	first := validEndpointSet(member.ID)
	first.EndpointSequence = 100
	first.ExpiresAt = "2026-08-13T12:00:01Z"
	firstBytes, err := signEndpointSet(first, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet(first) error = %v", err)
	}
	if _, _, err := cache.Accept(firstBytes, expected); err != nil {
		t.Fatalf("Accept(first) error = %v", err)
	}
	if _, found := cache.Current(
		member.ID,
		endpointTestNow.Add(time.Second),
	); found {
		t.Fatal("Current() retained an expired endpoint set")
	}

	lower := validEndpointSet(member.ID)
	lower.EndpointSequence = 1
	lower.IssuedAt = "2026-08-13T12:00:01Z"
	lower.ExpiresAt = "2026-08-13T12:02:41Z"
	expected.Now = endpointTestNow.Add(time.Second)
	lowerBytes, err := signEndpointSet(lower, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet(lower) error = %v", err)
	}
	if _, update, err := cache.Accept(lowerBytes, expected); err != nil ||
		update != EndpointSetStored {
		t.Fatalf("Accept(after expiry) = (%v, %v), want stored", update, err)
	}
	cache.Purge(member.ID)
	if _, found := cache.Current(member.ID, expected.Now); found {
		t.Fatal("Purge() retained member endpoint authority")
	}
}
