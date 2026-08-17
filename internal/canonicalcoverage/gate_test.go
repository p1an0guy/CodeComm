package canonicalcoverage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

type unitCollector struct {
	encoded [][]byte
	err     error
	calls   int
	got     []Requirement
}

func (collector *unitCollector) CollectCanonicalCoverage(
	_ context.Context,
	requirement Requirement,
) ([][]byte, error) {
	collector.calls++
	collector.got = append(collector.got, requirement)
	result := make([][]byte, len(collector.encoded))
	for index, encoded := range collector.encoded {
		result[index] = bytes.Clone(encoded)
	}
	return result, collector.err
}

func TestVerifyRequiresExactTargetMajority(t *testing.T) {
	identities := unitIdentities(t, 3)
	requirement := unitRequirement(
		t,
		identities,
		4,
		9,
		domain.GitOID("sha1:"+strings.Repeat("5", 40)),
	)
	snapshot := unitSnapshot(t, requirement, identities)
	receipts := []Receipt{
		unitSignReceipt(t, identities[0], requirement),
		unitSignReceipt(t, identities[1], requirement),
		unitSignReceipt(t, identities[2], requirement),
	}

	if _, err := unitCollectCandidate(t, snapshot, receipts[:2]); err != nil {
		t.Fatalf("Collect(majority): %v", err)
	}
	if _, err := unitCollectCandidate(
		t,
		snapshot,
		[]Receipt{receipts[1], receipts[0]},
	); err != nil {
		t.Fatalf("Collect(unordered majority): %v", err)
	}
	_, err := unitCollectCandidate(t, snapshot, receipts[:1])
	if !errors.Is(err, ErrObjectCoverageDegraded) ||
		!errors.Is(err, ErrCoverageQuorum) {
		t.Fatalf("Collect(minority) error = %v", err)
	}
	var degradedErr *DegradedError
	if !errors.As(err, &degradedErr) {
		t.Fatalf("Collect(minority) error type = %T", err)
	}
	wantMissing := []domain.DeviceID{identities[1].id, identities[2].id}
	if got := degradedErr.MissingVoterDeviceIDs(); !sameUnitDeviceIDs(
		got,
		wantMissing,
	) {
		t.Fatalf("missing voters = %v, want %v", got, wantMissing)
	}
	got := degradedErr.MissingVoterDeviceIDs()
	got[0] = ""
	if !sameUnitDeviceIDs(
		degradedErr.MissingVoterDeviceIDs(),
		wantMissing,
	) {
		t.Fatal("MissingVoterDeviceIDs() aliases retained state")
	}
}

func TestCollectAcceptsExactMajoritiesForEveryVoterCount(t *testing.T) {
	identities := unitIdentities(t, 5)
	for _, count := range []int{1, 3, 5} {
		t.Run(string(rune('0'+count))+" voters", func(t *testing.T) {
			target := identities[:count]
			requirement := unitRequirement(
				t,
				target,
				1,
				1,
				domain.GitOID("sha1:"+strings.Repeat(
					string(rune('0'+count)),
					40,
				)),
			)
			snapshot := unitSnapshot(t, requirement, target)
			required := count/2 + 1
			receipts := make([]Receipt, required)
			for index := range required {
				receipts[index] = unitSignReceipt(
					t,
					target[index],
					requirement,
				)
			}
			if _, err := unitCollectCandidate(
				t,
				snapshot,
				receipts,
			); err != nil {
				t.Fatalf("Collect(exact majority): %v", err)
			}
			if _, err := unitCollectCandidate(
				t,
				snapshot,
				receipts[:required-1],
			); !errors.Is(err, ErrCoverageQuorum) {
				t.Fatalf("Collect(minority) error = %v", err)
			}
		})
	}
}

func TestCollectClassifiesDuplicateForeignStaleAndForgedReceipts(t *testing.T) {
	identities := unitIdentities(t, 5)
	target := identities[:3]
	requirement := unitRequirement(
		t,
		target,
		2,
		3,
		domain.GitOID("sha1:"+strings.Repeat("6", 40)),
	)
	snapshot := unitSnapshot(t, requirement, target)
	first := unitSignReceipt(t, target[0], requirement)
	second := unitSignReceipt(t, target[1], requirement)

	tests := []struct {
		name      string
		receipts  func() []Receipt
		want      error
		integrity bool
	}{
		{
			"duplicate",
			func() []Receipt { return []Receipt{first, first} },
			ErrReceiptIntegrity,
			true,
		},
		{
			"too many",
			func() []Receipt {
				return []Receipt{first, second, first, second}
			},
			ErrReceiptIntegrity,
			true,
		},
		{
			"stale target version",
			func() []Receipt {
				stale := unitRequirement(
					t,
					target,
					1,
					3,
					requirement.CanonicalRef.CommitOID,
				)
				return []Receipt{
					unitSignReceipt(t, target[0], stale),
					second,
				}
			},
			ErrReceiptContext,
			false,
		},
		{
			"stale canonical version",
			func() []Receipt {
				stale := unitRequirement(
					t,
					target,
					2,
					2,
					requirement.CanonicalRef.CommitOID,
				)
				return []Receipt{
					unitSignReceipt(t, target[0], stale),
					second,
				}
			},
			ErrReceiptContext,
			false,
		},
		{
			"changed canonical commit",
			func() []Receipt {
				stale := unitRequirement(
					t,
					target,
					2,
					3,
					domain.GitOID("sha1:"+strings.Repeat("7", 40)),
				)
				return []Receipt{
					unitSignReceipt(t, target[0], stale),
					second,
				}
			},
			ErrReceiptContext,
			false,
		},
		{
			"cross-session replay",
			func() []Receipt {
				otherSession := domain.UUIDv7(
					"018f47de-89ab-7def-8123-456789abcdee",
				)
				ids := make([]domain.DeviceID, len(target))
				for index, identity := range target {
					ids[index] = identity.id
				}
				otherTarget, err := voterset.New(otherSession, ids, 2)
				if err != nil {
					t.Fatal(err)
				}
				stale := requirement
				stale.SessionID = otherSession
				stale.VoterSet = otherTarget
				return []Receipt{
					unitSignReceipt(t, target[0], stale),
					second,
				}
			},
			ErrReceiptContext,
			false,
		},
		{
			"cross-workspace replay",
			func() []Receipt {
				stale := requirement
				stale.WorkspaceID = domain.UUIDv4(
					"550e8400-e29b-41d4-a716-446655440001",
				)
				return []Receipt{
					unitSignReceipt(t, target[0], stale),
					second,
				}
			},
			ErrReceiptContext,
			false,
		},
		{
			"foreign voter",
			func() []Receipt {
				foreignTarget := []unitIdentity{
					target[0],
					target[1],
					identities[3],
				}
				sortUnitIdentities(foreignTarget)
				foreignRequirement := unitRequirement(
					t,
					foreignTarget,
					2,
					3,
					requirement.CanonicalRef.CommitOID,
				)
				return []Receipt{
					first,
					unitSignReceipt(t, identities[3], foreignRequirement),
				}
			},
			ErrReceiptContext,
			false,
		},
		{
			"forged signature",
			func() []Receipt {
				subject, _ := requirement.Subject()
				signedBytes, err := encodeUnsignedReceipt(
					subject,
					target[1].id,
				)
				if err != nil {
					t.Fatal(err)
				}
				signature, err := codecommcrypto.SignEd25519(
					target[0].private,
					codec.SignatureGitCanonicalCoverage,
					signedBytes,
				)
				if err != nil {
					t.Fatal(err)
				}
				forged, err := newReceipt(
					subject,
					target[1].id,
					signature,
				)
				if err != nil {
					t.Fatal(err)
				}
				return []Receipt{first, forged}
			},
			ErrReceiptIntegrity,
			true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := unitCollectCandidate(t, snapshot, test.receipts())
			if !errors.Is(err, test.want) {
				t.Fatalf("Collect() error = %v, want %v", err, test.want)
			}
			if test.integrity {
				if !errors.Is(err, ErrCoverageIntegrityBlocked) ||
					errors.Is(err, ErrObjectCoverageDegraded) {
					t.Fatalf("Collect() integrity classification = %v", err)
				}
			} else if !errors.Is(err, ErrObjectCoverageDegraded) ||
				errors.Is(err, ErrCoverageIntegrityBlocked) {
				t.Fatalf("Collect() degraded classification = %v", err)
			}
		})
	}
}

func TestNewSnapshotRequiresEveryTargetIdentity(t *testing.T) {
	identities := unitIdentities(t, 3)
	requirement := unitRequirement(
		t,
		identities,
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("8", 40)),
	)
	keys := unitIdentityKeys(identities)
	delete(keys, identities[2].id)
	if _, err := NewSnapshot(requirement, keys); !errors.Is(
		err,
		ErrInvalidSnapshot,
	) {
		t.Fatalf("NewSnapshot(missing key) error = %v", err)
	}
	keys = unitIdentityKeys(identities)
	keys[identities[1].id] = bytes.Clone(identities[0].public)
	if _, err := NewSnapshot(requirement, keys); !errors.Is(
		err,
		ErrInvalidSnapshot,
	) {
		t.Fatalf("NewSnapshot(mismatched key) error = %v", err)
	}

	keys = unitIdentityKeys(identities)
	snapshot, err := NewSnapshot(requirement, keys)
	if err != nil {
		t.Fatalf("NewSnapshot(): %v", err)
	}
	keys[identities[0].id][0] ^= 0xff
	if _, err := unitCollectCandidate(t, snapshot, []Receipt{
		unitSignReceipt(t, identities[0], requirement),
		unitSignReceipt(t, identities[1], requirement),
	}); err != nil {
		t.Fatalf("Collect(after input key mutation): %v", err)
	}
}

func TestCollectTreatsMalformedReceiptAsIntegrityBlocker(t *testing.T) {
	identities := unitIdentities(t, 3)
	requirement := unitRequirement(
		t,
		identities,
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("8", 40)),
	)
	snapshot := unitSnapshot(t, requirement, identities)
	gate, err := NewGate(&unitCollector{encoded: [][]byte{
		[]byte(`{}`),
		unitSignReceipt(t, identities[0], requirement).CanonicalBytes(),
	}})
	if err != nil {
		t.Fatalf("NewGate(): %v", err)
	}
	if _, err := gate.Collect(
		context.Background(),
		snapshot,
	); !errors.Is(err, ErrCoverageIntegrityBlocked) ||
		!errors.Is(err, ErrReceiptIntegrity) ||
		errors.Is(err, ErrObjectCoverageDegraded) {
		t.Fatalf("Collect(malformed) error = %v", err)
	}
}

func TestGateCandidateRequiresFreshAppliedCut(t *testing.T) {
	identities := unitIdentities(t, 3)
	requirement := unitRequirement(
		t,
		identities,
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("9", 40)),
	)
	before := unitSnapshot(t, requirement, identities)
	collector := &unitCollector{encoded: unitReceiptBytes([]Receipt{
		unitSignReceipt(t, identities[0], requirement),
		unitSignReceipt(t, identities[1], requirement),
	})}
	gate, err := NewGate(collector)
	if err != nil {
		t.Fatalf("NewGate(): %v", err)
	}
	candidate, err := gate.Collect(context.Background(), before)
	if err != nil {
		t.Fatalf("Collect(): %v", err)
	}
	if err := gate.VerifyCurrent(before, candidate); err != nil {
		t.Fatalf("VerifyCurrent(): %v", err)
	}
	if collector.calls != 1 ||
		len(collector.got) != 1 ||
		!collector.got[0].same(requirement) {
		t.Fatalf(
			"Collect() = calls %d, requirement %#v",
			collector.calls,
			collector.got,
		)
	}

	advancedVersionRequirement := unitRequirement(
		t,
		identities,
		1,
		2,
		requirement.CanonicalRef.CommitOID,
	)
	advancedVersion := unitSnapshot(
		t,
		advancedVersionRequirement,
		identities,
	)
	if err := gate.VerifyCurrent(
		advancedVersion,
		candidate,
	); !errors.Is(err, ErrObjectCoverageDegraded) ||
		!errors.Is(err, ErrCoverageChanged) {
		t.Fatalf("VerifyCurrent(advanced canonical version) error = %v", err)
	}

	advancedRequirement := unitRequirement(
		t,
		identities,
		1,
		2,
		domain.GitOID("sha1:"+strings.Repeat("a", 40)),
	)
	advanced := unitSnapshot(t, advancedRequirement, identities)
	if err := gate.VerifyCurrent(
		advanced,
		candidate,
	); !errors.Is(err, ErrObjectCoverageDegraded) ||
		!errors.Is(err, ErrCoverageChanged) {
		t.Fatalf("VerifyCurrent(advanced ref) error = %v", err)
	}

	sameIDs := requirement.VoterSet.VoterDeviceIDs()
	advancedTargetVersion, err := voterset.New(
		unitSessionID,
		sameIDs,
		2,
	)
	if err != nil {
		t.Fatalf("voterset.New(advanced version): %v", err)
	}
	targetVersionRequirement := requirement
	targetVersionRequirement.VoterSet = advancedTargetVersion
	targetVersionAdvanced := unitSnapshot(
		t,
		targetVersionRequirement,
		identities,
	)
	if err := gate.VerifyCurrent(
		targetVersionAdvanced,
		candidate,
	); !errors.Is(err, ErrCoverageChanged) {
		t.Fatalf("VerifyCurrent(advanced target version) error = %v", err)
	}

	advancedTarget, err := voterset.New(
		unitSessionID,
		[]domain.DeviceID{identities[0].id},
		2,
	)
	if err != nil {
		t.Fatalf("voterset.New(advanced): %v", err)
	}
	targetRequirement := requirement
	targetRequirement.VoterSet = advancedTarget
	targetAdvanced := unitSnapshot(
		t,
		targetRequirement,
		identities[:1],
	)
	if err := gate.VerifyCurrent(
		targetAdvanced,
		candidate,
	); !errors.Is(err, ErrCoverageChanged) {
		t.Fatalf("VerifyCurrent(advanced target) error = %v", err)
	}
}

func TestGateFailsClosedWithoutCollectorOrReceipts(t *testing.T) {
	identities := unitIdentities(t, 1)
	requirement := unitRequirement(
		t,
		identities,
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("b", 40)),
	)
	snapshot := unitSnapshot(t, requirement, identities)
	if _, err := (*Gate)(nil).Collect(
		context.Background(),
		snapshot,
	); !errors.Is(err, ErrCollectorUnavailable) ||
		!errors.Is(err, ErrObjectCoverageDegraded) {
		t.Fatalf("nil Gate.Collect() error = %v", err)
	}
	var typedNil *unitCollector
	if _, err := NewGate(typedNil); !errors.Is(
		err,
		ErrCollectorUnavailable,
	) {
		t.Fatalf("NewGate(typed nil) error = %v", err)
	}
	collector := &unitCollector{}
	gate, err := NewGate(collector)
	if err != nil {
		t.Fatalf("NewGate(): %v", err)
	}
	if _, err := gate.Collect(
		context.Background(),
		snapshot,
	); !errors.Is(err, ErrCoverageQuorum) {
		t.Fatalf("Collect(no receipts) error = %v", err)
	}
	injected := errors.New("network unavailable")
	collector.err = injected
	if _, err := gate.Collect(
		context.Background(),
		snapshot,
	); !errors.Is(err, ErrReceiptCollection) ||
		!errors.Is(err, injected) ||
		!errors.Is(err, ErrObjectCoverageDegraded) {
		t.Fatalf("Collect(collection failure) error = %v", err)
	}
}

func unitSnapshot(
	t *testing.T,
	requirement Requirement,
	identities []unitIdentity,
) Snapshot {
	t.Helper()
	snapshot, err := NewSnapshot(requirement, unitIdentityKeys(identities))
	if err != nil {
		t.Fatalf("NewSnapshot(): %v", err)
	}
	return snapshot
}

func unitCollectCandidate(
	t *testing.T,
	snapshot Snapshot,
	receipts []Receipt,
) (Candidate, error) {
	t.Helper()
	gate, err := NewGate(&unitCollector{encoded: unitReceiptBytes(receipts)})
	if err != nil {
		t.Fatalf("NewGate(): %v", err)
	}
	return gate.Collect(context.Background(), snapshot)
}

func unitReceiptBytes(receipts []Receipt) [][]byte {
	result := make([][]byte, len(receipts))
	for index, receipt := range receipts {
		result[index] = receipt.CanonicalBytes()
	}
	return result
}

func unitIdentityKeys(
	identities []unitIdentity,
) map[domain.DeviceID]ed25519.PublicKey {
	keys := make(map[domain.DeviceID]ed25519.PublicKey, len(identities))
	for _, identity := range identities {
		keys[identity.id] = bytes.Clone(identity.public)
	}
	return keys
}

func sameUnitDeviceIDs(left, right []domain.DeviceID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sortUnitIdentities(identities []unitIdentity) {
	for left := range identities {
		for right := left + 1; right < len(identities); right++ {
			if identities[right].id < identities[left].id {
				identities[left], identities[right] =
					identities[right], identities[left]
			}
		}
	}
}

var _ ReceiptCollector = (*unitCollector)(nil)
