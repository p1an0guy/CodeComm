package canonicalcoverage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

var (
	ErrInvalidSnapshot          = errors.New("canonical coverage: invalid applied snapshot")
	ErrCollectorUnavailable     = errors.New("canonical coverage: receipt collector unavailable")
	ErrReceiptCollection        = errors.New("canonical coverage: receipt collection failed")
	ErrReceiptContext           = errors.New("canonical coverage: receipt does not match current requirement")
	ErrReceiptIntegrity         = errors.New("canonical coverage: receipt integrity failure")
	ErrCoverageQuorum           = errors.New("canonical coverage: target majority not covered")
	ErrCoverageChanged          = errors.New("canonical coverage: target or canonical ref advanced")
	ErrCoverageIntegrityBlocked = errors.New(
		"canonical coverage: integrity blocked",
	)
)

// DegradedError is the fail-closed operator-facing coverage state. Missing
// voter IDs are sorted and independently returned to callers.
type DegradedError struct {
	detail  string
	missing []domain.DeviceID
	cause   error
}

func (err *DegradedError) Error() string {
	if err == nil {
		return ErrObjectCoverageDegraded.Error()
	}
	message := ErrObjectCoverageDegraded.Error()
	if err.detail != "" {
		message += ": " + err.detail
	}
	if len(err.missing) != 0 {
		values := make([]string, len(err.missing))
		for index, id := range err.missing {
			values[index] = string(id)
		}
		message += " (missing " + strings.Join(values, ",") + ")"
	}
	if err.cause != nil {
		message += ": " + err.cause.Error()
	}
	return message
}

func (err *DegradedError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (err *DegradedError) Is(target error) bool {
	return err != nil && target == ErrObjectCoverageDegraded
}

// MissingVoterDeviceIDs returns an independent sorted copy.
func (err *DegradedError) MissingVoterDeviceIDs() []domain.DeviceID {
	if err == nil {
		return nil
	}
	return append([]domain.DeviceID(nil), err.missing...)
}

func degraded(
	detail string,
	missing []domain.DeviceID,
	cause error,
) error {
	cloned := append([]domain.DeviceID(nil), missing...)
	sort.Slice(cloned, func(left, right int) bool {
		return cloned[left] < cloned[right]
	})
	return &DegradedError{detail: detail, missing: cloned, cause: cause}
}

// IntegrityError is a non-retryable signed-evidence failure. Callers audit it
// and block reconciliation instead of reporting ordinary object unavailability.
type IntegrityError struct {
	detail string
	cause  error
}

func (err *IntegrityError) Error() string {
	if err == nil {
		return ErrCoverageIntegrityBlocked.Error()
	}
	message := ErrCoverageIntegrityBlocked.Error()
	if err.detail != "" {
		message += ": " + err.detail
	}
	if err.cause != nil {
		message += ": " + err.cause.Error()
	}
	return message
}

func (err *IntegrityError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (err *IntegrityError) Is(target error) bool {
	return err != nil && target == ErrCoverageIntegrityBlocked
}

func integrityBlocked(detail string, cause error) error {
	return &IntegrityError{detail: detail, cause: cause}
}

// Snapshot is an immutable applied-state cut used to verify receipts.
type Snapshot struct {
	requirement        Requirement
	identityPublicKeys map[domain.DeviceID]ed25519.PublicKey
	valid              bool
}

// NewSnapshot validates and copies the target's enrolled identity keys.
func NewSnapshot(
	requirement Requirement,
	identityPublicKeys map[domain.DeviceID]ed25519.PublicKey,
) (Snapshot, error) {
	if err := requirement.Validate(); err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	target := requirement.VoterSet.VoterDeviceIDs()
	keys := make(map[domain.DeviceID]ed25519.PublicKey, len(target))
	for _, id := range target {
		key, exists := identityPublicKeys[id]
		if !exists {
			return Snapshot{}, fmt.Errorf(
				"%w: target voter %s has no identity key",
				ErrInvalidSnapshot,
				id,
			)
		}
		derivedID, err := device.DeriveID(key)
		if err != nil || derivedID != id {
			return Snapshot{}, fmt.Errorf(
				"%w: target voter %s has a mismatched identity key",
				ErrInvalidSnapshot,
				id,
			)
		}
		keys[id] = bytes.Clone(key)
	}
	return Snapshot{
		requirement:        requirement,
		identityPublicKeys: keys,
		valid:              true,
	}, nil
}

// Requirement returns the exact immutable target/ref requirement.
func (snapshot Snapshot) Requirement() (Requirement, bool) {
	if !snapshot.valid {
		return Requirement{}, false
	}
	return snapshot.requirement, true
}

func (snapshot Snapshot) same(other Snapshot) bool {
	if !snapshot.valid || !other.valid ||
		!snapshot.requirement.same(other.requirement) ||
		len(snapshot.identityPublicKeys) != len(other.identityPublicKeys) {
		return false
	}
	for id, key := range snapshot.identityPublicKeys {
		if !bytes.Equal(key, other.identityPublicKeys[id]) {
			return false
		}
	}
	return true
}

// ReceiptCollector obtains candidate signed receipt bytes for one exact
// current requirement. Its output is untrusted and is fully parsed and
// verified by Gate.
type ReceiptCollector interface {
	CollectCanonicalCoverage(context.Context, Requirement) ([][]byte, error)
}

// Candidate is an opaque verified receipt majority tied to one applied-state
// baseline. It contains no authority until VerifyCurrent accepts a fresh cut.
type Candidate struct {
	baseline Snapshot
	receipts []Receipt
	valid    bool
}

// Gate enforces exact target-majority coverage and freshness.
type Gate struct {
	collector ReceiptCollector
}

// NewGate constructs a verifier around an untrusted receipt collector.
func NewGate(collector ReceiptCollector) (*Gate, error) {
	if nilCapability(collector) {
		return nil, degraded(
			"receipt collector is unavailable",
			nil,
			ErrCollectorUnavailable,
		)
	}
	return &Gate{collector: collector}, nil
}

// Collect performs the potentially slow receipt acquisition and verifies the
// result against one immutable baseline. Consensus performs final verification
// only after entering its configuration-enqueue critical section.
func (gate *Gate) Collect(
	ctx context.Context,
	snapshot Snapshot,
) (Candidate, error) {
	if ctx == nil {
		return Candidate{}, ErrInvalidSnapshot
	}
	if err := ctx.Err(); err != nil {
		return Candidate{}, err
	}
	if gate == nil || nilCapability(gate.collector) {
		return Candidate{}, degraded(
			"receipt collector is unavailable",
			nil,
			ErrCollectorUnavailable,
		)
	}
	if !snapshot.valid {
		return Candidate{}, ErrInvalidSnapshot
	}
	encoded, err := gate.collector.CollectCanonicalCoverage(
		ctx,
		snapshot.requirement,
	)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Candidate{}, contextErr
		}
		return Candidate{}, degraded(
			"receipt collection failed",
			snapshot.requirement.VoterSet.VoterDeviceIDs(),
			fmt.Errorf("%w: %w", ErrReceiptCollection, err),
		)
	}
	if err := ctx.Err(); err != nil {
		return Candidate{}, err
	}
	receipts, err := parseAndVerifyReceipts(snapshot, encoded)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{
		baseline: snapshot,
		receipts: receipts,
		valid:    true,
	}, nil
}

// VerifyCurrent revalidates a candidate against a fresh applied-state cut.
// It performs no I/O and is intended to run immediately before a serialized
// Raft configuration enqueue.
func (gate *Gate) VerifyCurrent(
	current Snapshot,
	candidate Candidate,
) error {
	if gate == nil || nilCapability(gate.collector) {
		return degraded(
			"receipt collector is unavailable",
			nil,
			ErrCollectorUnavailable,
		)
	}
	if !current.valid || !candidate.valid || !candidate.baseline.valid {
		return ErrInvalidSnapshot
	}
	if !candidate.baseline.same(current) {
		requirement, valid := current.Requirement()
		var missing []domain.DeviceID
		if valid {
			missing = requirement.VoterSet.VoterDeviceIDs()
		}
		return degraded(
			"coverage changed after receipt collection",
			missing,
			ErrCoverageChanged,
		)
	}
	return verifyReceipts(current, candidate.receipts)
}

func parseAndVerifyReceipts(
	snapshot Snapshot,
	encoded [][]byte,
) ([]Receipt, error) {
	if len(encoded) > len(snapshot.requirement.VoterSet.VoterDeviceIDs()) {
		return nil, integrityBlocked(
			"receipt set exceeds the voter target",
			ErrReceiptIntegrity,
		)
	}
	receipts := make([]Receipt, len(encoded))
	for index, raw := range encoded {
		receipt, err := ParseReceipt(raw)
		if err != nil {
			return nil, integrityBlocked(
				fmt.Sprintf("receipt %d is malformed", index),
				fmt.Errorf("%w: %w", ErrReceiptIntegrity, err),
			)
		}
		receipts[index] = receipt
	}
	if err := verifyReceipts(snapshot, receipts); err != nil {
		return nil, err
	}
	return receipts, nil
}

func verifyReceipts(snapshot Snapshot, receipts []Receipt) error {
	requirement := snapshot.requirement
	subject, err := requirement.Subject()
	if err != nil {
		return ErrInvalidSnapshot
	}
	target := requirement.VoterSet.VoterDeviceIDs()
	if len(receipts) > len(target) {
		return integrityBlocked(
			"receipt set exceeds the voter target",
			ErrReceiptIntegrity,
		)
	}
	seen := make(map[domain.DeviceID]struct{}, len(receipts))
	for index, receipt := range receipts {
		id := receipt.VoterDeviceID()
		key, exists := snapshot.identityPublicKeys[id]
		if !exists || !requirement.VoterSet.Contains(id) {
			return degraded(
				fmt.Sprintf("receipt %d is from a non-target voter", index),
				target,
				ErrReceiptContext,
			)
		}
		if err := receipt.Verify(key); err != nil {
			return integrityBlocked(
				fmt.Sprintf("receipt %d from %s failed verification", index, id),
				fmt.Errorf("%w: %w", ErrReceiptIntegrity, err),
			)
		}
		if receipt.Subject() != subject {
			return degraded(
				fmt.Sprintf("receipt %d has stale context", index),
				target,
				ErrReceiptContext,
			)
		}
		if _, duplicate := seen[id]; duplicate {
			return integrityBlocked(
				fmt.Sprintf("receipt %d duplicates voter %s", index, id),
				ErrReceiptIntegrity,
			)
		}
		seen[id] = struct{}{}
	}
	required := len(target)/2 + 1
	if len(seen) < required {
		missing := make([]domain.DeviceID, 0, len(target)-len(seen))
		for _, id := range target {
			if _, exists := seen[id]; !exists {
				missing = append(missing, id)
			}
		}
		return degraded(
			fmt.Sprintf(
				"verified %d of %d required target receipts",
				len(seen),
				required,
			),
			missing,
			ErrCoverageQuorum,
		)
	}
	return nil
}
