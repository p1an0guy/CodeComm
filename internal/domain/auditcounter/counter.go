// Package auditcounter defines bounded per-device rejection-audit state.
package auditcounter

import (
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

// MaxAcceptedCount is the immutable V1 ceiling for accepted explicit
// rejection-audit events per device and credential epoch.
const MaxAcceptedCount uint64 = 1024

var (
	ErrInvalidDeviceID        = errors.New("audit counter: invalid device ID")
	ErrInvalidCredentialEpoch = errors.New("audit counter: invalid credential epoch")
	ErrInvalidAcceptedCount   = errors.New("audit counter: invalid accepted count")
)

// Counter is one enrolled device's current credential epoch and accepted
// audit-event count for that epoch.
type Counter struct {
	DeviceID        domain.DeviceID
	CredentialEpoch uint64
	AcceptedCount   uint64
}

// Validate verifies the row's persisted invariants.
func (counter Counter) Validate() error {
	if !counter.DeviceID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidDeviceID, counter.DeviceID)
	}
	if !domain.ValidUnsignedInteger(counter.CredentialEpoch) {
		return fmt.Errorf(
			"%w: must be in 0..%d",
			ErrInvalidCredentialEpoch,
			domain.MaxSafeInteger,
		)
	}
	if counter.AcceptedCount > MaxAcceptedCount {
		return fmt.Errorf(
			"%w: must be in 0..%d",
			ErrInvalidAcceptedCount,
			MaxAcceptedCount,
		)
	}
	return nil
}
