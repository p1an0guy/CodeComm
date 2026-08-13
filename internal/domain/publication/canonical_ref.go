package publication

import (
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

const CanonicalRefName = "refs/codecomm/canonical"

var (
	ErrInvalidCanonicalRefName    = errors.New("publication: invalid canonical ref name")
	ErrInvalidCanonicalCommit     = errors.New("publication: invalid canonical commit")
	ErrInvalidCanonicalRefVersion = errors.New("publication: invalid canonical ref version")
)

// CanonicalRef is the sole replicated repository pointer. It is never a user
// branch.
type CanonicalRef struct {
	RefName       string
	CommitOID     domain.GitOID
	EntityVersion uint64
}

// Validate checks the fixed name, full algorithm-tagged OID, and CAS version.
func (ref CanonicalRef) Validate() error {
	if ref.RefName != CanonicalRefName {
		return fmt.Errorf("%w: %q", ErrInvalidCanonicalRefName, ref.RefName)
	}
	if !ref.CommitOID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidCanonicalCommit, ref.CommitOID)
	}
	if ref.EntityVersion < 1 || !domain.ValidUnsignedInteger(ref.EntityVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidCanonicalRefVersion,
			domain.MaxSafeInteger,
		)
	}
	return nil
}
