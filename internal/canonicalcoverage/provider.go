package canonicalcoverage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

var (
	ErrInvalidRequirement     = errors.New("canonical coverage: invalid requirement")
	ErrProviderUnavailable    = errors.New("canonical coverage: object provider unavailable")
	ErrObjectVerification     = errors.New("canonical coverage: durable object verification failed")
	ErrSignerIdentity         = errors.New("canonical coverage: signer identity mismatch")
	ErrSignerOutsideTarget    = errors.New("canonical coverage: signer is outside voter target")
	ErrObjectCoverageDegraded = errors.New("object-coverage-degraded")
)

// Requirement combines the exact signed subject with the complete current
// voter target. The target is needed to authorize signers and establish the
// required majority.
type Requirement struct {
	SessionID    domain.UUIDv7
	WorkspaceID  domain.UUIDv4
	VoterSet     voterset.Set
	CanonicalRef publication.CanonicalRef
}

// Validate checks the complete current target/ref cut.
func (requirement Requirement) Validate() error {
	if !requirement.SessionID.Valid() ||
		!requirement.WorkspaceID.Valid() ||
		requirement.VoterSet.Validate() != nil ||
		requirement.VoterSet.SessionID != requirement.SessionID ||
		requirement.CanonicalRef.Validate() != nil {
		return ErrInvalidRequirement
	}
	return nil
}

// Subject returns the exact tuple each target voter signs.
func (requirement Requirement) Subject() (Subject, error) {
	if err := requirement.Validate(); err != nil {
		return Subject{}, err
	}
	return Subject{
		SessionID:           requirement.SessionID,
		WorkspaceID:         requirement.WorkspaceID,
		VoterSetVersion:     requirement.VoterSet.VoterSetVersion,
		CanonicalRefVersion: requirement.CanonicalRef.EntityVersion,
		CommitOID:           requirement.CanonicalRef.CommitOID,
	}, nil
}

func (requirement Requirement) same(other Requirement) bool {
	return requirement.SessionID == other.SessionID &&
		requirement.WorkspaceID == other.WorkspaceID &&
		requirement.CanonicalRef == other.CanonicalRef &&
		requirement.VoterSet.SessionID == other.VoterSet.SessionID &&
		requirement.VoterSet.VoterSetVersion ==
			other.VoterSet.VoterSetVersion &&
		requirement.VoterSet.SameTarget(other.VoterSet)
}

// Provider is an opaque local object-verification capability. Its
// package-owned implementation holds the import/GC lock while it verifies the
// exact canonical closure and invokes issue. External packages cannot supply a
// permissive implementation. Phase 4 adds the production Git constructor.
type Provider struct {
	verifyAndIssue func(context.Context, Subject, func() error) error
}

func newProvider(
	verifyAndIssue func(context.Context, Subject, func() error) error,
) *Provider {
	if verifyAndIssue == nil {
		return nil
	}
	return &Provider{verifyAndIssue: verifyAndIssue}
}

func (provider *Provider) available() bool {
	return provider != nil && provider.verifyAndIssue != nil
}

// Signer issues receipts only after its provider verifies the exact object.
type Signer struct {
	mu                 sync.Mutex
	provider           *Provider
	requirement        Requirement
	voterDeviceID      domain.DeviceID
	identityPrivateKey []byte
}

// NewSigner binds one package-owned provider and enrolled identity to one
// immutable applied-state snapshot. Sign accepts no caller-supplied tuple.
func NewSigner(
	provider *Provider,
	snapshot Snapshot,
	voterDeviceID domain.DeviceID,
	identityPrivateKey []byte,
) (*Signer, error) {
	if !provider.available() {
		return nil, degraded(
			"local durable-object provider is unavailable",
			nil,
			ErrProviderUnavailable,
		)
	}
	if !snapshot.valid {
		return nil, ErrInvalidSnapshot
	}
	if !snapshot.requirement.VoterSet.Contains(voterDeviceID) {
		return nil, ErrSignerOutsideTarget
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(
		identityPrivateKey,
	)
	if err != nil {
		return nil, err
	}
	derivedID, err := device.DeriveID(ed25519.PublicKey(publicKey))
	enrolledKey, enrolled := snapshot.identityPublicKeys[voterDeviceID]
	if err != nil ||
		derivedID != voterDeviceID ||
		!enrolled ||
		!bytes.Equal(publicKey, enrolledKey) {
		return nil, ErrSignerIdentity
	}
	return &Signer{
		provider:           provider,
		requirement:        snapshot.requirement,
		voterDeviceID:      voterDeviceID,
		identityPrivateKey: bytes.Clone(identityPrivateKey),
	}, nil
}

// Sign verifies durable possession and signs the bound applied-state tuple
// while the provider still holds its import/GC exclusion.
func (signer *Signer) Sign(ctx context.Context) (Receipt, error) {
	if ctx == nil {
		return Receipt{}, ErrInvalidRequirement
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if signer == nil {
		return Receipt{}, degraded(
			"local durable-object provider is unavailable",
			nil,
			ErrProviderUnavailable,
		)
	}
	signer.mu.Lock()
	defer signer.mu.Unlock()
	if !signer.provider.available() {
		return Receipt{}, degraded(
			"local durable-object provider is unavailable",
			nil,
			ErrProviderUnavailable,
		)
	}
	if err := signer.requirement.Validate(); err != nil {
		return Receipt{}, err
	}
	if !signer.requirement.VoterSet.Contains(signer.voterDeviceID) {
		return Receipt{}, ErrSignerOutsideTarget
	}
	subject, _ := signer.requirement.Subject()
	signedBytes, err := encodeUnsignedReceipt(subject, signer.voterDeviceID)
	if err != nil {
		return Receipt{}, err
	}
	var (
		receipt     Receipt
		issuanceErr error
		issued      bool
	)
	err = signer.provider.verifyAndIssue(
		ctx,
		subject,
		func() error {
			if issued {
				issuanceErr = errors.New(
					"canonical coverage: provider issued more than once",
				)
				return issuanceErr
			}
			issued = true
			if err := ctx.Err(); err != nil {
				issuanceErr = err
				return err
			}
			signature, err := codecommcrypto.SignEd25519(
				signer.identityPrivateKey,
				codec.SignatureGitCanonicalCoverage,
				signedBytes,
			)
			if err != nil {
				issuanceErr = err
				return err
			}
			receipt, issuanceErr = newReceipt(
				subject,
				signer.voterDeviceID,
				signature,
			)
			return issuanceErr
		},
	)
	if issuanceErr != nil {
		return Receipt{}, issuanceErr
	}
	if err != nil || !issued {
		if contextErr := ctx.Err(); contextErr != nil {
			return Receipt{}, contextErr
		}
		if err == nil {
			err = errors.New(
				"canonical coverage: provider returned without issuance",
			)
		}
		return Receipt{}, degraded(
			fmt.Sprintf(
				"device %s does not durably hold %s",
				signer.voterDeviceID,
				subject.CommitOID,
			),
			[]domain.DeviceID{signer.voterDeviceID},
			fmt.Errorf("%w: %w", ErrObjectVerification, err),
		)
	}
	return receipt, nil
}

// Close clears the retained private key. A closed signer cannot issue another
// receipt.
func (signer *Signer) Close() {
	if signer == nil {
		return
	}
	signer.mu.Lock()
	defer signer.mu.Unlock()
	clear(signer.identityPrivateKey)
	signer.identityPrivateKey = nil
	signer.provider = nil
	signer.requirement = Requirement{}
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
