// Package peerauth authorizes authenticated peer certificates against one
// immutable view of applied membership and credential state.
package peerauth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

var ErrInvalidSnapshot = errors.New("peer auth: invalid applied snapshot")

// SnapshotInput is the applied reducer subset needed at peer admission.
// NewSnapshot defensively copies it and retains at most the current and prior
// credential epoch for each device.
type SnapshotInput struct {
	SessionID          domain.UUIDv7
	RecoveryGeneration uint64
	AppliedChainIndex  uint64

	Devices                  map[domain.DeviceID]device.Device
	AuditCounters            map[domain.DeviceID]auditcounter.Counter
	CredentialAuthorizations map[credentialauthorization.Key]credentialauthorization.Authorization
}

// Changes is the admission-relevant subset of one validated reducer outcome.
type Changes struct {
	AdvancesEventChain       bool
	Devices                  []device.Device
	AuditCounters            []auditcounter.Counter
	CredentialAuthorizations []credentialauthorization.Authorization
}

// Snapshot is immutable after construction and safe for concurrent reads.
// Its maps and mutable row fields are never exposed without a defensive copy.
type Snapshot struct {
	sessionID          domain.UUIDv7
	recoveryGeneration uint64
	appliedChainIndex  uint64
	devices            map[domain.DeviceID]device.Device
	credentialEpochs   map[domain.DeviceID]uint64
	authorizations     map[credentialauthorization.Key]credentialauthorization.Authorization
	valid              bool
}

// NewSnapshot validates and copies one complete applied-state cut.
func NewSnapshot(input SnapshotInput) (*Snapshot, error) {
	devices := make(map[domain.DeviceID]device.Device, len(input.Devices))
	for id, member := range input.Devices {
		member.IdentityPublicKey = bytes.Clone(member.IdentityPublicKey)
		devices[id] = member
	}
	epochs := make(map[domain.DeviceID]uint64, len(input.AuditCounters))
	for id, counter := range input.AuditCounters {
		if id != counter.DeviceID {
			return nil, invalidSnapshot("audit-counter map key does not match row")
		}
		if err := counter.Validate(); err != nil {
			return nil, invalidSnapshot("audit counter %q: %v", id, err)
		}
		epochs[id] = counter.CredentialEpoch
	}
	for key, authorization := range input.CredentialAuthorizations {
		if key != authorization.PrimaryKey() {
			return nil, invalidSnapshot(
				"credential-authorization map key does not match row",
			)
		}
	}
	return newSnapshot(
		input.SessionID,
		input.RecoveryGeneration,
		input.AppliedChainIndex,
		devices,
		epochs,
		input.CredentialAuthorizations,
	)
}

// Advance derives the next immutable snapshot from one reducer outcome. It
// reuses unchanged maps and validates all changed rows before publication.
func (snapshot *Snapshot) Advance(changes Changes) (*Snapshot, error) {
	if snapshot == nil || !snapshot.valid {
		return nil, ErrInvalidSnapshot
	}
	chainIndex := snapshot.appliedChainIndex
	if changes.AdvancesEventChain {
		if chainIndex == domain.MaxSafeInteger {
			return nil, invalidSnapshot("applied chain index is exhausted")
		}
		chainIndex++
	} else if len(changes.Devices) != 0 ||
		len(changes.AuditCounters) != 0 ||
		len(changes.CredentialAuthorizations) != 0 {
		return nil, invalidSnapshot(
			"admission changes do not advance the event chain",
		)
	}
	if len(changes.Devices) == 0 &&
		len(changes.AuditCounters) == 0 &&
		len(changes.CredentialAuthorizations) == 0 {
		return &Snapshot{
			sessionID:          snapshot.sessionID,
			recoveryGeneration: snapshot.recoveryGeneration,
			appliedChainIndex:  chainIndex,
			devices:            snapshot.devices,
			credentialEpochs:   snapshot.credentialEpochs,
			authorizations:     snapshot.authorizations,
			valid:              true,
		}, nil
	}

	devices := cloneDevices(snapshot.devices)
	seenDevices := make(map[domain.DeviceID]struct{}, len(changes.Devices))
	for _, member := range changes.Devices {
		if _, duplicate := seenDevices[member.ID]; duplicate {
			return nil, invalidSnapshot("duplicate device change %q", member.ID)
		}
		seenDevices[member.ID] = struct{}{}
		member.IdentityPublicKey = bytes.Clone(member.IdentityPublicKey)
		devices[member.ID] = member
	}

	epochs := cloneEpochs(snapshot.credentialEpochs)
	seenCounters := make(map[domain.DeviceID]struct{}, len(changes.AuditCounters))
	for _, counter := range changes.AuditCounters {
		if err := counter.Validate(); err != nil {
			return nil, invalidSnapshot(
				"audit-counter change %q: %v",
				counter.DeviceID,
				err,
			)
		}
		if _, duplicate := seenCounters[counter.DeviceID]; duplicate {
			return nil, invalidSnapshot(
				"duplicate audit-counter change %q",
				counter.DeviceID,
			)
		}
		seenCounters[counter.DeviceID] = struct{}{}
		epochs[counter.DeviceID] = counter.CredentialEpoch
	}

	authorizations := cloneAuthorizations(snapshot.authorizations)
	seenAuthorizations := make(
		map[credentialauthorization.Key]struct{},
		len(changes.CredentialAuthorizations),
	)
	for _, authorization := range changes.CredentialAuthorizations {
		key := authorization.PrimaryKey()
		if _, duplicate := seenAuthorizations[key]; duplicate {
			return nil, invalidSnapshot(
				"duplicate credential-authorization change %q/%d",
				key.DeviceID,
				key.Epoch,
			)
		}
		seenAuthorizations[key] = struct{}{}
		authorizations[key] = authorization.Clone()
	}

	return newSnapshot(
		snapshot.sessionID,
		snapshot.recoveryGeneration,
		chainIndex,
		devices,
		epochs,
		authorizations,
	)
}

// Lineage returns the exact applied session and recovery generation.
func (snapshot *Snapshot) Lineage() (domain.UUIDv7, uint64, bool) {
	if snapshot == nil || !snapshot.valid {
		return "", 0, false
	}
	return snapshot.sessionID, snapshot.recoveryGeneration, true
}

// AppliedChainIndex returns the accepted-event position covered by this cut.
func (snapshot *Snapshot) AppliedChainIndex() (uint64, bool) {
	if snapshot == nil || !snapshot.valid {
		return 0, false
	}
	return snapshot.appliedChainIndex, true
}

// Member returns an independent copy of one applied membership row.
func (snapshot *Snapshot) Member(
	deviceID domain.DeviceID,
) (device.Device, bool) {
	if snapshot == nil || !snapshot.valid {
		return device.Device{}, false
	}
	member, exists := snapshot.devices[deviceID]
	if !exists {
		return device.Device{}, false
	}
	member.IdentityPublicKey = bytes.Clone(member.IdentityPublicKey)
	return member, true
}

// CurrentCredentialEpoch returns the latest committed epoch for one member.
func (snapshot *Snapshot) CurrentCredentialEpoch(
	deviceID domain.DeviceID,
) (uint64, bool) {
	if snapshot == nil || !snapshot.valid {
		return 0, false
	}
	epoch, exists := snapshot.credentialEpochs[deviceID]
	return epoch, exists
}

// Authorization returns an independent copy of a retained current or prior
// credential authorization.
func (snapshot *Snapshot) Authorization(
	key credentialauthorization.Key,
) (credentialauthorization.Authorization, bool) {
	if snapshot == nil || !snapshot.valid {
		return credentialauthorization.Authorization{}, false
	}
	authorization, exists := snapshot.authorizations[key]
	if !exists {
		return credentialauthorization.Authorization{}, false
	}
	return authorization.Clone(), true
}

// AuthorizationByEpochDigest resolves one retained authorization and its
// enrolled member for bounded discovery verification.
func (snapshot *Snapshot) AuthorizationByEpochDigest(
	epoch uint64,
	keyDigest [sha256.Size]byte,
) (
	credentialauthorization.Authorization,
	device.Device,
	bool,
) {
	if snapshot == nil ||
		!snapshot.valid ||
		epoch < 1 ||
		!domain.ValidUnsignedInteger(epoch) {
		return credentialauthorization.Authorization{},
			device.Device{},
			false
	}
	var (
		foundAuthorization credentialauthorization.Authorization
		foundMember        device.Device
		found              bool
	)
	for key, authorization := range snapshot.authorizations {
		if key.SessionID != snapshot.sessionID ||
			key.Epoch != epoch ||
			authorization.KeyDigest != keyDigest {
			continue
		}
		if found {
			return credentialauthorization.Authorization{},
				device.Device{},
				false
		}
		member, exists := snapshot.devices[key.DeviceID]
		if !exists {
			return credentialauthorization.Authorization{},
				device.Device{},
				false
		}
		foundAuthorization = authorization.Clone()
		member.IdentityPublicKey = bytes.Clone(member.IdentityPublicKey)
		foundMember = member
		found = true
	}
	return foundAuthorization, foundMember, found
}

// ActiveCredentialAuthorizationAt returns an active member's greatest
// retained epoch that is valid at the exact supplied instant. Before a
// committed successor reaches not_before, its overlap predecessor remains
// the active credential.
func (snapshot *Snapshot) ActiveCredentialAuthorizationAt(
	deviceID domain.DeviceID,
	at time.Time,
) (credentialauthorization.Authorization, bool) {
	if snapshot == nil ||
		!snapshot.valid ||
		!deviceID.Valid() ||
		at.IsZero() ||
		!snapshot.sessionID.Valid() ||
		!domain.ValidUnsignedInteger(snapshot.appliedChainIndex) {
		return credentialauthorization.Authorization{}, false
	}
	member, exists := snapshot.devices[deviceID]
	if !exists ||
		member.ID != deviceID ||
		member.Status != device.StatusActive ||
		member.Validate() != nil {
		return credentialauthorization.Authorization{}, false
	}
	epoch, exists := snapshot.credentialEpochs[deviceID]
	if !exists ||
		epoch == 0 ||
		!domain.ValidUnsignedInteger(epoch) {
		return credentialauthorization.Authorization{}, false
	}
	currentKey := credentialauthorization.Key{
		SessionID: snapshot.sessionID,
		DeviceID:  deviceID,
		Epoch:     epoch,
	}
	current, valid := snapshot.appliedAuthorization(currentKey)
	if !valid {
		return credentialauthorization.Authorization{}, false
	}
	if current.ActiveAt(at) {
		return current, true
	}
	if epoch == 1 {
		return credentialauthorization.Authorization{}, false
	}
	previous, valid := snapshot.appliedAuthorization(
		credentialauthorization.Key{
			SessionID: snapshot.sessionID,
			DeviceID:  deviceID,
			Epoch:     epoch - 1,
		},
	)
	if !valid || !previous.ActiveAt(at) {
		return credentialauthorization.Authorization{}, false
	}
	return previous, true
}

func (snapshot *Snapshot) appliedAuthorization(
	key credentialauthorization.Key,
) (credentialauthorization.Authorization, bool) {
	authorization, exists := snapshot.authorizations[key]
	if !exists ||
		authorization.PrimaryKey() != key ||
		authorization.AuthorizationChainIndex > snapshot.appliedChainIndex ||
		authorization.Validate() != nil {
		return credentialauthorization.Authorization{}, false
	}
	return authorization.Clone(), true
}

func newSnapshot(
	sessionID domain.UUIDv7,
	recoveryGeneration uint64,
	appliedChainIndex uint64,
	devices map[domain.DeviceID]device.Device,
	epochs map[domain.DeviceID]uint64,
	authorizations map[credentialauthorization.Key]credentialauthorization.Authorization,
) (*Snapshot, error) {
	if !sessionID.Valid() ||
		!domain.ValidUnsignedInteger(recoveryGeneration) ||
		!domain.ValidUnsignedInteger(appliedChainIndex) ||
		len(devices) == 0 ||
		len(devices) != len(epochs) {
		return nil, ErrInvalidSnapshot
	}
	for id, member := range devices {
		if id != member.ID {
			return nil, invalidSnapshot("device map key does not match row")
		}
		if err := member.Validate(); err != nil {
			return nil, invalidSnapshot("device %q: %v", id, err)
		}
		epoch, exists := epochs[id]
		if !exists || !domain.ValidUnsignedInteger(epoch) {
			return nil, invalidSnapshot(
				"device %q has no valid credential epoch",
				id,
			)
		}
	}
	for id := range epochs {
		if _, exists := devices[id]; !exists {
			return nil, invalidSnapshot(
				"credential epoch references missing device %q",
				id,
			)
		}
	}

	retained := make(
		map[credentialauthorization.Key]credentialauthorization.Authorization,
		len(devices)*2,
	)
	for key, authorization := range authorizations {
		if key != authorization.PrimaryKey() {
			return nil, invalidSnapshot(
				"credential-authorization map key does not match row",
			)
		}
		if err := authorization.Validate(); err != nil {
			return nil, invalidSnapshot(
				"credential authorization %q/%d: %v",
				key.DeviceID,
				key.Epoch,
				err,
			)
		}
		if authorization.AuthorizationChainIndex > appliedChainIndex {
			return nil, invalidSnapshot(
				"credential authorization %q/%d is not applied",
				key.DeviceID,
				key.Epoch,
			)
		}
		if authorization.SessionID != sessionID {
			continue
		}
		currentEpoch, exists := epochs[key.DeviceID]
		if !exists || key.Epoch > currentEpoch {
			return nil, invalidSnapshot(
				"credential authorization references an absent or future member epoch",
			)
		}
		if key.Epoch == currentEpoch ||
			currentEpoch > 1 && key.Epoch == currentEpoch-1 {
			retained[key] = authorization.Clone()
		}
	}
	for id, epoch := range epochs {
		if epoch == 0 {
			continue
		}
		key := credentialauthorization.Key{
			SessionID: sessionID,
			DeviceID:  id,
			Epoch:     epoch,
		}
		if _, exists := retained[key]; !exists {
			return nil, invalidSnapshot(
				"device %q lacks its current credential authorization",
				id,
			)
		}
	}

	return &Snapshot{
		sessionID:          sessionID,
		recoveryGeneration: recoveryGeneration,
		appliedChainIndex:  appliedChainIndex,
		devices:            devices,
		credentialEpochs:   epochs,
		authorizations:     retained,
		valid:              true,
	}, nil
}

func cloneDevices(
	source map[domain.DeviceID]device.Device,
) map[domain.DeviceID]device.Device {
	result := make(map[domain.DeviceID]device.Device, len(source))
	for id, member := range source {
		member.IdentityPublicKey = bytes.Clone(member.IdentityPublicKey)
		result[id] = member
	}
	return result
}

func cloneEpochs(source map[domain.DeviceID]uint64) map[domain.DeviceID]uint64 {
	result := make(map[domain.DeviceID]uint64, len(source))
	for id, epoch := range source {
		result[id] = epoch
	}
	return result
}

func cloneAuthorizations(
	source map[credentialauthorization.Key]credentialauthorization.Authorization,
) map[credentialauthorization.Key]credentialauthorization.Authorization {
	result := make(
		map[credentialauthorization.Key]credentialauthorization.Authorization,
		len(source),
	)
	for key, authorization := range source {
		result[key] = authorization.Clone()
	}
	return result
}

func invalidSnapshot(format string, arguments ...any) error {
	values := make([]any, 1, len(arguments)+1)
	values[0] = ErrInvalidSnapshot
	values = append(values, arguments...)
	return fmt.Errorf("%w: "+format, values...)
}
