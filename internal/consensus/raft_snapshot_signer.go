package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
)

var ErrInvalidRaftSnapshotSigner = errors.New(
	"consensus: invalid Raft snapshot signer",
)

// RaftSnapshotSigner is a device-identity capability used only to sign the
// logical root embedded in a locally created Raft snapshot.
type RaftSnapshotSigner interface {
	DeviceID() domain.DeviceID
	PublicKey() ed25519.PublicKey
	SignRoot(
		context.Context,
		logicalsnapshot.UnsignedRoot,
	) (logicalsnapshot.Root, error)
}

// RaftSnapshotSignerAdapter adapts a device-bound signing function without
// exposing private key material to consensus.
type RaftSnapshotSignerAdapter struct {
	SignerDeviceID  domain.DeviceID
	SignerPublicKey ed25519.PublicKey
	Sign            func(
		context.Context,
		logicalsnapshot.UnsignedRoot,
	) (logicalsnapshot.Root, error)
}

func (adapter RaftSnapshotSignerAdapter) DeviceID() domain.DeviceID {
	return adapter.SignerDeviceID
}

func (adapter RaftSnapshotSignerAdapter) PublicKey() ed25519.PublicKey {
	return bytes.Clone(adapter.SignerPublicKey)
}

func (adapter RaftSnapshotSignerAdapter) SignRoot(
	ctx context.Context,
	unsigned logicalsnapshot.UnsignedRoot,
) (logicalsnapshot.Root, error) {
	if ctx == nil ||
		adapter.Sign == nil ||
		validateRaftSnapshotSignerIdentity(
			adapter.SignerDeviceID,
			adapter.SignerPublicKey,
		) != nil {
		return logicalsnapshot.Root{}, ErrInvalidRaftSnapshotSigner
	}
	if err := ctx.Err(); err != nil {
		return logicalsnapshot.Root{}, err
	}
	return adapter.Sign(ctx, unsigned)
}

func normalizedRaftSnapshotSigner(
	signer RaftSnapshotSigner,
) RaftSnapshotSigner {
	if signer == nil {
		return nil
	}
	value := reflect.ValueOf(signer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil
		}
	}
	return signer
}

func validateRaftSnapshotSigner(
	deviceID domain.DeviceID,
	signer RaftSnapshotSigner,
) error {
	signer = normalizedRaftSnapshotSigner(signer)
	if signer == nil {
		return nil
	}
	if signer.DeviceID() != deviceID {
		return ErrInvalidRaftSnapshotSigner
	}
	return validateRaftSnapshotSignerIdentity(
		signer.DeviceID(),
		signer.PublicKey(),
	)
}

func validateRaftSnapshotSignerIdentity(
	deviceID domain.DeviceID,
	publicKey ed25519.PublicKey,
) error {
	derived, err := device.DeriveID(publicKey)
	if err != nil || derived != deviceID {
		return ErrInvalidRaftSnapshotSigner
	}
	return nil
}
