package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/peerauth"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
)

var errDaemonSettledCredential = errors.New(
	"codecommd: settled credential renewal failed",
)

type daemonSettledCredentialAdmission interface {
	PeerAdmissionSnapshot() (*peerauth.Snapshot, error)
	Status(context.Context) (coordstatus.Snapshot, error)
}

type daemonSettledCredentialConsensus struct {
	sessionID     domain.UUIDv7
	localDeviceID domain.DeviceID
	admission     daemonSettledCredentialAdmission
	transport     daemonSettledControlTransport
}

func newDaemonSettledCredentialConsensus(
	sessionID domain.UUIDv7,
	localDeviceID domain.DeviceID,
	admission daemonSettledCredentialAdmission,
	control daemonSettledControlTransport,
) (*daemonSettledCredentialConsensus, error) {
	if !sessionID.Valid() ||
		!localDeviceID.Valid() ||
		admission == nil ||
		control == nil {
		return nil, errDaemonSettledCredential
	}
	return &daemonSettledCredentialConsensus{
		sessionID:     sessionID,
		localDeviceID: localDeviceID,
		admission:     admission,
		transport:     control,
	}, nil
}

func (runtime *daemonSettledCredentialConsensus) PeerAdmissionSnapshot() (
	*peerauth.Snapshot,
	error,
) {
	if runtime == nil || runtime.admission == nil {
		return nil, errDaemonSettledCredential
	}
	return runtime.admission.PeerAdmissionSnapshot()
}

func (runtime *daemonSettledCredentialConsensus) RenewCredential(
	ctx context.Context,
	binding credential.Binding,
) (credentialauthorization.Authorization, error) {
	if runtime == nil ||
		runtime.admission == nil ||
		runtime.transport == nil ||
		ctx == nil ||
		binding.SessionID != runtime.sessionID ||
		binding.DeviceID != runtime.localDeviceID {
		return credentialauthorization.Authorization{},
			errDaemonSettledCredential
	}
	if err := ctx.Err(); err != nil {
		return credentialauthorization.Authorization{}, err
	}
	admission, err := runtime.admission.PeerAdmissionSnapshot()
	if err != nil {
		return credentialauthorization.Authorization{}, err
	}
	member, active := admission.Member(runtime.localDeviceID)
	if !active ||
		member.Status != device.StatusActive ||
		binding.Validate(member.IdentityPublicKey) != nil {
		return credentialauthorization.Authorization{},
			errDaemonSettledCredential
	}
	status, err := runtime.admission.Status(ctx)
	if err != nil {
		return credentialauthorization.Authorization{}, err
	}
	authorityIDs := status.Durable.CredentialAuthority.VoterDeviceIDs()
	candidates := make(
		[]domain.DeviceID,
		0,
		len(status.Durable.Members),
	)
	seen := make(map[domain.DeviceID]struct{}, len(status.Durable.Members))
	for _, peerID := range authorityIDs {
		candidates = append(candidates, peerID)
		seen[peerID] = struct{}{}
	}
	for _, candidate := range status.Durable.Members {
		if candidate.Status != device.StatusActive {
			continue
		}
		if _, exists := seen[candidate.ID]; exists {
			continue
		}
		candidates = append(candidates, candidate.ID)
		seen[candidate.ID] = struct{}{}
	}
	attemptErrors := make([]error, 0, len(candidates))
	for _, peerID := range candidates {
		if peerID == runtime.localDeviceID {
			continue
		}
		peer, exists := admission.Member(peerID)
		if !exists || peer.Status != device.StatusActive {
			continue
		}
		authorization, requestErr := consensus.SubmitCredentialRenewal(
			ctx,
			runtime.transport,
			peerID,
			binding,
		)
		if requestErr == nil {
			return authorization, nil
		}
		if err := ctx.Err(); err != nil {
			return credentialauthorization.Authorization{}, err
		}
		attemptErrors = append(attemptErrors, requestErr)
	}
	if len(attemptErrors) == 0 {
		return credentialauthorization.Authorization{},
			fmt.Errorf(
				"%w: no active forwarding peer",
				errDaemonSettledCredential,
			)
	}
	return credentialauthorization.Authorization{}, fmt.Errorf(
		"%w: %w",
		errDaemonSettledCredential,
		errors.Join(attemptErrors...),
	)
}

func (runtime *daemonSettledCredentialConsensus) BeginClose() error {
	if runtime == nil || runtime.transport == nil {
		return errDaemonSettledCredential
	}
	return runtime.transport.BeginClose()
}

func (runtime *daemonSettledCredentialConsensus) Wait() error {
	if runtime == nil || runtime.transport == nil {
		return errDaemonSettledCredential
	}
	return runtime.transport.Wait()
}

var _ phasedDaemonComponent = (*daemonSettledCredentialConsensus)(nil)
