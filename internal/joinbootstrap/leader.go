package joinbootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/transport"
)

type bootstrapPeer struct {
	deviceID          domain.DeviceID
	identityPublicKey ed25519.PublicKey
	routes            *pinnedEndpoints
}

type bootstrapLeaderConnection struct {
	peer    bootstrapPeer
	control *transport.ConsensusBootstrapClient
	status  consensus.ConsensusStatusResult
}

type bootstrapLeaderResolver func(
	context.Context,
	pendingJournal,
	*pinnedEndpoints,
	tls.Certificate,
) (*bootstrapLeaderConnection, error)

func resolveInitialBootstrapLeader(
	ctx context.Context,
	statePath string,
	journal *pendingJournal,
	inviterRoutes *pinnedEndpoints,
	identityCertificate tls.Certificate,
) (*bootstrapLeaderConnection, error) {
	if journal == nil {
		return nil, ErrBootstrapMismatch
	}
	if journal.Phase != journalPhaseDecisionApproved {
		return waitForBootstrapLeader(
			ctx,
			*journal,
			inviterRoutes,
			identityCertificate,
		)
	}
	return resolveDecisionApprovedBootstrapLeader(
		ctx,
		statePath,
		journal,
		inviterRoutes,
		identityCertificate,
		resolveBootstrapLeaderOnce,
	)
}

func resolveDecisionApprovedBootstrapLeader(
	ctx context.Context,
	statePath string,
	journal *pendingJournal,
	inviterRoutes *pinnedEndpoints,
	identityCertificate tls.Certificate,
	resolve bootstrapLeaderResolver,
) (*bootstrapLeaderConnection, error) {
	if journal == nil ||
		journal.Phase != journalPhaseDecisionApproved ||
		resolve == nil {
		return nil, ErrBootstrapMismatch
	}
	if journal.Mode == pairing.ModeRebootstrap {
		return nil, abandonAmbiguousRebootstrap(statePath, nil)
	}
	leader, err := resolve(
		ctx,
		*journal,
		inviterRoutes,
		identityCertificate,
	)
	if err != nil {
		if errors.Is(err, ErrBootstrapUnavailable) ||
			errors.Is(err, consensus.ErrConsensusStatusRejected) {
			return nil, errors.Join(ErrJoinIncomplete, err)
		}
		return nil, err
	}
	journal.Phase = journalPhaseConfirmed
	if err := writePendingJournal(statePath, *journal); err != nil {
		return nil, errors.Join(err, leader.Close())
	}
	return leader, nil
}

func waitForBootstrapLeader(
	ctx context.Context,
	journal pendingJournal,
	inviterRoutes *pinnedEndpoints,
	identityCertificate tls.Certificate,
) (*bootstrapLeaderConnection, error) {
	for {
		leader, err := resolveBootstrapLeaderOnce(
			ctx,
			journal,
			inviterRoutes,
			identityCertificate,
		)
		if err == nil {
			return leader, nil
		}
		if !errors.Is(err, ErrBootstrapUnavailable) {
			return nil, err
		}
		timer := time.NewTimer(joinSnapshotRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func resolveBootstrapLeaderOnce(
	ctx context.Context,
	journal pendingJournal,
	inviterRoutes *pinnedEndpoints,
	identityCertificate tls.Certificate,
) (*bootstrapLeaderConnection, error) {
	if ctx == nil ||
		inviterRoutes == nil ||
		inviterRoutes.peer != journal.InviterDeviceID {
		return nil, ErrBootstrapMismatch
	}
	current := bootstrapPeer{
		deviceID: journal.InviterDeviceID,
		identityPublicKey: bytes.Clone(
			journal.InviterIdentityPublicKey[:],
		),
		routes: inviterRoutes,
	}
	visited := make(
		map[domain.DeviceID]struct{},
		int(policy.MaxMemberDevices),
	)
	for range int(policy.MaxMemberDevices) {
		if _, duplicate := visited[current.deviceID]; duplicate {
			return nil, ErrBootstrapUnavailable
		}
		visited[current.deviceID] = struct{}{}

		control, err := openBootstrapControl(
			journal,
			current,
			identityCertificate,
		)
		if err != nil {
			return nil, err
		}
		status, err := consensus.RequestConsensusStatus(
			ctx,
			control,
			current.deviceID,
		)
		if err != nil {
			closeErr := control.Close()
			if errors.Is(err, consensus.ErrConsensusStatusUnavailable) {
				return nil, errors.Join(
					ErrBootstrapUnavailable,
					closeErr,
				)
			}
			return nil, errors.Join(err, closeErr)
		}
		if err := validateJoinConsensusStatus(
			status,
			journal,
			current,
		); err != nil {
			return nil, errors.Join(err, control.Close())
		}
		if status.LeaderDeviceID == nil {
			return nil, errors.Join(
				ErrBootstrapUnavailable,
				control.Close(),
			)
		}
		if *status.LeaderDeviceID == current.deviceID {
			return &bootstrapLeaderConnection{
				peer:    current,
				control: control,
				status:  status,
			}, nil
		}
		next, err := bootstrapLeaderPeerFromStatus(
			status,
			current.routes.dial,
		)
		closeErr := control.Close()
		if err != nil || closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		current = next
	}
	return nil, ErrBootstrapUnavailable
}

func openBootstrapControl(
	journal pendingJournal,
	peer bootstrapPeer,
	identityCertificate tls.Certificate,
) (*transport.ConsensusBootstrapClient, error) {
	if !peer.deviceID.Valid() ||
		len(peer.identityPublicKey) != ed25519.PublicKeySize ||
		peer.routes == nil ||
		peer.routes.peer != peer.deviceID {
		return nil, ErrBootstrapMismatch
	}
	return transport.NewConsensusBootstrapClient(
		transport.ConsensusBootstrapClientOptions{
			LocalDeviceID:       journal.LocalDeviceID,
			PeerDeviceID:        peer.deviceID,
			IdentityCertificate: identityCertificate,
			Endpoints:           peer.routes,
			Dialer:              peer.routes,
			VerifyExpectedPeer: bootstrapPeerIdentityVerifier(
				journal,
				peer,
			),
		},
	)
}

func bootstrapLeaderPeerFromStatus(
	status consensus.ConsensusStatusResult,
	dial func(context.Context, string, string) (net.Conn, error),
) (bootstrapPeer, error) {
	if status.LeaderDeviceID == nil ||
		len(status.LeaderEndpointSet) == 0 {
		return bootstrapPeer{}, ErrBootstrapUnavailable
	}
	leaderID := *status.LeaderDeviceID
	var leaderKey ed25519.PublicKey
	var leaderMember device.Device
	var leaderMemberFound bool
	for _, member := range status.ActiveRoster {
		if member.Device.ID == leaderID {
			leaderKey = bytes.Clone(member.Device.IdentityPublicKey)
			leaderMember = member.Device
			leaderMemberFound = true
			break
		}
	}
	if !leaderMemberFound {
		return bootstrapPeer{}, ErrBootstrapMismatch
	}
	verified, err := discovery.ValidateEndpointSet(
		status.LeaderEndpointSet,
		discovery.EndpointSetExpectation{
			SessionID:          status.SessionID,
			WorkspaceID:        status.WorkspaceID,
			RecoveryGeneration: status.RecoveryGeneration,
			Member:             leaderMember,
			AdvertisementInterval: time.Duration(
				status.AdvertisementIntervalSeconds,
			) * time.Second,
			Now: time.Now().UTC(),
		},
	)
	if err != nil {
		return bootstrapPeer{}, ErrBootstrapMismatch
	}
	value := verified.EndpointSet()
	endpoints := make([]netip.AddrPort, len(value.Endpoints))
	for index, endpoint := range value.Endpoints {
		endpoints[index] = netip.AddrPortFrom(
			endpoint.IP,
			endpoint.Port,
		)
	}
	routes, err := newPinnedEndpoints(leaderID, endpoints, dial)
	if err != nil {
		return bootstrapPeer{}, ErrBootstrapMismatch
	}
	return bootstrapPeer{
		deviceID:          leaderID,
		identityPublicKey: leaderKey,
		routes:            routes,
	}, nil
}

func bootstrapPeerIdentityVerifier(
	journal pendingJournal,
	peer bootstrapPeer,
) transport.ExpectedConsensusPeerVerifier {
	return func(
		expected domain.DeviceID,
		certificate transport.IdentityCertificate,
	) error {
		if expected != peer.deviceID {
			return transport.ErrTLSAdmission
		}
		return certificate.VerifyIdentity(
			journal.SessionID,
			journal.RecoveryGeneration,
			peer.deviceID,
			peer.identityPublicKey,
		)
	}
}

func (connection *bootstrapLeaderConnection) Close() error {
	if connection == nil || connection.control == nil {
		return nil
	}
	err := connection.control.Close()
	connection.control = nil
	return err
}
