package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	ConsensusRaftConnectionPoolMax = 3
	ConsensusRaftRPCsInFlightMax   = 2
	// ConsensusRaftOperationTimeout keeps HashiCorp Raft's aggregate
	// snapshot upload, restore, and response deadline no shorter than the
	// maintained stream's no-progress bound.
	ConsensusRaftOperationTimeout = consensusStreamProgress
)

var (
	ErrInvalidConsensusRaftTransport = errors.New(
		"transport: invalid consensus Raft transport options",
	)
	ErrConsensusRaftTargetMismatch = errors.New(
		"transport: Raft server ID and address must name one device",
	)
	ErrConsensusReplicationDenied = errors.New(
		"transport: consensus replication is not authorized",
	)
)

// ConsensusReplicationAuthorizer atomically verifies that the caller is the
// current applied leader, has applied through the committed membership index,
// and may replicate to the target in the live Raft configuration.
type ConsensusReplicationAuthorizer func(domain.DeviceID) error

// ConsensusCommitProbeAuthorizer authorizes the no-op-only AppendEntries class
// used to recover Raft's volatile commit index after restart.
type ConsensusCommitProbeAuthorizer func(domain.DeviceID) error

// ConsensusNetworkTransportOptions configures guarded HashiCorp Raft framing.
type ConsensusNetworkTransportOptions struct {
	Stream               *ConsensusStreamLayer
	LocalServerID        raft.ServerID
	Timeout              time.Duration
	Logger               hclog.Logger
	AuthorizeReplication ConsensusReplicationAuthorizer
	AuthorizeCommitProbe ConsensusCommitProbeAuthorizer
}

// ConsensusNetworkTransport keeps election traffic available while preventing
// log entries and snapshots from bypassing CodeComm's applied-leader gate.
type ConsensusNetworkTransport struct {
	delegate             *raft.NetworkTransport
	control              *ConsensusStreamLayer
	localDeviceID        domain.DeviceID
	authorizeReplication ConsensusReplicationAuthorizer
	authorizeCommitProbe ConsensusCommitProbeAuthorizer
}

// NewConsensusNetworkTransport binds maintained Raft framing to RFC 8441 and
// requires the production leader/apply/live-configuration replication gate.
func NewConsensusNetworkTransport(
	options ConsensusNetworkTransportOptions,
) (*ConsensusNetworkTransport, error) {
	if err := requireExtendedConnectStartup(); err != nil {
		return nil, err
	}
	if options.Stream == nil ||
		options.Timeout < ConsensusRaftOperationTimeout ||
		options.AuthorizeReplication == nil ||
		options.AuthorizeCommitProbe == nil {
		return nil, ErrInvalidConsensusRaftTransport
	}
	if err := options.Stream.openError(); err != nil {
		return nil, err
	}
	localDeviceID := domain.DeviceID(options.LocalServerID)
	if !localDeviceID.Valid() ||
		localDeviceID != options.Stream.localDeviceID {
		return nil, ErrInvalidConsensusRaftTransport
	}
	delegate := raft.NewNetworkTransportWithConfig(
		&raft.NetworkTransportConfig{
			Stream:          options.Stream,
			MaxPool:         ConsensusRaftConnectionPoolMax,
			MaxRPCsInFlight: ConsensusRaftRPCsInFlightMax,
			Timeout:         options.Timeout,
			Logger:          options.Logger,
		},
	)
	return &ConsensusNetworkTransport{
		delegate:             delegate,
		control:              options.Stream,
		localDeviceID:        localDeviceID,
		authorizeReplication: options.AuthorizeReplication,
		authorizeCommitProbe: options.AuthorizeCommitProbe,
	}, nil
}

// RequestConsensusStatus forwards the fixed identity-authenticated status
// route without broadening Raft, proof, or endorsement authorization.
func (transport *ConsensusNetworkTransport) RequestConsensusStatus(
	ctx context.Context,
	deviceID domain.DeviceID,
) (ConsensusControlResponse, error) {
	if transport == nil ||
		transport.delegate == nil ||
		transport.control == nil {
		return ConsensusControlResponse{},
			ErrInvalidConsensusRaftTransport
	}
	return transport.control.RequestConsensusStatus(ctx, deviceID)
}

// RequestConsensusProof forwards the fixed proof route through the same
// authenticated HTTP/2 connection pool used by the Raft stream adapter.
func (transport *ConsensusNetworkTransport) RequestConsensusProof(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (ConsensusControlResponse, error) {
	if transport == nil ||
		transport.delegate == nil ||
		transport.control == nil {
		return ConsensusControlResponse{},
			ErrInvalidConsensusRaftTransport
	}
	return transport.control.RequestConsensusProof(ctx, deviceID, body)
}

// RequestCredentialRenewal forwards the fixed identity-authenticated renewal
// route without broadening Raft or proof-route authorization.
func (transport *ConsensusNetworkTransport) RequestCredentialRenewal(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (ConsensusControlResponse, error) {
	if transport == nil ||
		transport.delegate == nil ||
		transport.control == nil {
		return ConsensusControlResponse{},
			ErrInvalidConsensusRaftTransport
	}
	return transport.control.RequestCredentialRenewal(
		ctx,
		deviceID,
		body,
	)
}

// RequestCredentialEndorsement forwards the fixed credential-time route
// through the authenticated consensus connection pool.
func (transport *ConsensusNetworkTransport) RequestCredentialEndorsement(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (ConsensusControlResponse, error) {
	if transport == nil ||
		transport.delegate == nil ||
		transport.control == nil {
		return ConsensusControlResponse{},
			ErrInvalidConsensusRaftTransport
	}
	return transport.control.RequestCredentialEndorsement(
		ctx,
		deviceID,
		body,
	)
}

// ProbeConsensusPeer forwards an active reachability probe through the
// authenticated consensus connection pool.
func (transport *ConsensusNetworkTransport) ProbeConsensusPeer(
	ctx context.Context,
	deviceID domain.DeviceID,
) (ConsensusPeerReachabilityToken, error) {
	if transport == nil ||
		transport.delegate == nil ||
		transport.control == nil {
		return ConsensusPeerReachabilityToken{},
			ErrInvalidConsensusRaftTransport
	}
	return transport.control.ProbeConsensusPeer(ctx, deviceID)
}

// VerifyConsensusPeerReachability forwards the in-memory token freshness
// check without performing network I/O.
func (transport *ConsensusNetworkTransport) VerifyConsensusPeerReachability(
	token ConsensusPeerReachabilityToken,
) error {
	if transport == nil ||
		transport.delegate == nil ||
		transport.control == nil {
		return ErrInvalidConsensusRaftTransport
	}
	return transport.control.VerifyConsensusPeerReachability(token)
}

// Consumer returns inbound Raft RPCs decoded by the maintained transport.
func (transport *ConsensusNetworkTransport) Consumer() <-chan raft.RPC {
	if transport == nil || transport.delegate == nil {
		return nil
	}
	return transport.delegate.Consumer()
}

// LocalAddr returns the local device ID used as the stable Raft address.
func (transport *ConsensusNetworkTransport) LocalAddr() raft.ServerAddress {
	if transport == nil || transport.delegate == nil {
		return ""
	}
	return transport.delegate.LocalAddr()
}

// AppendEntriesPipeline opens a pipeline whose entry-bearing sends are
// independently authorized immediately before transmission.
func (transport *ConsensusNetworkTransport) AppendEntriesPipeline(
	id raft.ServerID,
	target raft.ServerAddress,
) (raft.AppendPipeline, error) {
	deviceID, err := transport.target(id, target)
	if err != nil {
		return nil, err
	}
	delegate, err := transport.delegate.AppendEntriesPipeline(id, target)
	if err != nil {
		return nil, err
	}
	return &consensusAppendPipeline{
		delegate:  delegate,
		transport: transport,
		target:    deviceID,
	}, nil
}

// AppendEntries sends a heartbeat directly but gates any request carrying log
// entries on current replication authorization.
func (transport *ConsensusNetworkTransport) AppendEntries(
	id raft.ServerID,
	target raft.ServerAddress,
	request *raft.AppendEntriesRequest,
	response *raft.AppendEntriesResponse,
) error {
	deviceID, err := transport.target(id, target)
	if err != nil {
		return err
	}
	if request == nil || response == nil {
		return ErrInvalidConsensusRaftTransport
	}
	if len(request.Entries) > 0 {
		if err := transport.authorizeAppendEntries(
			deviceID,
			request.Entries,
		); err != nil {
			return err
		}
	}
	return transport.delegate.AppendEntries(id, target, request, response)
}

// RequestVote sends an identity-bound Raft vote request.
func (transport *ConsensusNetworkTransport) RequestVote(
	id raft.ServerID,
	target raft.ServerAddress,
	request *raft.RequestVoteRequest,
	response *raft.RequestVoteResponse,
) error {
	if _, err := transport.target(id, target); err != nil {
		return err
	}
	if request == nil || response == nil {
		return ErrInvalidConsensusRaftTransport
	}
	return transport.delegate.RequestVote(id, target, request, response)
}

// RequestPreVote sends an identity-bound Raft pre-vote request.
func (transport *ConsensusNetworkTransport) RequestPreVote(
	id raft.ServerID,
	target raft.ServerAddress,
	request *raft.RequestPreVoteRequest,
	response *raft.RequestPreVoteResponse,
) error {
	if _, err := transport.target(id, target); err != nil {
		return err
	}
	if request == nil || response == nil {
		return ErrInvalidConsensusRaftTransport
	}
	return transport.delegate.RequestPreVote(id, target, request, response)
}

// InstallSnapshot gates all snapshot bytes on current replication
// authorization.
func (transport *ConsensusNetworkTransport) InstallSnapshot(
	id raft.ServerID,
	target raft.ServerAddress,
	request *raft.InstallSnapshotRequest,
	response *raft.InstallSnapshotResponse,
	data io.Reader,
) error {
	deviceID, err := transport.target(id, target)
	if err != nil {
		return err
	}
	if request == nil || response == nil || data == nil {
		return ErrInvalidConsensusRaftTransport
	}
	if err := transport.authorize(deviceID); err != nil {
		return err
	}
	return transport.delegate.InstallSnapshot(
		id,
		target,
		request,
		response,
		&consensusReplicationReader{
			transport: transport,
			target:    deviceID,
			reader:    data,
		},
	)
}

// EncodePeer serializes only an address matching its device server ID.
func (transport *ConsensusNetworkTransport) EncodePeer(
	id raft.ServerID,
	target raft.ServerAddress,
) []byte {
	if transport == nil || transport.delegate == nil {
		return nil
	}
	deviceID := domain.DeviceID(id)
	if !deviceID.Valid() ||
		target != raft.ServerAddress(deviceID) {
		return nil
	}
	return transport.delegate.EncodePeer(id, target)
}

// DecodePeer accepts only a canonical device ID address.
func (transport *ConsensusNetworkTransport) DecodePeer(
	encoded []byte,
) raft.ServerAddress {
	if transport == nil || transport.delegate == nil {
		return ""
	}
	target := transport.delegate.DecodePeer(encoded)
	if !domain.DeviceID(target).Valid() {
		return ""
	}
	return target
}

// SetHeartbeatHandler installs HashiCorp Raft's heartbeat fast path.
func (transport *ConsensusNetworkTransport) SetHeartbeatHandler(
	handler func(raft.RPC),
) {
	if transport != nil && transport.delegate != nil {
		transport.delegate.SetHeartbeatHandler(handler)
	}
}

// TimeoutNow sends an identity-bound leadership-transfer request.
func (transport *ConsensusNetworkTransport) TimeoutNow(
	id raft.ServerID,
	target raft.ServerAddress,
	request *raft.TimeoutNowRequest,
	response *raft.TimeoutNowResponse,
) error {
	if _, err := transport.target(id, target); err != nil {
		return err
	}
	if request == nil || response == nil {
		return ErrInvalidConsensusRaftTransport
	}
	return transport.delegate.TimeoutNow(id, target, request, response)
}

// Close stops the maintained transport and its RFC 8441 stream layer.
func (transport *ConsensusNetworkTransport) Close() error {
	if transport == nil || transport.delegate == nil {
		return nil
	}
	return transport.delegate.Close()
}

func (transport *ConsensusNetworkTransport) target(
	id raft.ServerID,
	target raft.ServerAddress,
) (domain.DeviceID, error) {
	if transport == nil || transport.delegate == nil {
		return "", ErrInvalidConsensusRaftTransport
	}
	deviceID := domain.DeviceID(id)
	if !deviceID.Valid() ||
		domain.DeviceID(target) != deviceID ||
		deviceID == transport.localDeviceID {
		return "", ErrConsensusRaftTargetMismatch
	}
	return deviceID, nil
}

func (transport *ConsensusNetworkTransport) authorize(
	deviceID domain.DeviceID,
) (err error) {
	if transport == nil ||
		transport.authorizeReplication == nil ||
		!deviceID.Valid() {
		return ErrConsensusReplicationDenied
	}
	defer func() {
		if recover() != nil {
			err = ErrConsensusReplicationDenied
		}
	}()
	if err := transport.authorizeReplication(deviceID); err != nil {
		return fmt.Errorf("%w: %w", ErrConsensusReplicationDenied, err)
	}
	return nil
}

func (transport *ConsensusNetworkTransport) authorizeCommitRecovery(
	deviceID domain.DeviceID,
) (err error) {
	if transport == nil ||
		transport.authorizeCommitProbe == nil ||
		!deviceID.Valid() {
		return ErrConsensusReplicationDenied
	}
	defer func() {
		if recover() != nil {
			err = ErrConsensusReplicationDenied
		}
	}()
	if err := transport.authorizeCommitProbe(deviceID); err != nil {
		return fmt.Errorf("%w: %w", ErrConsensusReplicationDenied, err)
	}
	return nil
}

func (transport *ConsensusNetworkTransport) authorizeAppendEntries(
	deviceID domain.DeviceID,
	entries []*raft.Log,
) error {
	if commitProbeEntries(entries) {
		return transport.authorizeCommitRecovery(deviceID)
	}
	return transport.authorize(deviceID)
}

func commitProbeEntries(entries []*raft.Log) bool {
	if len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		if entry == nil || entry.Type != raft.LogNoop {
			return false
		}
	}
	return true
}

type consensusAppendPipeline struct {
	delegate  raft.AppendPipeline
	transport *ConsensusNetworkTransport
	target    domain.DeviceID
}

type consensusReplicationReader struct {
	transport *ConsensusNetworkTransport
	target    domain.DeviceID
	reader    io.Reader
}

func (reader *consensusReplicationReader) Read(buffer []byte) (int, error) {
	if reader == nil || reader.reader == nil {
		return 0, ErrInvalidConsensusRaftTransport
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	if err := reader.transport.authorize(reader.target); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(buffer)
	if count > 0 {
		if authorizationErr := reader.transport.authorize(
			reader.target,
		); authorizationErr != nil {
			return 0, authorizationErr
		}
	}
	return count, err
}

func (pipeline *consensusAppendPipeline) AppendEntries(
	request *raft.AppendEntriesRequest,
	response *raft.AppendEntriesResponse,
) (raft.AppendFuture, error) {
	if pipeline == nil ||
		pipeline.delegate == nil ||
		request == nil ||
		response == nil {
		return nil, ErrInvalidConsensusRaftTransport
	}
	if len(request.Entries) > 0 {
		if err := pipeline.transport.authorizeAppendEntries(
			pipeline.target,
			request.Entries,
		); err != nil {
			_ = pipeline.delegate.Close()
			return nil, err
		}
	}
	return pipeline.delegate.AppendEntries(request, response)
}

func (pipeline *consensusAppendPipeline) Consumer() <-chan raft.AppendFuture {
	if pipeline == nil || pipeline.delegate == nil {
		return nil
	}
	return pipeline.delegate.Consumer()
}

func (pipeline *consensusAppendPipeline) Close() error {
	if pipeline == nil || pipeline.delegate == nil {
		return nil
	}
	return pipeline.delegate.Close()
}

var (
	_ raft.Transport      = (*ConsensusNetworkTransport)(nil)
	_ raft.WithPreVote    = (*ConsensusNetworkTransport)(nil)
	_ raft.WithClose      = (*ConsensusNetworkTransport)(nil)
	_ raft.AppendPipeline = (*consensusAppendPipeline)(nil)
)
