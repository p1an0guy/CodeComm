package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	consensusStatusPath                    = "/v1/consensus/status"
	consensusStatusSchemaVersion    uint64 = 4
	consensusStatusBootstrapRowsMax        = 1_024
)

var (
	ErrInvalidConsensusStatus = errors.New(
		"consensus: invalid consensus status",
	)
	ErrConsensusStatusUnavailable = errors.New(
		"consensus: consensus status unavailable",
	)
	ErrConsensusStatusRejected = errors.New(
		"consensus: consensus status request rejected",
	)
	ErrConsensusStatusMismatch = errors.New(
		"consensus: consensus status response mismatch",
	)
)

type consensusStatusResponseWire struct {
	SchemaVersion                    uint64                         `json:"schema_version"`
	SessionID                        string                         `json:"session_id"`
	WorkspaceID                      string                         `json:"workspace_id"`
	RecoveryGeneration               uint64                         `json:"recovery_generation"`
	ServerDeviceID                   string                         `json:"server_device_id"`
	LocalTerm                        uint64                         `json:"local_term"`
	LeaderDeviceID                   *string                        `json:"leader_device_id"`
	LeaderEndpointSet                *string                        `json:"leader_endpoint_set"`
	AdvertisementIntervalSeconds     int64                          `json:"advertisement_interval_seconds"`
	QuorumRequired                   uint64                         `json:"quorum_required"`
	LastRaftAppliedLogIndex          *uint64                        `json:"last_raft_applied_log_index"`
	MembershipAppliedChainIndex      uint64                         `json:"membership_applied_chain_index"`
	RequesterMembership              consensusStatusMemberWire      `json:"requester_membership"`
	ActiveRoster                     []consensusStatusMemberWire    `json:"active_roster"`
	RequesterCredentialAuthorization *credentialRenewalResponseWire `json:"requester_credential_authorization"`
	CredentialAuthority              consensusStatusAuthorityWire   `json:"credential_authority"`
	ContentCredentialAuthorization   credentialRenewalResponseWire  `json:"content_credential_authorization"`
	GenerationZeroState              consensusStatusBootstrapWire   `json:"generation_zero_state"`
}

type consensusStatusMemberWire struct {
	DeviceID               string `json:"device_id"`
	Role                   string `json:"role"`
	IdentityPublicKey      string `json:"identity_public_key"`
	DaemonVersion          string `json:"daemon_version"`
	MaxApplyLevel          uint64 `json:"max_apply_level"`
	Status                 string `json:"status"`
	EntityVersion          uint64 `json:"entity_version"`
	CurrentCredentialEpoch uint64 `json:"current_credential_epoch"`
}

type consensusStatusAuthorityWire struct {
	SessionID                   string            `json:"session_id"`
	VoterDeviceIDs              []string          `json:"voter_device_ids"`
	VoterSetVersion             uint64            `json:"voter_set_version"`
	ActivationSource            string            `json:"activation_source"`
	ActivationCheckpointEventID *string           `json:"activation_checkpoint_event_id"`
	ActivationProofs            []json.RawMessage `json:"activation_proofs"`
	PriorAuthoritySigner        *string           `json:"prior_authority_signer"`
	PriorAuthorityHandoff       *string           `json:"prior_authority_handoff"`
}

type consensusStatusBootstrapWire struct {
	SessionID               string                            `json:"session_id"`
	WorkspaceID             string                            `json:"workspace_id"`
	GenesisJSON             string                            `json:"genesis_json"`
	DigestVersion           uint64                            `json:"digest_version"`
	ProjectionSchemaVersion uint64                            `json:"projection_schema_version"`
	ProjectionStateDigest   string                            `json:"projection_state_digest"`
	ProjectionRows          []consensusStatusBootstrapRowWire `json:"projection_rows"`
}

type consensusStatusBootstrapRowWire struct {
	Table      string `json:"table"`
	PrimaryKey string `json:"primary_key"`
	Row        string `json:"row"`
}

// ConsensusStatusResult is one peer-pinned identity-plane bootstrap cut.
// The caller still verifies any authority handoff and authorization signatures
// against its own applied state before provisional use.
type ConsensusStatusResult struct {
	SessionID                        domain.UUIDv7
	WorkspaceID                      domain.UUIDv4
	RecoveryGeneration               uint64
	ServerDeviceID                   domain.DeviceID
	LocalTerm                        uint64
	LeaderDeviceID                   *domain.DeviceID
	LeaderEndpointSet                []byte
	AdvertisementIntervalSeconds     int64
	QuorumRequired                   uint64
	LastRaftAppliedLogIndex          *uint64
	MembershipAppliedChainIndex      uint64
	RequesterMembership              ConsensusStatusMember
	ActiveRoster                     []ConsensusStatusMember
	RequesterCredentialAuthorization *credentialauthorization.Authorization
	CredentialAuthority              credentialauthority.Authority
	ContentCredentialAuthorization   credentialauthorization.Authorization
	GenerationZeroState              store.StateView
}

// ConsensusStatusMember binds one active membership row to its current
// credential counter at the response's applied-chain cut.
type ConsensusStatusMember struct {
	Device                 device.Device
	CurrentCredentialEpoch uint64
}

// ConsensusStatusRequester sends the bodyless identity-authenticated request.
type ConsensusStatusRequester interface {
	RequestConsensusStatus(
		context.Context,
		domain.DeviceID,
	) (transport.ConsensusControlResponse, error)
}

// RequestConsensusStatus fetches and strictly validates one peer's bounded
// late-wake bootstrap cut.
func RequestConsensusStatus(
	ctx context.Context,
	requester ConsensusStatusRequester,
	peerDeviceID domain.DeviceID,
) (ConsensusStatusResult, error) {
	return requestConsensusStatusWithClock(
		ctx,
		requester,
		peerDeviceID,
		time.Now,
	)
}

// RequestConsensusStatusAt fetches and validates one peer status at the
// caller's captured credential time. Long-running runtimes use the same clock
// for certificate selection, verification, and this late-wake bootstrap cut.
func RequestConsensusStatusAt(
	ctx context.Context,
	requester ConsensusStatusRequester,
	peerDeviceID domain.DeviceID,
	now time.Time,
) (ConsensusStatusResult, error) {
	return requestConsensusStatusAt(
		ctx,
		requester,
		peerDeviceID,
		now,
	)
}

func requestConsensusStatusAt(
	ctx context.Context,
	requester ConsensusStatusRequester,
	peerDeviceID domain.DeviceID,
	now time.Time,
) (ConsensusStatusResult, error) {
	return requestConsensusStatusWithClock(
		ctx,
		requester,
		peerDeviceID,
		func() time.Time { return now },
	)
}

func requestConsensusStatusWithClock(
	ctx context.Context,
	requester ConsensusStatusRequester,
	peerDeviceID domain.DeviceID,
	now func() time.Time,
) (ConsensusStatusResult, error) {
	if ctx == nil ||
		requester == nil ||
		!peerDeviceID.Valid() ||
		now == nil {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	if err := ctx.Err(); err != nil {
		return ConsensusStatusResult{}, err
	}
	response, err := requester.RequestConsensusStatus(ctx, peerDeviceID)
	if err != nil {
		return ConsensusStatusResult{}, fmt.Errorf(
			"%w: %w",
			ErrConsensusStatusUnavailable,
			err,
		)
	}
	if response.StatusCode != http.StatusOK {
		if response.MediaType != "application/problem+json" {
			return ConsensusStatusResult{}, ErrInvalidConsensusStatus
		}
		problem, err := decodeConsensusStatusProblem(
			response.Body,
			response.StatusCode,
		)
		if err != nil {
			return ConsensusStatusResult{}, err
		}
		classification := ErrConsensusStatusRejected
		if problem.Retryable {
			classification = ErrConsensusStatusUnavailable
		}
		return ConsensusStatusResult{}, fmt.Errorf(
			"%w: remote code %s, HTTP status %d",
			classification,
			problem.Code,
			response.StatusCode,
		)
	}
	if response.MediaType != "application/json" {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	receivedAt := now()
	if receivedAt.IsZero() {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	return decodeConsensusStatusResponse(
		response.Body,
		peerDeviceID,
		receivedAt,
	)
}

func encodeConsensusStatusResponse(
	status ConsensusStatusResult,
	now time.Time,
) ([]byte, error) {
	return encodeConsensusStatusResponseForUse(status, now, true)
}

func encodeConsensusStatusResponseForUse(
	status ConsensusStatusResult,
	now time.Time,
	serverActive bool,
) ([]byte, error) {
	if err := validateConsensusStatusResult(
		status,
		status.ServerDeviceID,
		now,
		serverActive,
	); err != nil {
		return nil, err
	}
	authorization, err := credentialAuthorizationToWire(
		status.ContentCredentialAuthorization,
	)
	if err != nil {
		return nil, ErrInvalidConsensusStatus
	}
	authority, err := consensusStatusAuthorityToWire(
		status.CredentialAuthority,
	)
	if err != nil {
		return nil, ErrInvalidConsensusStatus
	}
	bootstrap, err := consensusStatusBootstrapToWire(
		status.GenerationZeroState,
	)
	if err != nil {
		return nil, ErrInvalidConsensusStatus
	}
	requester, err := consensusStatusMemberToWire(
		status.RequesterMembership,
	)
	if err != nil {
		return nil, ErrInvalidConsensusStatus
	}
	roster := make(
		[]consensusStatusMemberWire,
		len(status.ActiveRoster),
	)
	for index, member := range status.ActiveRoster {
		roster[index], err = consensusStatusMemberToWire(member)
		if err != nil {
			return nil, ErrInvalidConsensusStatus
		}
	}
	var requesterAuthorization *credentialRenewalResponseWire
	if status.RequesterCredentialAuthorization != nil {
		encoded, encodeErr := credentialAuthorizationToWire(
			*status.RequesterCredentialAuthorization,
		)
		if encodeErr != nil {
			return nil, ErrInvalidConsensusStatus
		}
		requesterAuthorization = &encoded
	}
	wire := consensusStatusResponseWire{
		SchemaVersion:                    consensusStatusSchemaVersion,
		SessionID:                        string(status.SessionID),
		WorkspaceID:                      string(status.WorkspaceID),
		RecoveryGeneration:               status.RecoveryGeneration,
		ServerDeviceID:                   string(status.ServerDeviceID),
		LocalTerm:                        status.LocalTerm,
		LeaderDeviceID:                   encodeOptionalDeviceID(status.LeaderDeviceID),
		LeaderEndpointSet:                encodeOptionalBytes(status.LeaderEndpointSet),
		AdvertisementIntervalSeconds:     status.AdvertisementIntervalSeconds,
		QuorumRequired:                   status.QuorumRequired,
		LastRaftAppliedLogIndex:          cloneOptionalUint64(status.LastRaftAppliedLogIndex),
		MembershipAppliedChainIndex:      status.MembershipAppliedChainIndex,
		RequesterMembership:              requester,
		ActiveRoster:                     roster,
		RequesterCredentialAuthorization: requesterAuthorization,
		CredentialAuthority:              authority,
		ContentCredentialAuthorization:   authorization,
		GenerationZeroState:              bootstrap,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, ErrInvalidConsensusStatus
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil ||
		len(canonical) == 0 ||
		len(canonical) > transport.ConsensusControlBodyMaxBytes {
		return nil, ErrInvalidConsensusStatus
	}
	return bytes.Clone(canonical), nil
}

func decodeConsensusStatusResponse(
	encoded []byte,
	expectedServerDeviceID domain.DeviceID,
	now time.Time,
) (ConsensusStatusResult, error) {
	var wire consensusStatusResponseWire
	if err := decodeCanonicalConsensusStatus(encoded, &wire); err != nil {
		return ConsensusStatusResult{}, err
	}
	authorization, err := credentialAuthorizationFromWire(
		wire.ContentCredentialAuthorization,
	)
	if err != nil {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	authority, err := consensusStatusAuthorityFromWire(
		wire.CredentialAuthority,
	)
	if err != nil {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	bootstrap, err := consensusStatusBootstrapFromWire(
		wire.GenerationZeroState,
	)
	if err != nil {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	requester, err := consensusStatusMemberFromWire(
		wire.RequesterMembership,
	)
	if err != nil {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	roster := make([]ConsensusStatusMember, len(wire.ActiveRoster))
	for index, encoded := range wire.ActiveRoster {
		roster[index], err = consensusStatusMemberFromWire(encoded)
		if err != nil {
			return ConsensusStatusResult{}, ErrInvalidConsensusStatus
		}
	}
	var requesterAuthorization *credentialauthorization.Authorization
	if wire.RequesterCredentialAuthorization != nil {
		value, decodeErr := credentialAuthorizationFromWire(
			*wire.RequesterCredentialAuthorization,
		)
		if decodeErr != nil {
			return ConsensusStatusResult{}, ErrInvalidConsensusStatus
		}
		requesterAuthorization = &value
	}
	leaderEndpointSet, err := decodeOptionalBytes(
		wire.LeaderEndpointSet,
		discovery.MaxEndpointSetBytes,
	)
	if err != nil {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	status := ConsensusStatusResult{
		SessionID:                        domain.UUIDv7(wire.SessionID),
		WorkspaceID:                      domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration:               wire.RecoveryGeneration,
		ServerDeviceID:                   domain.DeviceID(wire.ServerDeviceID),
		LocalTerm:                        wire.LocalTerm,
		LeaderDeviceID:                   decodeOptionalDeviceID(wire.LeaderDeviceID),
		LeaderEndpointSet:                leaderEndpointSet,
		AdvertisementIntervalSeconds:     wire.AdvertisementIntervalSeconds,
		QuorumRequired:                   wire.QuorumRequired,
		LastRaftAppliedLogIndex:          cloneOptionalUint64(wire.LastRaftAppliedLogIndex),
		MembershipAppliedChainIndex:      wire.MembershipAppliedChainIndex,
		RequesterMembership:              requester,
		ActiveRoster:                     roster,
		RequesterCredentialAuthorization: requesterAuthorization,
		CredentialAuthority:              authority,
		ContentCredentialAuthorization:   authorization,
		GenerationZeroState:              bootstrap,
	}
	if err := validateConsensusStatusResult(
		status,
		expectedServerDeviceID,
		now,
		false,
	); err != nil {
		return ConsensusStatusResult{}, err
	}
	expected, err := encodeConsensusStatusResponseForUse(
		status,
		now,
		false,
	)
	if err != nil || !bytes.Equal(expected, encoded) {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	return cloneConsensusStatusResult(status), nil
}

func validateConsensusStatusResult(
	status ConsensusStatusResult,
	expectedServerDeviceID domain.DeviceID,
	now time.Time,
	serverActive bool,
) error {
	maximumQuorum := uint64(policy.MaxMemberDevices/2 + 1)
	advertisementInterval := time.Duration(
		status.AdvertisementIntervalSeconds,
	) * time.Second
	if !expectedServerDeviceID.Valid() ||
		!status.SessionID.Valid() ||
		!status.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(status.RecoveryGeneration) ||
		status.ServerDeviceID != expectedServerDeviceID ||
		status.LocalTerm < 1 ||
		!domain.ValidUnsignedInteger(status.LocalTerm) ||
		status.QuorumRequired < 1 ||
		status.QuorumRequired > maximumQuorum ||
		status.LeaderDeviceID != nil &&
			!(*status.LeaderDeviceID).Valid() ||
		status.AdvertisementIntervalSeconds <
			policy.MinAdvertisementIntervalSeconds ||
		status.AdvertisementIntervalSeconds >
			policy.MaxAdvertisementIntervalSeconds ||
		status.LastRaftAppliedLogIndex != nil &&
			(*status.LastRaftAppliedLogIndex < 1 ||
				!domain.ValidUnsignedInteger(
					*status.LastRaftAppliedLogIndex,
				)) {
		return ErrConsensusStatusMismatch
	}
	authority := status.CredentialAuthority
	if authority.Validate() != nil ||
		authority.SessionID != status.SessionID {
		return ErrConsensusStatusMismatch
	}
	if !validConsensusStatusMembership(
		status,
		advertisementInterval,
		now,
	) {
		return ErrConsensusStatusMismatch
	}
	authorization := status.ContentCredentialAuthorization
	if authorization.Validate() != nil ||
		authorization.SessionID != status.SessionID ||
		authorization.DeviceID != status.ServerDeviceID ||
		authorization.AuthorityVoterSetVersion >
			authority.VoterSetVersion ||
		!consensusStatusAuthorizationUsableAt(
			authorization,
			now,
			serverActive,
		) {
		return ErrConsensusStatusMismatch
	}
	if err := validateConsensusStatusBootstrap(
		status.GenerationZeroState,
	); err != nil ||
		status.GenerationZeroState.WorkspaceID != status.WorkspaceID ||
		status.RecoveryGeneration == 0 &&
			status.GenerationZeroState.SessionID != status.SessionID {
		return ErrConsensusStatusMismatch
	}
	return nil
}

func validConsensusStatusMembership(
	status ConsensusStatusResult,
	advertisementInterval time.Duration,
	now time.Time,
) bool {
	if !domain.ValidUnsignedInteger(status.MembershipAppliedChainIndex) ||
		len(status.ActiveRoster) < 1 ||
		len(status.ActiveRoster) > int(policy.MaxMemberDevices) ||
		!validConsensusStatusMember(status.RequesterMembership) {
		return false
	}
	var (
		requesterFound bool
		server         *ConsensusStatusMember
		leader         *ConsensusStatusMember
		authorityFound = make(
			map[domain.DeviceID]bool,
			len(status.CredentialAuthority.VoterDeviceIDs),
		)
	)
	for index, member := range status.ActiveRoster {
		if !validConsensusStatusMember(member) ||
			index > 0 &&
				status.ActiveRoster[index-1].Device.ID >=
					member.Device.ID {
			return false
		}
		if member.Device.ID == status.RequesterMembership.Device.ID {
			if !sameConsensusStatusMember(
				member,
				status.RequesterMembership,
			) {
				return false
			}
			requesterFound = true
		}
		if member.Device.ID == status.ServerDeviceID {
			value := member
			server = &value
		}
		if status.LeaderDeviceID != nil &&
			member.Device.ID == *status.LeaderDeviceID {
			value := member
			leader = &value
		}
		if status.CredentialAuthority.Contains(member.Device.ID) {
			authorityFound[member.Device.ID] = true
		}
	}
	if !requesterFound || server == nil {
		return false
	}
	switch {
	case status.LeaderDeviceID == nil:
		if len(status.LeaderEndpointSet) != 0 {
			return false
		}
	case leader == nil:
		return false
	case *status.LeaderDeviceID == status.ServerDeviceID:
		if len(status.LeaderEndpointSet) != 0 {
			return false
		}
	default:
		if len(status.LeaderEndpointSet) == 0 {
			return false
		}
		if _, err := discovery.ValidateEndpointSet(
			status.LeaderEndpointSet,
			discovery.EndpointSetExpectation{
				SessionID:             status.SessionID,
				WorkspaceID:           status.WorkspaceID,
				RecoveryGeneration:    status.RecoveryGeneration,
				Member:                leader.Device,
				AdvertisementInterval: advertisementInterval,
				Now:                   now,
			},
		); err != nil {
			return false
		}
	}
	for _, voterID := range status.CredentialAuthority.VoterDeviceIDs {
		if !authorityFound[voterID] {
			return false
		}
	}
	requesterEpoch := status.RequesterMembership.CurrentCredentialEpoch
	switch {
	case requesterEpoch == 0:
		if status.RequesterCredentialAuthorization != nil {
			return false
		}
	case status.RequesterCredentialAuthorization == nil:
		return false
	default:
		authorization := *status.RequesterCredentialAuthorization
		if !consensusStatusAuthorizationMatchesMember(
			authorization,
			status.RequesterMembership,
			status.SessionID,
			status.MembershipAppliedChainIndex,
		) || authorization.Epoch != requesterEpoch ||
			authorization.AuthorityVoterSetVersion >
				status.CredentialAuthority.VoterSetVersion {
			return false
		}
	}
	serverAuthorization := status.ContentCredentialAuthorization
	if !consensusStatusAuthorizationMatchesMember(
		serverAuthorization,
		*server,
		status.SessionID,
		status.MembershipAppliedChainIndex,
	) ||
		serverAuthorization.Epoch > server.CurrentCredentialEpoch ||
		server.CurrentCredentialEpoch-serverAuthorization.Epoch > 1 {
		return false
	}
	return true
}

func validConsensusStatusMember(member ConsensusStatusMember) bool {
	return member.Device.Validate() == nil &&
		member.Device.Status == device.StatusActive &&
		domain.ValidUnsignedInteger(member.CurrentCredentialEpoch)
}

func sameConsensusStatusMember(
	left ConsensusStatusMember,
	right ConsensusStatusMember,
) bool {
	return left.CurrentCredentialEpoch == right.CurrentCredentialEpoch &&
		left.Device.ID == right.Device.ID &&
		left.Device.Role == right.Device.Role &&
		bytes.Equal(
			left.Device.IdentityPublicKey,
			right.Device.IdentityPublicKey,
		) &&
		left.Device.DaemonVersion == right.Device.DaemonVersion &&
		left.Device.MaxApplyLevel == right.Device.MaxApplyLevel &&
		left.Device.Status == right.Device.Status &&
		left.Device.EntityVersion == right.Device.EntityVersion
}

func consensusStatusAuthorizationMatchesMember(
	authorization credentialauthorization.Authorization,
	member ConsensusStatusMember,
	sessionID domain.UUIDv7,
	appliedChainIndex uint64,
) bool {
	if authorization.Validate() != nil ||
		authorization.SessionID != sessionID ||
		authorization.DeviceID != member.Device.ID ||
		authorization.AuthorizationChainIndex > appliedChainIndex {
		return false
	}
	binding := credential.Binding{
		SessionID:      authorization.SessionID,
		DeviceID:       authorization.DeviceID,
		Epoch:          authorization.Epoch,
		EpochPublicKey: authorization.EpochPublicKey,
		KeyDigest:      authorization.KeyDigest,
		Signature:      authorization.BindingSignature,
	}
	return binding.Validate(member.Device.IdentityPublicKey) == nil
}

func consensusStatusMemberToWire(
	member ConsensusStatusMember,
) (consensusStatusMemberWire, error) {
	if !validConsensusStatusMember(member) {
		return consensusStatusMemberWire{}, ErrInvalidConsensusStatus
	}
	return consensusStatusMemberWire{
		DeviceID:               string(member.Device.ID),
		Role:                   string(member.Device.Role),
		IdentityPublicKey:      codec.EncodeBase64URL(member.Device.IdentityPublicKey),
		DaemonVersion:          member.Device.DaemonVersion,
		MaxApplyLevel:          member.Device.MaxApplyLevel,
		Status:                 string(member.Device.Status),
		EntityVersion:          member.Device.EntityVersion,
		CurrentCredentialEpoch: member.CurrentCredentialEpoch,
	}, nil
}

func consensusStatusMemberFromWire(
	wire consensusStatusMemberWire,
) (ConsensusStatusMember, error) {
	publicKey, err := codec.DecodeBase64URLExact(
		wire.IdentityPublicKey,
		ed25519.PublicKeySize,
	)
	if err != nil {
		return ConsensusStatusMember{}, ErrInvalidConsensusStatus
	}
	member := ConsensusStatusMember{
		Device: device.Device{
			ID:                domain.DeviceID(wire.DeviceID),
			Role:              device.Role(wire.Role),
			IdentityPublicKey: ed25519.PublicKey(publicKey),
			DaemonVersion:     wire.DaemonVersion,
			MaxApplyLevel:     wire.MaxApplyLevel,
			Status:            device.Status(wire.Status),
			EntityVersion:     wire.EntityVersion,
		},
		CurrentCredentialEpoch: wire.CurrentCredentialEpoch,
	}
	if !validConsensusStatusMember(member) {
		return ConsensusStatusMember{}, ErrInvalidConsensusStatus
	}
	return member, nil
}

func consensusStatusBootstrapToWire(
	view store.StateView,
) (consensusStatusBootstrapWire, error) {
	if err := validateConsensusStatusBootstrap(view); err != nil {
		return consensusStatusBootstrapWire{}, err
	}
	rows := make(
		[]consensusStatusBootstrapRowWire,
		len(view.ProjectionRows),
	)
	for index, row := range view.ProjectionRows {
		rows[index] = consensusStatusBootstrapRowWire{
			Table:      row.Table,
			PrimaryKey: codec.EncodeBase64URL(row.PrimaryKey),
			Row:        codec.EncodeBase64URL(row.Row),
		}
	}
	return consensusStatusBootstrapWire{
		SessionID:               string(view.SessionID),
		WorkspaceID:             string(view.WorkspaceID),
		GenesisJSON:             codec.EncodeBase64URL(view.GenesisJSON),
		DigestVersion:           view.Heads.DigestVersion,
		ProjectionSchemaVersion: view.Heads.ProjectionSchemaVersion,
		ProjectionStateDigest: codec.EncodeBase64URL(
			view.ProjectionStateDigest[:],
		),
		ProjectionRows: rows,
	}, nil
}

func consensusStatusBootstrapFromWire(
	wire consensusStatusBootstrapWire,
) (store.StateView, error) {
	if len(wire.ProjectionRows) > consensusStatusBootstrapRowsMax {
		return store.StateView{}, ErrInvalidConsensusStatus
	}
	genesisJSON, genesisErr := codec.DecodeBase64URL(wire.GenesisJSON)
	stateDigest, digestErr := codec.DecodeBase64URLExact(
		wire.ProjectionStateDigest,
		sha256.Size,
	)
	if genesisErr != nil || digestErr != nil {
		return store.StateView{}, ErrInvalidConsensusStatus
	}
	rows := make([]chain.LogicalRow, len(wire.ProjectionRows))
	for index, encoded := range wire.ProjectionRows {
		primaryKey, primaryErr := codec.DecodeBase64URL(
			encoded.PrimaryKey,
		)
		row, rowErr := codec.DecodeBase64URL(encoded.Row)
		if primaryErr != nil || rowErr != nil {
			return store.StateView{}, ErrInvalidConsensusStatus
		}
		rows[index] = chain.LogicalRow{
			Table:      encoded.Table,
			PrimaryKey: primaryKey,
			Row:        row,
		}
	}
	genesisDigest, err := chain.GenesisDigest(genesisJSON)
	if err != nil {
		return store.StateView{}, ErrInvalidConsensusStatus
	}
	eventSeed, err := chain.EventSeed(
		chain.Boundary{Genesis: genesisDigest},
	)
	if err != nil {
		return store.StateView{}, ErrInvalidConsensusStatus
	}
	resultSeed, err := chain.ResultSeed(
		chain.Boundary{Genesis: genesisDigest},
	)
	if err != nil {
		return store.StateView{}, ErrInvalidConsensusStatus
	}
	var projectionDigest store.Digest
	copy(projectionDigest[:], stateDigest)
	accumulator := chain.AccumulatorSeedInitial(
		genesisDigest,
		chain.Digest(projectionDigest),
	)
	view := store.StateView{
		SessionID:          domain.UUIDv7(wire.SessionID),
		WorkspaceID:        domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration: 0,
		GenesisJSON:        genesisJSON,
		Heads: store.ApplyHeads{
			ChainHash:               store.Digest(eventSeed),
			ResultHash:              store.Digest(resultSeed),
			ProjectionAccumulator:   store.Digest(accumulator),
			DigestVersion:           wire.DigestVersion,
			ProjectionSchemaVersion: wire.ProjectionSchemaVersion,
		},
		ProjectionStateDigest: projectionDigest,
		ProjectionRows:        rows,
	}
	if err := validateConsensusStatusBootstrap(view); err != nil {
		return store.StateView{}, ErrInvalidConsensusStatus
	}
	return view, nil
}

func validateConsensusStatusBootstrap(view store.StateView) error {
	if view.RecoveryGeneration != 0 ||
		view.AdmissionRevision != 0 ||
		view.CurrentTerm != nil ||
		view.LastRaftAppliedLogIndex != nil ||
		view.Heads.ChainIndex != 0 ||
		view.Heads.ResultIndex != 0 ||
		len(view.ProjectionRows) > consensusStatusBootstrapRowsMax {
		return ErrInvalidConsensusStatus
	}
	if _, _, err := decodeReducerStateView(view); err != nil {
		return ErrInvalidConsensusStatus
	}
	genesisDigest, err := chain.GenesisDigest(view.GenesisJSON)
	if err != nil {
		return ErrInvalidConsensusStatus
	}
	eventSeed, eventErr := chain.EventSeed(
		chain.Boundary{Genesis: genesisDigest},
	)
	resultSeed, resultErr := chain.ResultSeed(
		chain.Boundary{Genesis: genesisDigest},
	)
	accumulator := chain.AccumulatorSeedInitial(
		genesisDigest,
		chain.Digest(view.ProjectionStateDigest),
	)
	if eventErr != nil ||
		resultErr != nil ||
		view.Heads.ChainHash != store.Digest(eventSeed) ||
		view.Heads.ResultHash != store.Digest(resultSeed) ||
		view.Heads.ProjectionAccumulator != store.Digest(accumulator) {
		return ErrInvalidConsensusStatus
	}
	return nil
}

func consensusStatusAuthorityToWire(
	authority credentialauthority.Authority,
) (consensusStatusAuthorityWire, error) {
	if authority.Validate() != nil {
		return consensusStatusAuthorityWire{}, ErrInvalidConsensusStatus
	}
	voters := make([]string, len(authority.VoterDeviceIDs))
	for index, deviceID := range authority.VoterDeviceIDs {
		voters[index] = string(deviceID)
	}
	proofs := make(
		[]json.RawMessage,
		len(authority.ActivationProofs),
	)
	for index, proof := range authority.ActivationProofs {
		proofs[index] = bytes.Clone(proof.CanonicalJSON)
	}
	var checkpointEventID *string
	if authority.ActivationCheckpointEventID != "" {
		value := string(authority.ActivationCheckpointEventID)
		checkpointEventID = &value
	}
	var priorSigner *string
	if authority.PriorAuthoritySigner != "" {
		value := string(authority.PriorAuthoritySigner)
		priorSigner = &value
	}
	var handoff *string
	if authority.PriorAuthorityHandoff != nil {
		value := codec.EncodeBase64URL(
			authority.PriorAuthorityHandoff[:],
		)
		handoff = &value
	}
	return consensusStatusAuthorityWire{
		SessionID:                   string(authority.SessionID),
		VoterDeviceIDs:              voters,
		VoterSetVersion:             authority.VoterSetVersion,
		ActivationSource:            string(authority.ActivationSource),
		ActivationCheckpointEventID: checkpointEventID,
		ActivationProofs:            proofs,
		PriorAuthoritySigner:        priorSigner,
		PriorAuthorityHandoff:       handoff,
	}, nil
}

func consensusStatusAuthorityFromWire(
	wire consensusStatusAuthorityWire,
) (credentialauthority.Authority, error) {
	voters := make([]domain.DeviceID, len(wire.VoterDeviceIDs))
	for index, encoded := range wire.VoterDeviceIDs {
		voters[index] = domain.DeviceID(encoded)
	}
	proofs := make(
		[]credentialauthority.ActivationProof,
		len(wire.ActivationProofs),
	)
	for index, encoded := range wire.ActivationProofs {
		var deviceID domain.DeviceID
		if index < len(voters) {
			deviceID = voters[index]
		}
		proofs[index] = credentialauthority.ActivationProof{
			VoterDeviceID: deviceID,
			CanonicalJSON: bytes.Clone(encoded),
		}
	}
	var handoff *[ed25519.SignatureSize]byte
	if wire.PriorAuthorityHandoff != nil {
		decoded, err := codec.DecodeBase64URLExact(
			*wire.PriorAuthorityHandoff,
			ed25519.SignatureSize,
		)
		if err != nil {
			return credentialauthority.Authority{},
				ErrInvalidConsensusStatus
		}
		value := [ed25519.SignatureSize]byte{}
		copy(value[:], decoded)
		handoff = &value
	}
	authority := credentialauthority.Authority{
		SessionID:       domain.UUIDv7(wire.SessionID),
		VoterDeviceIDs:  voters,
		VoterSetVersion: wire.VoterSetVersion,
		ActivationSource: credentialauthority.ActivationSource(
			wire.ActivationSource,
		),
		ActivationCheckpointEventID: domain.UUIDv7(
			optionalString(wire.ActivationCheckpointEventID),
		),
		ActivationProofs: proofs,
		PriorAuthoritySigner: domain.DeviceID(
			optionalString(wire.PriorAuthoritySigner),
		),
		PriorAuthorityHandoff: handoff,
	}
	if authority.Validate() != nil {
		return credentialauthority.Authority{},
			ErrInvalidConsensusStatus
	}
	return authority, nil
}

func consensusStatusAuthorizationUsableAt(
	authorization credentialauthorization.Authorization,
	now time.Time,
	serverActive bool,
) bool {
	if serverActive {
		return authorization.ActiveAt(now)
	}
	if now.IsZero() || authorization.Validate() != nil {
		return false
	}
	notBefore, err := authorization.NotBefore.Time()
	if err != nil {
		return false
	}
	expiresAt := notBefore.Add(
		time.Duration(authorization.ValiditySeconds) * time.Second,
	)
	return !now.Add(credentialEndorsementClockSkew).Before(notBefore) &&
		now.Before(expiresAt)
}

func decodeCanonicalConsensusStatus(encoded []byte, destination any) error {
	if len(encoded) == 0 ||
		len(encoded) > transport.ConsensusControlBodyMaxBytes ||
		destination == nil {
		return ErrInvalidConsensusStatus
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidConsensusStatus
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidConsensusStatus
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidConsensusStatus
	}
	return nil
}

func decodeConsensusStatusProblem(
	encoded []byte,
	status int,
) (consensusProofProblem, error) {
	var members map[string]json.RawMessage
	if err := decodeCanonicalConsensusStatus(encoded, &members); err != nil {
		return consensusProofProblem{}, err
	}
	required := [...]string{
		"type",
		"title",
		"status",
		"code",
		"correlation_id",
		"retryable",
	}
	for _, field := range required {
		if _, exists := members[field]; !exists {
			return consensusProofProblem{}, ErrInvalidConsensusStatus
		}
	}
	if len(members) != len(required) {
		if _, hasDetail := members["detail"]; !hasDetail ||
			len(members) != len(required)+1 {
			return consensusProofProblem{}, ErrInvalidConsensusStatus
		}
	}
	var problem consensusProofProblem
	if err := decodeCanonicalConsensusStatus(encoded, &problem); err != nil {
		return consensusProofProblem{}, err
	}
	if status < http.StatusBadRequest ||
		status > 599 ||
		problem.Status != status ||
		problem.Type != "urn:codecomm:problem:"+problem.Code ||
		!validConsensusProofText(problem.Title, 1, 128) ||
		!validConsensusProofText(problem.CorrelationID, 1, 128) ||
		!validConsensusProofText(problem.Detail, 0, 1024) ||
		!validConsensusStatusProblem(problem) {
		return consensusProofProblem{}, ErrInvalidConsensusStatus
	}
	return problem, nil
}

func validConsensusStatusProblem(problem consensusProofProblem) bool {
	switch problem.Code {
	case "route_not_found":
		return problem.Status == http.StatusNotFound && !problem.Retryable
	case "unsupported_media_type":
		return problem.Status == http.StatusUnsupportedMediaType &&
			!problem.Retryable
	case "invalid_consensus_status_request":
		return problem.Status == http.StatusBadRequest &&
			!problem.Retryable
	case "consensus_status_forbidden":
		return problem.Status == http.StatusForbidden &&
			!problem.Retryable
	case "consensus_status_unavailable":
		return (problem.Status == http.StatusRequestTimeout ||
			problem.Status == http.StatusServiceUnavailable) &&
			problem.Retryable
	case "internal_error":
		return problem.Status == http.StatusInternalServerError &&
			problem.Retryable
	default:
		return false
	}
}

func encodeOptionalDeviceID(value *domain.DeviceID) *string {
	if value == nil {
		return nil
	}
	encoded := string(*value)
	return &encoded
}

func decodeOptionalDeviceID(value *string) *domain.DeviceID {
	if value == nil {
		return nil
	}
	decoded := domain.DeviceID(*value)
	return &decoded
}

func encodeOptionalBytes(value []byte) *string {
	if len(value) == 0 {
		return nil
	}
	encoded := codec.EncodeBase64URL(value)
	return &encoded
}

func decodeOptionalBytes(value *string, maximum int) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	if *value == "" {
		return nil, ErrInvalidConsensusStatus
	}
	decoded, err := codec.DecodeBase64URL(*value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum {
		return nil, ErrInvalidConsensusStatus
	}
	return decoded, nil
}

func cloneOptionalUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneConsensusStatusResult(
	status ConsensusStatusResult,
) ConsensusStatusResult {
	result := status
	if status.LeaderDeviceID != nil {
		leader := *status.LeaderDeviceID
		result.LeaderDeviceID = &leader
	}
	result.LeaderEndpointSet = bytes.Clone(status.LeaderEndpointSet)
	result.LastRaftAppliedLogIndex = cloneOptionalUint64(
		status.LastRaftAppliedLogIndex,
	)
	result.RequesterMembership = cloneConsensusStatusMember(
		status.RequesterMembership,
	)
	result.ActiveRoster = make(
		[]ConsensusStatusMember,
		len(status.ActiveRoster),
	)
	for index, member := range status.ActiveRoster {
		result.ActiveRoster[index] = cloneConsensusStatusMember(member)
	}
	if status.RequesterCredentialAuthorization != nil {
		value := status.RequesterCredentialAuthorization.Clone()
		result.RequesterCredentialAuthorization = &value
	}
	result.CredentialAuthority = status.CredentialAuthority.Clone()
	result.ContentCredentialAuthorization =
		status.ContentCredentialAuthorization.Clone()
	result.GenerationZeroState = cloneConsensusStatusBootstrap(
		status.GenerationZeroState,
	)
	return result
}

func cloneConsensusStatusMember(
	member ConsensusStatusMember,
) ConsensusStatusMember {
	result := member
	result.Device.IdentityPublicKey = bytes.Clone(
		member.Device.IdentityPublicKey,
	)
	return result
}

func cloneConsensusStatusBootstrap(view store.StateView) store.StateView {
	result := view
	result.GenesisJSON = bytes.Clone(view.GenesisJSON)
	result.CurrentTerm = cloneOptionalUint64(view.CurrentTerm)
	result.LastRaftAppliedLogIndex = cloneOptionalUint64(
		view.LastRaftAppliedLogIndex,
	)
	result.ProjectionRows = make(
		[]chain.LogicalRow,
		len(view.ProjectionRows),
	)
	for index, row := range view.ProjectionRows {
		result.ProjectionRows[index] = chain.LogicalRow{
			Table:      row.Table,
			PrimaryKey: bytes.Clone(row.PrimaryKey),
			Row:        bytes.Clone(row.Row),
		}
	}
	return result
}
