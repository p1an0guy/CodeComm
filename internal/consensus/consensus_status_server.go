package consensus

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/transport"
)

var (
	errConsensusStatusDenied = errors.New(
		"consensus: consensus status requester is not authorized",
	)
	errConsensusStatusRequestBody = errors.New(
		"consensus: consensus status request must have no body",
	)
	errConsensusStatusRequestMedia = errors.New(
		"consensus: consensus status request has media metadata",
	)
	consensusStatusProblemInvalid = consensusProofProblemDefinition{
		code:  "invalid_consensus_status_request",
		title: "Invalid consensus status request",
	}
	consensusStatusProblemForbidden = consensusProofProblemDefinition{
		code:  "consensus_status_forbidden",
		title: "Consensus status request forbidden",
	}
	consensusStatusProblemUnavailable = consensusProofProblemDefinition{
		code:      "consensus_status_unavailable",
		title:     "Consensus status unavailable",
		retryable: true,
	}
)

func (node *SingleNode) serveConsensusStatus(
	writer http.ResponseWriter,
	request *http.Request,
	peer transport.AuthenticatedPeer,
) {
	if err := validateConsensusStatusHTTPRequest(request); err != nil {
		if errors.Is(err, errConsensusStatusRequestMedia) {
			writeConsensusProofProblem(
				writer,
				http.StatusUnsupportedMediaType,
				proofProblemMediaType,
			)
			return
		}
		writeConsensusProofProblem(
			writer,
			http.StatusBadRequest,
			consensusStatusProblemInvalid,
		)
		return
	}
	status, now, err := node.consensusStatusResult(
		request.Context(),
		peer,
	)
	if err != nil {
		switch {
		case errors.Is(err, errConsensusStatusDenied):
			writeConsensusProofProblem(
				writer,
				http.StatusForbidden,
				consensusStatusProblemForbidden,
			)
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded),
			errors.Is(err, ErrNodeClosed),
			errors.Is(err, ErrConsensusAuthorizationUnavailable),
			errors.Is(err, ErrPeerAdmissionUnavailable):
			writeConsensusProofProblem(
				writer,
				http.StatusServiceUnavailable,
				consensusStatusProblemUnavailable,
			)
		default:
			writeConsensusProofProblem(
				writer,
				http.StatusServiceUnavailable,
				consensusStatusProblemUnavailable,
			)
		}
		return
	}
	response, err := encodeConsensusStatusResponse(status, now)
	if err != nil {
		writeConsensusProofProblem(
			writer,
			http.StatusInternalServerError,
			proofProblemInternal,
		)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response)
}

func validateConsensusStatusHTTPRequest(request *http.Request) error {
	if request == nil ||
		request.Method != http.MethodGet ||
		request.URL == nil ||
		request.URL.Path != consensusStatusPath ||
		request.URL.RawPath != "" ||
		request.URL.RawQuery != "" ||
		request.URL.Fragment != "" ||
		request.URL.RawFragment != "" ||
		request.URL.ForceQuery {
		return ErrInvalidConsensusStatus
	}
	if request.Header.Get("Content-Type") != "" ||
		request.Header.Get("Content-Encoding") != "" {
		return errConsensusStatusRequestMedia
	}
	if request.ContentLength != 0 ||
		len(request.TransferEncoding) != 0 {
		return errConsensusStatusRequestBody
	}
	if request.Body == nil {
		return nil
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, 1))
	if err != nil {
		if requestErr := request.Context().Err(); requestErr != nil {
			return requestErr
		}
		return errConsensusStatusRequestBody
	}
	if len(body) != 0 {
		return errConsensusStatusRequestBody
	}
	return nil
}

func (node *SingleNode) consensusStatusResult(
	ctx context.Context,
	peer transport.AuthenticatedPeer,
) (ConsensusStatusResult, time.Time, error) {
	if node == nil ||
		node.raft == nil ||
		node.fsm == nil ||
		node.state == nil ||
		ctx == nil {
		return ConsensusStatusResult{}, time.Time{},
			ErrConsensusAuthorizationUnavailable
	}
	if peer.Plane != transport.PlaneConsensus ||
		!peer.SessionID.Valid() ||
		!peer.DeviceID.Valid() ||
		!domain.ValidUnsignedInteger(peer.RecoveryGeneration) {
		return ConsensusStatusResult{}, time.Time{},
			errConsensusStatusDenied
	}
	if err := ctx.Err(); err != nil {
		return ConsensusStatusResult{}, time.Time{}, err
	}
	if err := node.beginOperation(); err != nil {
		return ConsensusStatusResult{}, time.Time{}, err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return ConsensusStatusResult{}, time.Time{},
			ErrConsensusAuthorizationUnavailable
	}

	for range consensusAuthorizationReadAttempts {
		before := node.consensusStatusAdmissionPublication()
		if before == nil || before.snapshot == nil || before.revision == 0 {
			continue
		}
		view, err := node.state.View(ctx)
		if err != nil {
			return ConsensusStatusResult{}, time.Time{}, err
		}
		configuration := node.effectiveConsensusStatusConfiguration()
		termBefore, err := raftTerm(node.raft.Stats())
		if err != nil {
			continue
		}
		leaderAddress, leaderID := node.raft.LeaderWithID()
		now := node.consensusStatusTime()
		termAfter, err := raftTerm(node.raft.Stats())
		if err != nil {
			continue
		}
		after := node.consensusStatusAdmissionPublication()
		afterConfiguration := node.effectiveConsensusStatusConfiguration()
		if before != after ||
			before.revision != view.AdmissionRevision ||
			termBefore != termAfter ||
			!sameConsensusStatusConfiguration(
				configuration,
				afterConfiguration,
			) ||
			now.IsZero() {
			continue
		}

		sessionID, recoveryGeneration, valid :=
			before.snapshot.Lineage()
		authority, authorityValid :=
			before.snapshot.CredentialAuthority()
		requester, requesterExists :=
			before.snapshot.Member(peer.DeviceID)
		localDeviceID := domain.DeviceID(node.serverID)
		local, localExists := before.snapshot.Member(localDeviceID)
		if !valid ||
			view.SessionID != sessionID ||
			!view.WorkspaceID.Valid() ||
			!authorityValid ||
			authority.SessionID != sessionID ||
			view.RecoveryGeneration != recoveryGeneration {
			continue
		}
		if peer.SessionID != sessionID ||
			peer.RecoveryGeneration != recoveryGeneration ||
			!requesterExists ||
			requester.Status != device.StatusActive {
			return ConsensusStatusResult{}, time.Time{},
				errConsensusStatusDenied
		}
		if !localExists || local.Status != device.StatusActive {
			return ConsensusStatusResult{}, time.Time{},
				ErrConsensusAuthorizationUnavailable
		}
		authorization, found :=
			before.snapshot.ActiveCredentialAuthorizationAt(
				localDeviceID,
				now,
			)
		if !found ||
			authorization.SessionID != sessionID ||
			authorization.DeviceID != localDeviceID {
			return ConsensusStatusResult{}, time.Time{},
				ErrConsensusAuthorizationUnavailable
		}
		quorum, leader, err := consensusStatusConfiguration(
			configuration,
			localDeviceID,
			leaderAddress,
			leaderID,
		)
		if err != nil {
			return ConsensusStatusResult{}, time.Time{},
				ErrConsensusAuthorizationUnavailable
		}
		if view.CurrentTerm != nil && *view.CurrentTerm > termAfter {
			continue
		}
		result := ConsensusStatusResult{
			SessionID:                      sessionID,
			WorkspaceID:                    view.WorkspaceID,
			RecoveryGeneration:             recoveryGeneration,
			ServerDeviceID:                 localDeviceID,
			LocalTerm:                      termAfter,
			LeaderDeviceID:                 leader,
			QuorumRequired:                 quorum,
			LastRaftAppliedLogIndex:        cloneOptionalUint64(view.LastRaftAppliedLogIndex),
			CredentialAuthority:            authority,
			ContentCredentialAuthorization: authorization,
		}
		if err := validateConsensusStatusResult(
			result,
			localDeviceID,
			now,
			true,
		); err != nil {
			return ConsensusStatusResult{}, time.Time{},
				ErrConsensusAuthorizationUnavailable
		}
		return cloneConsensusStatusResult(result), now, nil
	}
	return ConsensusStatusResult{}, time.Time{},
		ErrConsensusAuthorizationUnavailable
}

func (node *SingleNode) consensusStatusAdmissionPublication() (
	publication *peerAdmissionPublication,
) {
	if node == nil || node.fsm == nil {
		return nil
	}
	node.fsm.admissionMu.Lock()
	publication = node.fsm.admission.Load()
	node.fsm.admissionMu.Unlock()
	return publication
}

func (node *SingleNode) consensusStatusTime() time.Time {
	if node == nil || node.credentialEndorsementNow == nil {
		return time.Time{}
	}
	return node.credentialEndorsementNow()
}

func (node *SingleNode) effectiveConsensusStatusConfiguration() (
	configuration *committedRaftConfiguration,
) {
	if node == nil || node.fsm == nil {
		return nil
	}
	configuration = node.fsm.committedConfiguration()
	if configuration == nil && node.transportGate != nil {
		configuration = node.transportGate.effectiveConfiguration(node)
	}
	return configuration
}

func sameConsensusStatusConfiguration(
	left *committedRaftConfiguration,
	right *committedRaftConfiguration,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Index == right.Index &&
		sameRaftConfiguration(
			left.Configuration,
			right.Configuration,
		)
}

func consensusStatusConfiguration(
	configuration *committedRaftConfiguration,
	localDeviceID domain.DeviceID,
	leaderAddress raft.ServerAddress,
	leaderID raft.ServerID,
) (uint64, *domain.DeviceID, error) {
	if configuration == nil ||
		configuration.Index < 1 ||
		!domain.ValidUnsignedInteger(configuration.Index) ||
		!localDeviceID.Valid() ||
		len(configuration.Configuration.Servers) < 1 ||
		len(configuration.Configuration.Servers) >
			int(policy.MaxMemberDevices) {
		return 0, nil, ErrInvalidRaftTopology
	}
	seen := make(
		map[domain.DeviceID]struct{},
		len(configuration.Configuration.Servers),
	)
	voters := make(map[domain.DeviceID]struct{})
	for _, server := range configuration.Configuration.Servers {
		deviceID := domain.DeviceID(server.ID)
		if !deviceID.Valid() ||
			server.Address != raft.ServerAddress(deviceID) {
			return 0, nil, ErrInvalidRaftTopology
		}
		if _, duplicate := seen[deviceID]; duplicate {
			return 0, nil, ErrInvalidRaftTopology
		}
		seen[deviceID] = struct{}{}
		switch server.Suffrage {
		case raft.Voter:
			voters[deviceID] = struct{}{}
		case raft.Nonvoter:
		default:
			return 0, nil, ErrInvalidRaftTopology
		}
	}
	if _, localVoter := voters[localDeviceID]; !localVoter {
		return 0, nil, ErrConsensusAuthorizationUnavailable
	}
	if len(voters) == 0 {
		return 0, nil, ErrInvalidRaftTopology
	}
	var leader *domain.DeviceID
	switch {
	case leaderID == "" && leaderAddress == "":
	case leaderID == "" || leaderAddress == "":
		return 0, nil, ErrInvalidRaftTopology
	default:
		deviceID := domain.DeviceID(leaderID)
		if !deviceID.Valid() ||
			leaderAddress != raft.ServerAddress(deviceID) {
			return 0, nil, ErrInvalidRaftTopology
		}
		if _, leaderVoter := voters[deviceID]; !leaderVoter {
			return 0, nil, ErrInvalidRaftTopology
		}
		leader = &deviceID
	}
	return uint64(len(voters)/2 + 1), leader, nil
}
