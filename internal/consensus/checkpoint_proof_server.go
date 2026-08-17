package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	consensusProofRequestTimeout = 30 * time.Second
	consensusProofNoProgress     = 30 * time.Second
)

var (
	errConsensusProofDenied = errors.New(
		"consensus: checkpoint proof requester is not authorized",
	)
	errConsensusProofNotApplied = errors.New(
		"consensus: requested checkpoint is not applied",
	)
	errConsensusProofStale = errors.New(
		"consensus: requested checkpoint predates staging",
	)
	errConsensusProofMismatch = errors.New(
		"consensus: requested checkpoint differs from applied checkpoint",
	)
	errConsensusProofBodyTooLarge = errors.New(
		"consensus: checkpoint proof body is too large",
	)
	errConsensusProofBodyTimeout = errors.New(
		"consensus: checkpoint proof body made no progress",
	)
)

type stagingProofAuthority struct {
	term                   uint64
	configurationIndex     uint64
	leaderDeviceID         domain.DeviceID
	requesterEntityVersion uint64
	targetEntityVersion    uint64
}

func (gate *nodeTransportGate) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if gate == nil || request == nil {
		writeConsensusProofProblem(
			writer,
			http.StatusServiceUnavailable,
			proofProblemUnavailable,
		)
		return
	}
	node, err := gate.activeNode()
	if err != nil {
		writeConsensusProofProblem(
			writer,
			http.StatusServiceUnavailable,
			proofProblemUnavailable,
		)
		return
	}
	node.serveConsensusControl(writer, request)
}

func (node *SingleNode) serveConsensusControl(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if node == nil || request == nil {
		writeConsensusProofProblem(
			writer,
			http.StatusServiceUnavailable,
			proofProblemUnavailable,
		)
		return
	}
	if request.Method != http.MethodPost ||
		request.URL == nil ||
		request.URL.Path != consensusProofPath ||
		request.URL.RawPath != "" ||
		request.URL.RawQuery != "" ||
		request.URL.Fragment != "" ||
		request.URL.RawFragment != "" ||
		request.URL.ForceQuery {
		writeConsensusProofProblem(
			writer,
			http.StatusNotFound,
			proofProblemRoute,
		)
		return
	}
	callContext, cancel := context.WithTimeout(
		request.Context(),
		consensusProofRequestTimeout,
	)
	defer cancel()
	request = request.WithContext(callContext)

	peer, ok := transport.AuthenticatedPeerFromContext(request.Context())
	if !ok || peer.Plane != transport.PlaneConsensus {
		writeConsensusProofProblem(
			writer,
			http.StatusForbidden,
			proofProblemForbidden,
		)
		return
	}
	if err := transport.ReauthorizeAuthenticatedPeer(
		request.Context(),
	); err != nil {
		status := http.StatusServiceUnavailable
		problem := proofProblemUnavailable
		if errors.Is(err, transport.ErrPeerAuthorizationDenied) {
			status = http.StatusForbidden
			problem = proofProblemForbidden
		}
		writeConsensusProofProblem(writer, status, problem)
		return
	}
	requestAuthority, err := node.consensusProofRequesterAuthority(peer)
	if err != nil {
		status := http.StatusServiceUnavailable
		problem := proofProblemUnavailable
		if errors.Is(err, errConsensusProofDenied) {
			status = http.StatusForbidden
			problem = proofProblemForbidden
		}
		writeConsensusProofProblem(writer, status, problem)
		return
	}
	if !validConsensusProofContentType(request.Header) {
		writeConsensusProofProblem(
			writer,
			http.StatusUnsupportedMediaType,
			proofProblemMediaType,
		)
		return
	}
	body, err := readConsensusProofBody(writer, request)
	if err != nil {
		switch {
		case errors.Is(err, errConsensusProofBodyTooLarge):
			writeConsensusProofProblem(
				writer,
				http.StatusRequestEntityTooLarge,
				proofProblemBodyTooLarge,
			)
		case errors.Is(err, errConsensusProofBodyTimeout):
			writeConsensusProofProblem(
				writer,
				http.StatusRequestTimeout,
				proofProblemUnavailable,
			)
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			writeConsensusProofProblem(
				writer,
				http.StatusRequestTimeout,
				proofProblemUnavailable,
			)
		default:
			writeConsensusProofProblem(
				writer,
				http.StatusBadRequest,
				proofProblemInvalid,
			)
		}
		return
	}
	proofRequest, err := decodeStagingApplyRequest(body)
	if err != nil {
		writeConsensusProofProblem(
			writer,
			http.StatusBadRequest,
			proofProblemInvalid,
		)
		return
	}

	proof, err := node.proveStagingApply(
		callContext,
		peer,
		proofRequest,
		requestAuthority,
	)
	if err != nil {
		switch {
		case errors.Is(err, errConsensusProofDenied):
			writeConsensusProofProblem(
				writer,
				http.StatusForbidden,
				proofProblemForbidden,
			)
		case errors.Is(err, errConsensusProofNotApplied):
			writeConsensusProofProblem(
				writer,
				http.StatusConflict,
				proofProblemNotApplied,
			)
		case errors.Is(err, errConsensusProofStale):
			writeConsensusProofProblem(
				writer,
				http.StatusConflict,
				proofProblemStale,
			)
		case errors.Is(err, errConsensusProofMismatch):
			writeConsensusProofProblem(
				writer,
				http.StatusConflict,
				proofProblemMismatch,
			)
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded),
			errors.Is(err, ErrNodeClosed),
			errors.Is(err, ErrConsensusAuthorizationUnavailable):
			writeConsensusProofProblem(
				writer,
				http.StatusServiceUnavailable,
				proofProblemUnavailable,
			)
		default:
			writeConsensusProofProblem(
				writer,
				http.StatusInternalServerError,
				proofProblemInternal,
			)
		}
		return
	}
	response, err := encodeStagingApplyResponse(proof)
	if err != nil ||
		len(response) == 0 ||
		len(response) > transport.ConsensusControlBodyMaxBytes {
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

func (node *SingleNode) proveStagingApply(
	ctx context.Context,
	peer transport.AuthenticatedPeer,
	request stagingApplyRequest,
	requestAuthority stagingProofAuthority,
) (stagingApplyProof, error) {
	if node == nil || ctx == nil {
		return stagingApplyProof{}, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return stagingApplyProof{}, err
	}
	if err := node.beginOperation(); err != nil {
		return stagingApplyProof{}, err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return stagingApplyProof{}, err
	}

	before, err := node.stagingProofAuthority(peer, request.targetDeviceID)
	if err != nil {
		return stagingApplyProof{}, err
	}
	if !before.sameRequester(requestAuthority) {
		return stagingApplyProof{}, ErrConsensusAuthorizationUnavailable
	}
	lookup, found, err := node.state.AppliedCheckpoint(
		ctx,
		request.checkpointEventID,
	)
	if err != nil {
		return stagingApplyProof{}, err
	}
	if !found {
		return stagingApplyProof{}, errConsensusProofNotApplied
	}
	if before.configurationIndex >
		lookup.Record.CoveredAppliedLogIndex {
		return stagingApplyProof{}, errConsensusProofStale
	}
	if !bytes.Equal(
		lookup.Record.CheckpointJSON,
		request.checkpointJSON,
	) ||
		lookup.Record.AuthoritySignature != request.checkpointSignature {
		return stagingApplyProof{}, errConsensusProofMismatch
	}
	after, err := node.stagingProofAuthority(peer, request.targetDeviceID)
	if err != nil {
		return stagingApplyProof{}, err
	}
	if before != after {
		return stagingApplyProof{}, ErrConsensusAuthorizationUnavailable
	}
	return stagingApplyProof{
		expectation: stagingCheckpointExpectation{
			targetDeviceID: request.targetDeviceID,
			record:         lookup.Record,
		},
		appliedLogIndex: lookup.AppliedLogIndex,
	}, nil
}

func (node *SingleNode) stagingProofAuthority(
	peer transport.AuthenticatedPeer,
	targetDeviceID domain.DeviceID,
) (stagingProofAuthority, error) {
	return node.checkpointProofAuthority(peer, &targetDeviceID)
}

func (node *SingleNode) consensusProofRequesterAuthority(
	peer transport.AuthenticatedPeer,
) (stagingProofAuthority, error) {
	return node.checkpointProofAuthority(peer, nil)
}

func (node *SingleNode) checkpointProofAuthority(
	peer transport.AuthenticatedPeer,
	targetDeviceID *domain.DeviceID,
) (stagingProofAuthority, error) {
	if node == nil || node.raft == nil || node.fsm == nil ||
		targetDeviceID != nil &&
			(*targetDeviceID != domain.DeviceID(node.serverID) ||
				peer.DeviceID == *targetDeviceID) {
		return stagingProofAuthority{}, errConsensusProofDenied
	}
	admission, err := node.PeerAdmissionSnapshot()
	if err != nil {
		return stagingProofAuthority{}, ErrConsensusAuthorizationUnavailable
	}
	sessionID, recoveryGeneration, ok := admission.Lineage()
	member, memberExists := admission.Member(peer.DeviceID)
	var (
		target       device.Device
		targetExists bool
	)
	if targetDeviceID != nil {
		target, targetExists = admission.Member(*targetDeviceID)
	}
	if !ok ||
		peer.SessionID != sessionID ||
		peer.RecoveryGeneration != recoveryGeneration ||
		!memberExists ||
		member.Status != device.StatusActive ||
		targetDeviceID != nil &&
			(!targetExists || target.Status != device.StatusActive) {
		return stagingProofAuthority{}, errConsensusProofDenied
	}

	beforeTerm, err := raftTerm(node.raft.Stats())
	if err != nil {
		return stagingProofAuthority{}, ErrConsensusAuthorizationUnavailable
	}
	leaderAddress, leaderID := node.raft.LeaderWithID()
	configuration := node.fsm.committedConfiguration()
	afterTerm, err := raftTerm(node.raft.Stats())
	if err != nil ||
		beforeTerm != afterTerm ||
		configuration == nil ||
		configuration.Index < 1 {
		return stagingProofAuthority{},
			ErrConsensusAuthorizationUnavailable
	}
	if leaderID == "" {
		return stagingProofAuthority{},
			ErrConsensusAuthorizationUnavailable
	}
	if leaderID != raft.ServerID(peer.DeviceID) ||
		leaderAddress != raft.ServerAddress(peer.DeviceID) {
		return stagingProofAuthority{}, errConsensusProofDenied
	}

	var requesterVoter, targetNonvoter bool
	for _, server := range configuration.Configuration.Servers {
		deviceID := domain.DeviceID(server.ID)
		if !deviceID.Valid() ||
			server.Address != raft.ServerAddress(deviceID) {
			return stagingProofAuthority{},
				ErrConsensusAuthorizationUnavailable
		}
		switch {
		case deviceID == peer.DeviceID && server.Suffrage == raft.Voter:
			requesterVoter = true
		case targetDeviceID != nil &&
			deviceID == *targetDeviceID &&
			server.Suffrage == raft.Nonvoter:
			targetNonvoter = true
		}
	}
	if !requesterVoter ||
		targetDeviceID != nil && !targetNonvoter {
		return stagingProofAuthority{}, errConsensusProofDenied
	}
	authority := stagingProofAuthority{
		term:                   beforeTerm,
		configurationIndex:     configuration.Index,
		leaderDeviceID:         peer.DeviceID,
		requesterEntityVersion: member.EntityVersion,
	}
	if targetDeviceID != nil {
		authority.targetEntityVersion = target.EntityVersion
	}
	return authority, nil
}

func (authority stagingProofAuthority) sameRequester(
	other stagingProofAuthority,
) bool {
	return authority.term == other.term &&
		authority.configurationIndex == other.configurationIndex &&
		authority.leaderDeviceID == other.leaderDeviceID &&
		authority.requesterEntityVersion ==
			other.requesterEntityVersion
}

func validConsensusProofContentType(header http.Header) bool {
	if header == nil || header.Get("Content-Encoding") != "" {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(
		header.Get("Content-Type"),
	)
	return err == nil &&
		mediaType == "application/json" &&
		len(parameters) == 0
}

func readConsensusProofBody(
	writer http.ResponseWriter,
	request *http.Request,
) ([]byte, error) {
	if request == nil ||
		request.Body == nil ||
		request.ContentLength == 0 {
		return nil, ErrInvalidCheckpointProof
	}
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	if request.ContentLength > transport.ConsensusControlBodyMaxBytes {
		return nil, errConsensusProofBodyTooLarge
	}
	body := http.MaxBytesReader(
		writer,
		request.Body,
		transport.ConsensusControlBodyMaxBytes,
	)
	defer body.Close()

	var timedOut atomic.Bool
	progress := make(chan struct{}, 1)
	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		timer := time.NewTimer(consensusProofNoProgress)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				timedOut.Store(true)
				_ = body.Close()
				return
			case <-progress:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(consensusProofNoProgress)
			case <-request.Context().Done():
				_ = body.Close()
				return
			case <-done:
				return
			}
		}
	}()
	defer func() {
		close(done)
		<-watcherDone
	}()

	buffer := bytes.NewBuffer(make(
		[]byte,
		0,
		consensusProofBodyCapacity(request.ContentLength),
	))
	chunk := make([]byte, 32<<10)
	for {
		count, err := body.Read(chunk)
		if count > 0 {
			_, _ = buffer.Write(chunk[:count])
			select {
			case progress <- struct{}{}:
			default:
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		var maximum *http.MaxBytesError
		switch {
		case timedOut.Load():
			return nil, errConsensusProofBodyTimeout
		case errors.As(err, &maximum):
			return nil, errConsensusProofBodyTooLarge
		default:
			if requestErr := request.Context().Err(); requestErr != nil {
				return nil, requestErr
			}
			return nil, err
		}
	}
	if requestErr := request.Context().Err(); requestErr != nil {
		return nil, requestErr
	}
	if timedOut.Load() {
		return nil, errConsensusProofBodyTimeout
	}
	if buffer.Len() == 0 {
		return nil, ErrInvalidCheckpointProof
	}
	return buffer.Bytes(), nil
}

func consensusProofBodyCapacity(contentLength int64) int {
	if contentLength > 0 &&
		contentLength <= transport.ConsensusControlBodyMaxBytes {
		return int(contentLength)
	}
	return 32 << 10
}

type consensusProofProblemDefinition struct {
	code      string
	title     string
	retryable bool
}

var (
	proofProblemRoute = consensusProofProblemDefinition{
		code: "route_not_found", title: "Route not found",
	}
	proofProblemMediaType = consensusProofProblemDefinition{
		code: "unsupported_media_type", title: "Unsupported media type",
	}
	proofProblemBodyTooLarge = consensusProofProblemDefinition{
		code: "body_too_large", title: "Request body too large",
	}
	proofProblemInvalid = consensusProofProblemDefinition{
		code: "invalid_proof_request", title: "Invalid proof request",
	}
	proofProblemForbidden = consensusProofProblemDefinition{
		code: "proof_forbidden", title: "Proof request forbidden",
	}
	proofProblemNotApplied = consensusProofProblemDefinition{
		code:      "checkpoint_not_applied",
		title:     "Checkpoint not applied",
		retryable: true,
	}
	proofProblemStale = consensusProofProblemDefinition{
		code: "checkpoint_stale", title: "Checkpoint predates staging",
	}
	proofProblemMismatch = consensusProofProblemDefinition{
		code: "checkpoint_mismatch", title: "Checkpoint mismatch",
	}
	proofProblemUnavailable = consensusProofProblemDefinition{
		code:      "proof_unavailable",
		title:     "Proof service unavailable",
		retryable: true,
	}
	proofProblemInternal = consensusProofProblemDefinition{
		code:      "internal_error",
		title:     "Internal server error",
		retryable: true,
	}
)

func writeConsensusProofProblem(
	writer http.ResponseWriter,
	status int,
	definition consensusProofProblemDefinition,
) {
	if writer == nil {
		return
	}
	correlationID := "unavailable"
	if id, err := uuid.NewV7(); err == nil {
		correlationID = id.String()
	}
	body, err := json.Marshal(consensusProofProblem{
		Type:          "urn:codecomm:problem:" + definition.code,
		Title:         definition.title,
		Status:        status,
		Code:          definition.code,
		CorrelationID: correlationID,
		Retryable:     definition.retryable,
	})
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(
			`{"type":"urn:codecomm:problem:internal_error","title":"Internal server error","status":500,"code":"internal_error","correlation_id":"unavailable","retryable":true}`,
		)
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

var _ http.Handler = (*nodeTransportGate)(nil)
