package contenthttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/replication"
)

const ReplicationPath = "/v1/replication"

var (
	ErrInvalidReplicationCursor = errors.New(
		"content HTTP: invalid replication cursor",
	)
	ErrReplicationSnapshotRequired = errors.New(
		"content HTTP: replication snapshot required",
	)
	ErrReplicationUnavailable = errors.New(
		"content HTTP: replication temporarily unavailable",
	)
)

func (handler *connectionHandler) serveReplication(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeProblem(writer, http.StatusMethodNotAllowed, problemMethod)
		return
	}
	if !validBodylessRequest(request) {
		writeProblem(writer, http.StatusBadRequest, problemRequestBody)
		return
	}
	if !validNegotiation(request.Header) {
		writeProblem(writer, http.StatusNotAcceptable, problemNegotiation)
		return
	}
	afterResult, valid := replicationCursor(request)
	if !valid {
		writeProblem(
			writer,
			http.StatusBadRequest,
			problemInvalidReplicationCursor,
		)
		return
	}
	select {
	case handler.server.replicationHandlers <- struct{}{}:
		defer func() { <-handler.server.replicationHandlers }()
	default:
		writer.Header().Set("Retry-After", "1")
		writeProblem(
			writer,
			http.StatusServiceUnavailable,
			problemReplicationUnavailable,
		)
		return
	}

	callContext, cancel := context.WithTimeout(
		request.Context(),
		handler.server.handlerTimeout,
	)
	defer cancel()
	batch, err := handler.server.service.Replication(
		callContext,
		afterResult,
	)
	if err != nil {
		writeReplicationProblem(writer, err)
		return
	}
	metadata := batch.Unsigned().Metadata()
	if metadata.SessionID != handler.peer.SessionID ||
		afterResult == domain.MaxSafeInteger ||
		metadata.FromResultIndex != afterResult+1 {
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
		return
	}
	encodedLen := batch.EncodedLen()
	if encodedLen < 1 || encodedLen > replication.MaxBatchExpandedBytes {
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
		return
	}
	writeJSONHeader(
		writer,
		http.StatusOK,
		contentJSONMediaType,
		encodedLen,
	)
	_ = batch.WriteCanonical(writer)
}

func replicationCursor(request *http.Request) (uint64, bool) {
	if request == nil ||
		request.URL == nil ||
		request.URL.Path != ReplicationPath ||
		!validRequestPath(request) ||
		request.URL.ForceQuery {
		return 0, false
	}
	const prefix = "after_result="
	raw := request.URL.RawQuery
	if !strings.HasPrefix(raw, prefix) {
		return 0, false
	}
	encoded := strings.TrimPrefix(raw, prefix)
	if encoded == "" || len(encoded) > 1 && encoded[0] == '0' {
		return 0, false
	}
	for _, character := range encoded {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(encoded, 10, 64)
	return value, err == nil &&
		domain.ValidUnsignedInteger(value) &&
		raw == prefix+strconv.FormatUint(value, 10)
}

func writeReplicationProblem(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidReplicationCursor):
		writeProblem(
			writer,
			http.StatusBadRequest,
			problemInvalidReplicationCursor,
		)
	case errors.Is(err, ErrReplicationSnapshotRequired):
		writeProblem(
			writer,
			http.StatusConflict,
			problemSnapshotRequired,
		)
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrReplicationUnavailable):
		writeProblem(
			writer,
			http.StatusServiceUnavailable,
			problemReplicationUnavailable,
		)
	default:
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
	}
}

var (
	problemInvalidReplicationCursor = problemDefinition{
		code:  "invalid_replication_cursor",
		title: "Invalid replication cursor",
	}
	problemSnapshotRequired = problemDefinition{
		code:  "snapshot_required",
		title: "Replication snapshot required",
	}
	problemReplicationUnavailable = problemDefinition{
		code:      "replication_unavailable",
		title:     "Replication temporarily unavailable",
		retryable: true,
	}
)

// Replication returns one canonical, link-verified result batch after Session
// binds this client to the peer's lineage. Signature and signer authorization
// remain untrusted until terminal scratch replay establishes the named
// identity key and active authority.
func (client *Client) Replication(
	ctx context.Context,
	afterResult uint64,
) (replication.Batch, error) {
	if client == nil ||
		ctx == nil ||
		!domain.ValidUnsignedInteger(afterResult) {
		return replication.Batch{}, ErrInvalidClient
	}
	client.operationMu.Lock()
	defer client.operationMu.Unlock()

	lineage, err := client.replicationLineage()
	if err != nil {
		return replication.Batch{}, err
	}
	target := ReplicationPath + "?after_result=" +
		strconv.FormatUint(afterResult, 10)
	body, err := client.requestBounded(
		ctx,
		http.MethodGet,
		target,
		nil,
		nil,
		int64(replication.MaxBatchExpandedBytes),
	)
	if err != nil {
		return replication.Batch{}, err
	}
	batch, err := replication.ParseBatch(body)
	if err != nil {
		client.invalidate()
		return replication.Batch{}, fmt.Errorf(
			"%w: parse replication batch: %w",
			ErrResponseProtocol,
			err,
		)
	}
	metadata := batch.Unsigned().Metadata()
	switch {
	case metadata.SessionID != lineage.sessionID,
		metadata.WorkspaceID != lineage.workspaceID,
		metadata.RecoveryGeneration != lineage.recoveryGeneration:
		client.invalidate()
		return replication.Batch{}, ErrLineageMismatch
	case afterResult == domain.MaxSafeInteger ||
		metadata.FromResultIndex != afterResult+1:
		client.invalidate()
		return replication.Batch{}, ErrResponseProtocol
	}
	return batch, nil
}

type replicationClientLineage struct {
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
}

func (client *Client) replicationLineage() (
	replicationClientLineage,
	error,
) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || client.http2 == nil || client.raw == nil {
		return replicationClientLineage{}, ErrClientClosed
	}
	if !client.lineageSet ||
		!client.sessionBound ||
		!client.peerBinding.SessionID.Valid() ||
		!client.peerBinding.DeviceID.Valid() ||
		!client.workspaceID.Valid() ||
		!domain.ValidUnsignedInteger(client.recoveryGeneration) {
		return replicationClientLineage{}, ErrLineageMismatch
	}
	return replicationClientLineage{
		sessionID:          client.peerBinding.SessionID,
		workspaceID:        client.workspaceID,
		recoveryGeneration: client.recoveryGeneration,
	}, nil
}

func validClientReplicationTarget(target string) bool {
	const prefix = ReplicationPath + "?after_result="
	if !strings.HasPrefix(target, prefix) {
		return false
	}
	value := strings.TrimPrefix(target, prefix)
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil &&
		domain.ValidUnsignedInteger(parsed) &&
		target == prefix+strconv.FormatUint(parsed, 10)
}
