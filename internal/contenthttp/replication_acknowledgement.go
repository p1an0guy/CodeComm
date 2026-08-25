package contenthttp

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/replication"
)

const ReplicationAcknowledgementPath = "/v1/replication/acknowledgement"

func (handler *connectionHandler) serveReplicationAcknowledgement(
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
	atResult, valid := replicationAcknowledgementCursor(request)
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
	acknowledgement, err :=
		handler.server.service.ReplicationAcknowledgement(
			callContext,
			atResult,
		)
	if err != nil {
		writeReplicationProblem(writer, err)
		return
	}
	metadata := acknowledgement.Unsigned().Metadata()
	if metadata.SessionID != handler.peer.SessionID ||
		metadata.ResultIndex != atResult ||
		metadata.ServerAppliedResultIndex != atResult {
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
		return
	}
	encoded := acknowledgement.CanonicalBytes()
	if len(encoded) == 0 || len(encoded) > replication.MaxAcknowledgementBytes {
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
		return
	}
	writeJSONHeader(
		writer,
		http.StatusOK,
		contentJSONMediaType,
		len(encoded),
	)
	_, _ = writer.Write(encoded)
}

func replicationAcknowledgementCursor(
	request *http.Request,
) (uint64, bool) {
	return exactReplicationCursor(
		request,
		ReplicationAcknowledgementPath,
		"at_result=",
	)
}

// ReplicationAcknowledgement returns one signed current-head observation
// after Session binds this client to the peer's lineage.
func (client *Client) ReplicationAcknowledgement(
	ctx context.Context,
	atResult uint64,
) (replication.Acknowledgement, error) {
	if client == nil ||
		ctx == nil ||
		!domain.ValidUnsignedInteger(atResult) {
		return replication.Acknowledgement{}, ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return replication.Acknowledgement{}, err
	}
	client.operationMu.Lock()
	defer client.operationMu.Unlock()

	lineage, err := client.replicationLineage()
	if err != nil {
		return replication.Acknowledgement{}, err
	}
	target := ReplicationAcknowledgementPath + "?at_result=" +
		strconv.FormatUint(atResult, 10)
	body, err := client.requestBounded(
		ctx,
		http.MethodGet,
		target,
		nil,
		nil,
		int64(replication.MaxAcknowledgementBytes),
	)
	if err != nil {
		return replication.Acknowledgement{},
			normalizeClientReplicationError(err)
	}
	acknowledgement, err := replication.ParseAcknowledgement(body)
	if err != nil {
		client.invalidate()
		return replication.Acknowledgement{}, fmt.Errorf(
			"%w: parse replication acknowledgement: %w",
			ErrResponseProtocol,
			err,
		)
	}
	metadata := acknowledgement.Unsigned().Metadata()
	switch {
	case metadata.SessionID != lineage.sessionID,
		metadata.WorkspaceID != lineage.workspaceID,
		metadata.RecoveryGeneration != lineage.recoveryGeneration:
		client.invalidate()
		return replication.Acknowledgement{}, ErrLineageMismatch
	case metadata.ResultIndex != atResult ||
		metadata.ServerAppliedResultIndex != atResult:
		client.invalidate()
		return replication.Acknowledgement{}, ErrResponseProtocol
	}
	return acknowledgement, nil
}

func validClientReplicationAcknowledgementTarget(target string) bool {
	const prefix = ReplicationAcknowledgementPath + "?at_result="
	return validCanonicalUnsignedTarget(target, prefix)
}

func validCanonicalUnsignedTarget(target, prefix string) bool {
	if len(target) <= len(prefix) || target[:len(prefix)] != prefix {
		return false
	}
	value := target[len(prefix):]
	if len(value) > 1 && value[0] == '0' {
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
