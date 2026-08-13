package reducer

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/controlfile"
	"github.com/ijonahch/codecomm/internal/domain/controlpath"
)

const (
	CodeControlFilePathMismatch Code = "control_file_path_mismatch"
	CodeControlFilePathRequired Code = "control_file_path_required"
)

var controlFilePayloadFields = [...]string{
	"path",
	"operation",
	"content_digest",
	"content_size",
	"diff",
}

func decodeControlFileProposal(
	context reductionContext,
) (controlfile.Proposal, Code) {
	canonical, err := codec.CanonicalizeSignedObject(context.proposal.Payload)
	if err != nil || !bytes.Equal(canonical, context.proposal.Payload) {
		return controlfile.Proposal{}, CodeInvalidPayload
	}
	var payload payloadObject
	if err := json.Unmarshal(canonical, &payload); err != nil || payload == nil {
		return controlfile.Proposal{}, CodeInvalidPayload
	}
	allowed := make(map[string]struct{}, len(controlFilePayloadFields))
	for _, field := range controlFilePayloadFields {
		allowed[field] = struct{}{}
	}
	for field := range payload {
		if _, exists := allowed[field]; !exists {
			return controlfile.Proposal{}, CodeUnknownPayloadField
		}
	}
	for _, field := range controlFilePayloadFields {
		if _, exists := payload[field]; !exists {
			return controlfile.Proposal{}, CodeMissingPayloadField
		}
		if field != "content_digest" &&
			bytes.Equal(payload[field], []byte("null")) {
			return controlfile.Proposal{}, CodeInvalidPayload
		}
	}

	pathText, pathOK := decodeValue[string](payload, "path")
	operationText, operationOK := decodeValue[string](payload, "operation")
	contentSize, sizeOK := decodeValue[uint64](payload, "content_size")
	diff, diffOK := decodeValue[string](payload, "diff")
	if !pathOK || !operationOK || !sizeOK || !diffOK {
		return controlfile.Proposal{}, CodeInvalidPayload
	}
	path := domain.RepositoryPath(pathText)
	entityPath, _ := context.proposal.EntityID.Value()
	if pathText != entityPath {
		return controlfile.Proposal{}, CodeControlFilePathMismatch
	}
	if !controlpath.IsControlledV1(path) {
		return controlfile.Proposal{}, CodeControlFilePathRequired
	}

	var digest *controlfile.SHA256Digest
	if !bytes.Equal(payload["content_digest"], []byte("null")) {
		digestText, ok := decodeValue[string](payload, "content_digest")
		digestBytes, err := codec.DecodeBase64URLExact(
			digestText,
			sha256.Size,
		)
		if !ok || err != nil {
			return controlfile.Proposal{}, CodeInvalidPayload
		}
		value := controlfile.SHA256Digest{}
		copy(value[:], digestBytes)
		digest = &value
	}
	proposal := controlfile.Proposal{
		ProposalEventID:    context.proposal.EventID,
		SessionID:          context.state.sessionID,
		Path:               path,
		Operation:          controlfile.Operation(operationText),
		ContentDigest:      digest,
		ContentSize:        contentSize,
		Diff:               diff,
		ProposedByDeviceID: context.device.ID,
		ChainIndex:         context.state.currentChainIndex + 1,
	}
	if err := proposal.Validate(); err != nil {
		return controlfile.Proposal{}, CodeInvalidPayload
	}
	return proposal, ""
}
