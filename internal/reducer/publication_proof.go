package reducer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/publication"
)

const (
	publicationMetadataLabel        = "codecomm/v1/publication-metadata"
	publicationReceiptWindow uint64 = 100_000
)

var stagingReceiptFields = []string{
	"session_id",
	"workspace_id",
	"voter_set_version",
	"publication_metadata_digest",
	"voter_device_id",
	"staged_result_index",
	"signature",
}

type publicationMetadataWire struct {
	ProposalEventID         string   `json:"proposal_event_id"`
	PublicationID           string   `json:"publication_id"`
	SupersedesPublicationID *string  `json:"supersedes_publication_id"`
	TaskID                  *string  `json:"task_id"`
	AuthorDeviceID          string   `json:"author_device_id"`
	AuthorAgentSessionID    string   `json:"author_agent_session_id"`
	BaseCommit              string   `json:"base_commit"`
	CommitOID               string   `json:"commit_oid"`
	TreeOID                 string   `json:"tree_oid"`
	ParentOIDs              []string `json:"parent_oids"`
	Paths                   []string `json:"paths"`
	ArtifactDigest          string   `json:"artifact_digest"`
	ResolvesConflictIDs     []string `json:"resolves_conflict_ids"`
	WorkingRootID           string   `json:"working_root_id"`
}

type stagingReceiptUnsignedWire struct {
	SessionID                 string `json:"session_id"`
	WorkspaceID               string `json:"workspace_id"`
	VoterSetVersion           uint64 `json:"voter_set_version"`
	PublicationMetadataDigest string `json:"publication_metadata_digest"`
	VoterDeviceID             string `json:"voter_device_id"`
	StagedResultIndex         uint64 `json:"staged_result_index"`
}

func publicationMetadataDigest(
	metadata publication.Metadata,
) (publication.SHA256Digest, error) {
	encoded, err := json.Marshal(publicationMetadataWire{
		ProposalEventID:         string(metadata.ProposalEventID),
		PublicationID:           string(metadata.PublicationID),
		SupersedesPublicationID: optionalUUIDText(metadata.SupersedesPublicationID),
		TaskID:                  optionalUUIDText(metadata.TaskID),
		AuthorDeviceID:          string(metadata.AuthorDeviceID),
		AuthorAgentSessionID:    string(metadata.AuthorAgentSessionID),
		BaseCommit:              string(metadata.BaseCommit),
		CommitOID:               string(metadata.CommitOID),
		TreeOID:                 string(metadata.TreeOID),
		ParentOIDs:              gitOIDStrings(metadata.ParentOIDs),
		Paths:                   repositoryPathStrings(metadata.Paths),
		ArtifactDigest:          codec.EncodeBase64URL(metadata.ArtifactDigest[:]),
		ResolvesConflictIDs:     conflictIDStrings(metadata.ResolvesConflictIDs),
		WorkingRootID:           string(metadata.WorkingRootID),
	})
	if err != nil {
		return publication.SHA256Digest{}, err
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return publication.SHA256Digest{}, err
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(publicationMetadataLabel))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(canonical)
	var digest publication.SHA256Digest
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

func decodeStagingReceipts(
	rawValues []json.RawMessage,
) ([]publication.StagingReceipt, bool) {
	receipts := make([]publication.StagingReceipt, len(rawValues))
	for index, raw := range rawValues {
		object, code := decodePayload(raw, stagingReceiptFields, nil)
		if code != "" {
			return nil, false
		}
		sessionText, sessionOK := decodeValue[string](object, "session_id")
		workspaceText, workspaceOK := decodeValue[string](object, "workspace_id")
		version, versionOK := decodeValue[uint64](object, "voter_set_version")
		digestText, digestOK := decodeValue[string](
			object,
			"publication_metadata_digest",
		)
		voterText, voterOK := decodeValue[string](object, "voter_device_id")
		resultIndex, resultOK := decodeValue[uint64](
			object,
			"staged_result_index",
		)
		signatureText, signatureOK := decodeValue[string](object, "signature")
		digestBytes, digestErr := codec.DecodeBase64URLExact(
			digestText,
			sha256.Size,
		)
		signatureBytes, signatureErr := codec.DecodeBase64URLExact(
			signatureText,
			ed25519.SignatureSize,
		)
		receipt := publication.StagingReceipt{
			SessionID:         domain.UUIDv7(sessionText),
			WorkspaceID:       domain.UUIDv4(workspaceText),
			VoterSetVersion:   version,
			VoterDeviceID:     domain.DeviceID(voterText),
			StagedResultIndex: resultIndex,
		}
		if !sessionOK || !workspaceOK || !versionOK || !digestOK ||
			digestErr != nil || !voterOK || !resultOK ||
			!signatureOK || signatureErr != nil {
			return nil, false
		}
		copy(receipt.PublicationMetadataDigest[:], digestBytes)
		copy(receipt.Signature[:], signatureBytes)
		if err := receipt.Validate(); err != nil {
			return nil, false
		}
		receipts[index] = receipt
	}
	if err := publication.ValidateStagingReceipts(receipts); err != nil {
		return nil, false
	}
	return receipts, true
}

func verifyStagingReceiptSignature(
	receipt publication.StagingReceipt,
	publicKey ed25519.PublicKey,
) bool {
	encoded, err := json.Marshal(stagingReceiptUnsignedWire{
		SessionID:       string(receipt.SessionID),
		WorkspaceID:     string(receipt.WorkspaceID),
		VoterSetVersion: receipt.VoterSetVersion,
		PublicationMetadataDigest: codec.EncodeBase64URL(
			receipt.PublicationMetadataDigest[:],
		),
		VoterDeviceID:     string(receipt.VoterDeviceID),
		StagedResultIndex: receipt.StagedResultIndex,
	})
	if err != nil {
		return false
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return false
	}
	return verifyLabeledSignature(
		publicKey,
		codec.SignatureGitStageReceipt,
		canonical,
		receipt.Signature[:],
	)
}

func validatePublicationReceipts(
	state State,
	metadata publication.Metadata,
	receipts []publication.StagingReceipt,
) Code {
	if err := publication.ValidateStagingReceipts(receipts); err != nil {
		return CodeInvalidPublicationReceipts
	}
	digest, err := publicationMetadataDigest(metadata)
	if err != nil {
		return CodeInvalidPublicationReceipts
	}
	targetVersion := state.voterSet.VoterSetVersion
	targetIDs := state.voterSet.VoterDeviceIDs()
	for _, receipt := range receipts {
		if receipt.SessionID != state.sessionID ||
			receipt.WorkspaceID != state.workspaceID ||
			receipt.VoterSetVersion != targetVersion ||
			receipt.PublicationMetadataDigest != digest {
			return CodeInvalidPublicationReceipts
		}
		if receipt.StagedResultIndex > state.currentResultIndex {
			return CodePublicationReceiptFromFuture
		}
		if state.currentResultIndex-receipt.StagedResultIndex >
			publicationReceiptWindow {
			return CodePublicationReceiptStale
		}
		member, exists := state.devices[receipt.VoterDeviceID]
		if !exists || member.Status != device.StatusActive ||
			!state.voterSet.Contains(receipt.VoterDeviceID) {
			return CodeInvalidPublicationReceipts
		}
		if !verifyStagingReceiptSignature(
			receipt,
			member.IdentityPublicKey,
		) {
			return CodeInvalidPublicationReceipts
		}
	}
	required := len(targetIDs)/2 + 1
	if len(receipts) < required {
		return CodePublicationReceiptQuorumNotMet
	}
	return ""
}

func optionalUUIDText[T ~string](value T) *string {
	if value == "" {
		return nil
	}
	text := string(value)
	return &text
}

func gitOIDStrings(values []domain.GitOID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func repositoryPathStrings(values []domain.RepositoryPath) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func conflictIDStrings(values []domain.ConflictID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}
