package reducer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
)

const (
	conflictIDLabel      = "codecomm/v1/conflict-id"
	mergeInputsVersionV1 = uint64(1)
)

type conflictIdentityWire struct {
	WorkspaceID        string   `json:"workspace_id"`
	MergeInputsVersion uint64   `json:"merge_inputs_version"`
	MergeKind          string   `json:"merge_kind"`
	PublicationID      string   `json:"publication_id"`
	ReplayCommitOID    *string  `json:"replay_commit_oid"`
	MergeBaseOIDs      []string `json:"merge_base_oids"`
	CanonicalCommit    string   `json:"canonical_commit"`
	CandidateCommit    string   `json:"candidate_commit"`
}

func deriveConflictID(
	workspaceID domain.UUIDv4,
	detection conflict.Detection,
) (domain.ConflictID, error) {
	input, err := detection.IdentityInput(
		workspaceID,
		mergeInputsVersionV1,
	)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(conflictIdentityWire{
		WorkspaceID:        string(input.WorkspaceID()),
		MergeInputsVersion: input.MergeInputsVersion(),
		MergeKind:          string(input.MergeKind()),
		PublicationID:      string(input.PublicationID()),
		ReplayCommitOID:    optionalUUIDText(input.ReplayCommitOID()),
		MergeBaseOIDs:      gitOIDStrings(input.MergeBaseOIDs()),
		CanonicalCommit:    string(input.CanonicalCommit()),
		CandidateCommit:    string(input.CandidateCommit()),
	})
	if err != nil {
		return "", err
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(conflictIDLabel))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(canonical)
	return domain.ConflictID("ccf1" + hex.EncodeToString(hasher.Sum(nil))), nil
}
