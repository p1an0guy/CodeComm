package reducer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const (
	checkpointDigestVersion           uint64 = 1
	checkpointProjectionSchemaVersion uint64 = 1
)

var checkpointProofFields = []string{
	"session_id",
	"workspace_id",
	"recovery_generation",
	"authority_voter_set_version",
	"signer_device_id",
	"term",
	"covered_applied_log_index",
	"covered_chain_index",
	"covered_chain_hash",
	"covered_result_index",
	"covered_result_hash",
	"projection_accumulator",
	"digest_version",
	"projection_schema_version",
	"authority_signature",
}

// CheckpointDirective is the reducer-owned, context-free proof retained for a
// consensus.checkpoint apply. CanonicalUnsignedJSON is the exact unsigned
// checkpoint object protected by AuthoritySignature.
type CheckpointDirective struct {
	Checkpoint            domain.Checkpoint
	CanonicalUnsignedJSON json.RawMessage
	AuthoritySignature    [ed25519.SignatureSize]byte
}

// decodeCheckpointProof validates the context-free shape and authority proof.
//
// Term, covered log position, chain/result heads, and projection accumulator
// must be compared with the local pre-command apply context. This function
// deliberately does not perform or approximate those checks; reducer/apply
// integration must supply that context separately.
func decodeCheckpointProof(
	state State,
	payload json.RawMessage,
) (CheckpointDirective, bool) {
	object, code := decodePayload(payload, checkpointProofFields, nil)
	if code != "" {
		return CheckpointDirective{}, false
	}

	signatureText, signatureOK := decodeValue[string](
		object,
		"authority_signature",
	)
	signature, signatureErr := codec.DecodeBase64URLExact(
		signatureText,
		ed25519.SignatureSize,
	)
	if !signatureOK || signatureErr != nil {
		return CheckpointDirective{}, false
	}

	unsignedObject := make(payloadObject, len(checkpointFields))
	for _, field := range checkpointFields {
		unsignedObject[field] = object[field]
	}
	encoded, err := json.Marshal(unsignedObject)
	if err != nil {
		return CheckpointDirective{}, false
	}
	unsigned, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return CheckpointDirective{}, false
	}
	checkpoint, canonicalUnsigned, checkpointOK := decodeCheckpoint(unsigned)
	if !checkpointOK ||
		checkpoint.SessionID != state.sessionID ||
		checkpoint.WorkspaceID != state.workspaceID ||
		checkpoint.RecoveryGeneration != state.recoveryGeneration ||
		checkpoint.DigestVersion != checkpointDigestVersion ||
		checkpoint.ProjectionSchemaVersion !=
			checkpointProjectionSchemaVersion ||
		checkpoint.AuthorityVoterSetVersion !=
			state.credentialAuthority.VoterSetVersion {
		return CheckpointDirective{}, false
	}

	signer, exists := state.devices[checkpoint.SignerDeviceID]
	if !exists ||
		signer.Status != device.StatusActive ||
		!state.credentialAuthority.Contains(checkpoint.SignerDeviceID) ||
		!verifyLabeledSignature(
			signer.IdentityPublicKey,
			codec.SignatureCheckpoint,
			canonicalUnsigned,
			signature,
		) {
		return CheckpointDirective{}, false
	}

	directive := CheckpointDirective{
		Checkpoint:            checkpoint,
		CanonicalUnsignedJSON: bytes.Clone(canonicalUnsigned),
	}
	copy(directive.AuthoritySignature[:], signature)
	return directive, true
}
