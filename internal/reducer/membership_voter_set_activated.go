package reducer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

var checkpointFields = []string{
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
}

var voterActivationProofFields = []string{
	"session_id",
	"workspace_id",
	"recovery_generation",
	"target_voter_set_version",
	"current_authority_voter_set_version",
	"voter_set",
	"voter_device_id",
	"live_configuration_index",
	"checkpoint_event_id",
	"checkpoint",
	"checkpoint_signature",
	"voter_signature",
}

type checkpointWire struct {
	SessionID                string `json:"session_id"`
	WorkspaceID              string `json:"workspace_id"`
	RecoveryGeneration       uint64 `json:"recovery_generation"`
	AuthorityVoterSetVersion uint64 `json:"authority_voter_set_version"`
	SignerDeviceID           string `json:"signer_device_id"`
	Term                     uint64 `json:"term"`
	CoveredAppliedLogIndex   uint64 `json:"covered_applied_log_index"`
	CoveredChainIndex        uint64 `json:"covered_chain_index"`
	CoveredChainHash         string `json:"covered_chain_hash"`
	CoveredResultIndex       uint64 `json:"covered_result_index"`
	CoveredResultHash        string `json:"covered_result_hash"`
	ProjectionAccumulator    string `json:"projection_accumulator"`
	DigestVersion            uint64 `json:"digest_version"`
	ProjectionSchemaVersion  uint64 `json:"projection_schema_version"`
}

type voterActivationProofUnsignedWire struct {
	SessionID                       string          `json:"session_id"`
	WorkspaceID                     string          `json:"workspace_id"`
	RecoveryGeneration              uint64          `json:"recovery_generation"`
	TargetVoterSetVersion           uint64          `json:"target_voter_set_version"`
	CurrentAuthorityVoterSetVersion uint64          `json:"current_authority_voter_set_version"`
	VoterSet                        []string        `json:"voter_set"`
	VoterDeviceID                   string          `json:"voter_device_id"`
	LiveConfigurationIndex          uint64          `json:"live_configuration_index"`
	CheckpointEventID               string          `json:"checkpoint_event_id"`
	Checkpoint                      json.RawMessage `json:"checkpoint"`
	CheckpointSignature             string          `json:"checkpoint_signature"`
}

type authorityHandoffWire struct {
	SessionID                        string            `json:"session_id"`
	WorkspaceID                      string            `json:"workspace_id"`
	RecoveryGeneration               uint64            `json:"recovery_generation"`
	TargetVoterSetVersion            uint64            `json:"target_voter_set_version"`
	ExpectedAuthorityVoterSetVersion uint64            `json:"expected_authority_voter_set_version"`
	VoterSet                         []string          `json:"voter_set"`
	ActivationCheckpointEventID      string            `json:"activation_checkpoint_event_id"`
	ActivationProofs                 []json.RawMessage `json:"activation_proofs"`
	PriorAuthoritySigner             string            `json:"prior_authority_signer"`
}

type decodedVoterActivationProof struct {
	raw                     json.RawMessage
	unsigned                []byte
	sessionID               domain.UUIDv7
	workspaceID             domain.UUIDv4
	recoveryGeneration      uint64
	targetVersion           uint64
	currentAuthorityVersion uint64
	voterIDs                []domain.DeviceID
	voterDeviceID           domain.DeviceID
	liveConfigurationIndex  uint64
	checkpointEventID       domain.UUIDv7
	checkpoint              domain.Checkpoint
	checkpointBytes         []byte
	checkpointSignature     [ed25519.SignatureSize]byte
	voterSignature          [ed25519.SignatureSize]byte
}

func reduceMembershipVoterSetActivated(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{
			"target_voter_set_version",
			"expected_authority_voter_set_version",
			"voter_set",
			"activation_checkpoint_event_id",
			"activation_proofs",
			"prior_authority_signer",
			"prior_authority_handoff",
		},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	targetVersion, targetVersionOK := decodeValue[uint64](
		payload,
		"target_voter_set_version",
	)
	expectedAuthorityVersion, authorityVersionOK := decodeValue[uint64](
		payload,
		"expected_authority_voter_set_version",
	)
	voterIDs, votersOK := decodeDeviceIDs(payload, "voter_set")
	checkpointEventText, checkpointEventOK := decodeValue[string](
		payload,
		"activation_checkpoint_event_id",
	)
	proofObjects, proofsOK := decodeValue[[]json.RawMessage](
		payload,
		"activation_proofs",
	)
	priorSignerText, signerOK := decodeValue[string](
		payload,
		"prior_authority_signer",
	)
	handoffText, handoffOK := decodeValue[string](
		payload,
		"prior_authority_handoff",
	)
	checkpointEventID := domain.UUIDv7(checkpointEventText)
	priorSigner := domain.DeviceID(priorSignerText)
	handoffBytes, handoffErr := codec.DecodeBase64URLExact(
		handoffText,
		ed25519.SignatureSize,
	)
	if !targetVersionOK || targetVersion < 1 ||
		!domain.ValidUnsignedInteger(targetVersion) ||
		!authorityVersionOK || expectedAuthorityVersion < 1 ||
		!domain.ValidUnsignedInteger(expectedAuthorityVersion) ||
		!votersOK || !checkpointEventOK || !checkpointEventID.Valid() ||
		!proofsOK || !signerOK || !priorSigner.Valid() ||
		!handoffOK || handoffErr != nil {
		return context.reject(CodeInvalidPayload), nil
	}
	decodedProofs := make(
		[]decodedVoterActivationProof,
		len(proofObjects),
	)
	for index, raw := range proofObjects {
		proof, ok := decodeVoterActivationProof(raw)
		if !ok {
			return context.reject(CodeInvalidVoterActivationProof), nil
		}
		decodedProofs[index] = proof
	}

	entityText, _ := context.proposal.EntityID.Value()
	if domain.UUIDv7(entityText) != context.state.sessionID {
		return context.reject(CodeSessionBindingMismatch), nil
	}
	target := context.state.voterSet
	authority := context.state.credentialAuthority
	if targetVersion != target.VoterSetVersion {
		return context.reject(CodeVoterSetVersionMismatch), nil
	}
	if expectedAuthorityVersion != authority.VoterSetVersion {
		return context.reject(CodeCredentialAuthorityVersionMismatch), nil
	}
	if targetVersion == authority.VoterSetVersion {
		return context.reject(CodeVoterTargetAlreadyActivated), nil
	}
	if !sameDeviceIDs(voterIDs, target.VoterDeviceIDs()) {
		return context.reject(CodeInvalidVoterSet), nil
	}
	if len(decodedProofs) != len(voterIDs) {
		return context.reject(CodeInvalidVoterActivationProof), nil
	}
	priorSignerDevice, exists := context.state.devices[priorSigner]
	if !exists ||
		priorSignerDevice.Status != device.StatusActive ||
		!authority.Contains(priorSigner) {
		return context.reject(CodeInvalidCredentialAuthorityHandoff), nil
	}

	var commonProof decodedVoterActivationProof
	for index, proof := range decodedProofs {
		if !validActivationProofContext(
			context.state,
			proof,
			voterIDs[index],
			voterIDs,
			targetVersion,
			expectedAuthorityVersion,
			checkpointEventID,
		) {
			return context.reject(CodeInvalidVoterActivationProof), nil
		}
		if index == 0 {
			commonProof = proof
		} else if proof.liveConfigurationIndex !=
			commonProof.liveConfigurationIndex ||
			!bytes.Equal(proof.checkpointBytes, commonProof.checkpointBytes) ||
			proof.checkpointSignature != commonProof.checkpointSignature {
			return context.reject(CodeInvalidVoterActivationProof), nil
		}
	}
	if len(decodedProofs) == 0 ||
		!verifyCheckpoint(context.state, commonProof) {
		return context.reject(CodeInvalidVoterActivationProof), nil
	}
	for _, proof := range decodedProofs {
		member := context.state.devices[proof.voterDeviceID]
		if !verifyLabeledSignature(
			member.IdentityPublicKey,
			codec.SignatureVoterActivationProof,
			proof.unsigned,
			proof.voterSignature[:],
		) {
			return context.reject(CodeInvalidVoterActivationProof), nil
		}
	}

	handoffJSON, err := json.Marshal(authorityHandoffWire{
		SessionID:                        string(context.state.sessionID),
		WorkspaceID:                      string(context.state.workspaceID),
		RecoveryGeneration:               context.state.recoveryGeneration,
		TargetVoterSetVersion:            targetVersion,
		ExpectedAuthorityVoterSetVersion: expectedAuthorityVersion,
		VoterSet:                         deviceIDStrings(voterIDs),
		ActivationCheckpointEventID:      string(checkpointEventID),
		ActivationProofs:                 cloneRawMessages(proofObjects),
		PriorAuthoritySigner:             string(priorSigner),
	})
	if err != nil {
		return Outcome{}, invalidState("encode authority handoff: %v", err)
	}
	handoffPreimage, err := codec.CanonicalizeSignedObject(handoffJSON)
	if err != nil {
		return Outcome{}, invalidState(
			"canonicalize authority handoff: %v",
			err,
		)
	}
	if !verifyLabeledSignature(
		priorSignerDevice.IdentityPublicKey,
		codec.SignatureVoterAuthorityHandoff,
		handoffPreimage,
		handoffBytes,
	) {
		return context.reject(CodeInvalidCredentialAuthorityHandoff), nil
	}

	var handoffSignature [ed25519.SignatureSize]byte
	copy(handoffSignature[:], handoffBytes)
	activationProofs := make(
		[]credentialauthority.ActivationProof,
		len(decodedProofs),
	)
	for index, proof := range decodedProofs {
		activationProofs[index] = credentialauthority.ActivationProof{
			VoterDeviceID: proof.voterDeviceID,
			CanonicalJSON: bytes.Clone(proof.raw),
		}
	}
	next := credentialauthority.Authority{
		SessionID:                   context.state.sessionID,
		VoterDeviceIDs:              append([]domain.DeviceID(nil), voterIDs...),
		VoterSetVersion:             targetVersion,
		ActivationSource:            credentialauthority.ActivationHandoff,
		ActivationCheckpointEventID: checkpointEventID,
		ActivationProofs:            activationProofs,
		PriorAuthoritySigner:        priorSigner,
		PriorAuthorityHandoff:       &handoffSignature,
	}
	if err := credentialauthority.ValidateTransition(
		credentialauthority.OperationActivate,
		authority,
		next,
	); err != nil {
		return Outcome{}, invalidState(
			"validated authority activation failed transition: %v",
			err,
		)
	}
	return context.acceptMembership(
		nil,
		nil,
		nil,
		[]credentialauthority.Authority{next},
		nil,
	)
}

func decodeVoterActivationProof(
	raw json.RawMessage,
) (decodedVoterActivationProof, bool) {
	object, code := decodePayload(raw, voterActivationProofFields, nil)
	if code != "" {
		return decodedVoterActivationProof{}, false
	}
	sessionText, sessionOK := decodeValue[string](object, "session_id")
	workspaceText, workspaceOK := decodeValue[string](object, "workspace_id")
	generation, generationOK := decodeValue[uint64](
		object,
		"recovery_generation",
	)
	targetVersion, targetOK := decodeValue[uint64](
		object,
		"target_voter_set_version",
	)
	authorityVersion, authorityOK := decodeValue[uint64](
		object,
		"current_authority_voter_set_version",
	)
	voterIDs, votersOK := decodeDeviceIDs(object, "voter_set")
	voterText, voterOK := decodeValue[string](object, "voter_device_id")
	configurationIndex, configurationOK := decodeValue[uint64](
		object,
		"live_configuration_index",
	)
	checkpointEventText, eventOK := decodeValue[string](
		object,
		"checkpoint_event_id",
	)
	checkpointSignatureText, checkpointSignatureOK := decodeValue[string](
		object,
		"checkpoint_signature",
	)
	voterSignatureText, voterSignatureOK := decodeValue[string](
		object,
		"voter_signature",
	)
	checkpoint, checkpointBytes, checkpointOK := decodeCheckpoint(
		object["checkpoint"],
	)
	checkpointSignature, checkpointSignatureErr :=
		codec.DecodeBase64URLExact(
			checkpointSignatureText,
			ed25519.SignatureSize,
		)
	voterSignature, voterSignatureErr := codec.DecodeBase64URLExact(
		voterSignatureText,
		ed25519.SignatureSize,
	)
	proof := decodedVoterActivationProof{
		raw:                     bytes.Clone(raw),
		sessionID:               domain.UUIDv7(sessionText),
		workspaceID:             domain.UUIDv4(workspaceText),
		recoveryGeneration:      generation,
		targetVersion:           targetVersion,
		currentAuthorityVersion: authorityVersion,
		voterIDs:                voterIDs,
		voterDeviceID:           domain.DeviceID(voterText),
		liveConfigurationIndex:  configurationIndex,
		checkpointEventID:       domain.UUIDv7(checkpointEventText),
		checkpoint:              checkpoint,
		checkpointBytes:         checkpointBytes,
	}
	if !sessionOK || !proof.sessionID.Valid() ||
		!workspaceOK || !proof.workspaceID.Valid() ||
		!generationOK || !domain.ValidUnsignedInteger(generation) ||
		!targetOK || targetVersion < 1 ||
		!domain.ValidUnsignedInteger(targetVersion) ||
		!authorityOK || authorityVersion < 1 ||
		!domain.ValidUnsignedInteger(authorityVersion) ||
		!votersOK || !voterOK || !proof.voterDeviceID.Valid() ||
		!configurationOK || configurationIndex < 1 ||
		!domain.ValidUnsignedInteger(configurationIndex) ||
		!eventOK || !proof.checkpointEventID.Valid() ||
		!checkpointOK ||
		!checkpointSignatureOK || checkpointSignatureErr != nil ||
		!voterSignatureOK || voterSignatureErr != nil {
		return decodedVoterActivationProof{}, false
	}
	copy(proof.checkpointSignature[:], checkpointSignature)
	copy(proof.voterSignature[:], voterSignature)
	unsignedJSON, err := json.Marshal(voterActivationProofUnsignedWire{
		SessionID:                       sessionText,
		WorkspaceID:                     workspaceText,
		RecoveryGeneration:              generation,
		TargetVoterSetVersion:           targetVersion,
		CurrentAuthorityVoterSetVersion: authorityVersion,
		VoterSet:                        deviceIDStrings(voterIDs),
		VoterDeviceID:                   voterText,
		LiveConfigurationIndex:          configurationIndex,
		CheckpointEventID:               checkpointEventText,
		Checkpoint:                      bytes.Clone(checkpointBytes),
		CheckpointSignature:             checkpointSignatureText,
	})
	if err != nil {
		return decodedVoterActivationProof{}, false
	}
	proof.unsigned, err = codec.CanonicalizeSignedObject(unsignedJSON)
	if err != nil {
		return decodedVoterActivationProof{}, false
	}
	return proof, true
}

func decodeCheckpoint(
	raw json.RawMessage,
) (domain.Checkpoint, []byte, bool) {
	object, code := decodePayload(raw, checkpointFields, nil)
	if code != "" {
		return domain.Checkpoint{}, nil, false
	}
	sessionText, sessionOK := decodeValue[string](object, "session_id")
	workspaceText, workspaceOK := decodeValue[string](object, "workspace_id")
	generation, generationOK := decodeValue[uint64](
		object,
		"recovery_generation",
	)
	authorityVersion, authorityOK := decodeValue[uint64](
		object,
		"authority_voter_set_version",
	)
	signerText, signerOK := decodeValue[string](object, "signer_device_id")
	term, termOK := decodeValue[uint64](object, "term")
	appliedIndex, appliedOK := decodeValue[uint64](
		object,
		"covered_applied_log_index",
	)
	chainIndex, chainIndexOK := decodeValue[uint64](
		object,
		"covered_chain_index",
	)
	chainHashText, chainHashOK := decodeValue[string](
		object,
		"covered_chain_hash",
	)
	resultIndex, resultIndexOK := decodeValue[uint64](
		object,
		"covered_result_index",
	)
	resultHashText, resultHashOK := decodeValue[string](
		object,
		"covered_result_hash",
	)
	accumulatorText, accumulatorOK := decodeValue[string](
		object,
		"projection_accumulator",
	)
	digestVersion, digestOK := decodeValue[uint64](
		object,
		"digest_version",
	)
	projectionVersion, projectionOK := decodeValue[uint64](
		object,
		"projection_schema_version",
	)
	chainHash, chainDecodeErr := codec.DecodeBase64URLExact(
		chainHashText,
		sha256.Size,
	)
	resultHash, resultDecodeErr := codec.DecodeBase64URLExact(
		resultHashText,
		sha256.Size,
	)
	accumulator, accumulatorDecodeErr := codec.DecodeBase64URLExact(
		accumulatorText,
		sha256.Size,
	)
	if !sessionOK || !workspaceOK || !generationOK ||
		!authorityOK || !signerOK || !termOK || !appliedOK ||
		!chainIndexOK || !chainHashOK || chainDecodeErr != nil ||
		!resultIndexOK || !resultHashOK || resultDecodeErr != nil ||
		!accumulatorOK || accumulatorDecodeErr != nil ||
		!digestOK || !projectionOK {
		return domain.Checkpoint{}, nil, false
	}
	checkpoint := domain.Checkpoint{
		SessionID:                domain.UUIDv7(sessionText),
		WorkspaceID:              domain.UUIDv4(workspaceText),
		RecoveryGeneration:       generation,
		AuthorityVoterSetVersion: authorityVersion,
		SignerDeviceID:           domain.DeviceID(signerText),
		Term:                     term,
		CoveredAppliedLogIndex:   appliedIndex,
		CoveredChainIndex:        chainIndex,
		CoveredResultIndex:       resultIndex,
		DigestVersion:            digestVersion,
		ProjectionSchemaVersion:  projectionVersion,
	}
	copy(checkpoint.CoveredChainHash[:], chainHash)
	copy(checkpoint.CoveredResultHash[:], resultHash)
	copy(checkpoint.ProjectionAccumulator[:], accumulator)
	if checkpoint.Validate() != nil {
		return domain.Checkpoint{}, nil, false
	}
	reencoded, err := json.Marshal(checkpointWire{
		SessionID:                sessionText,
		WorkspaceID:              workspaceText,
		RecoveryGeneration:       generation,
		AuthorityVoterSetVersion: authorityVersion,
		SignerDeviceID:           signerText,
		Term:                     term,
		CoveredAppliedLogIndex:   appliedIndex,
		CoveredChainIndex:        chainIndex,
		CoveredChainHash:         chainHashText,
		CoveredResultIndex:       resultIndex,
		CoveredResultHash:        resultHashText,
		ProjectionAccumulator:    accumulatorText,
		DigestVersion:            digestVersion,
		ProjectionSchemaVersion:  projectionVersion,
	})
	if err != nil {
		return domain.Checkpoint{}, nil, false
	}
	canonical, err := codec.CanonicalizeSignedObject(reencoded)
	if err != nil || !bytes.Equal(canonical, raw) {
		return domain.Checkpoint{}, nil, false
	}
	return checkpoint, canonical, true
}

func validActivationProofContext(
	state State,
	proof decodedVoterActivationProof,
	expectedVoter domain.DeviceID,
	target []domain.DeviceID,
	targetVersion uint64,
	authorityVersion uint64,
	checkpointEventID domain.UUIDv7,
) bool {
	member, exists := state.devices[expectedVoter]
	return exists &&
		member.Status == device.StatusActive &&
		proof.sessionID == state.sessionID &&
		proof.workspaceID == state.workspaceID &&
		proof.recoveryGeneration == state.recoveryGeneration &&
		proof.targetVersion == targetVersion &&
		proof.currentAuthorityVersion == authorityVersion &&
		sameDeviceIDs(proof.voterIDs, target) &&
		proof.voterDeviceID == expectedVoter &&
		proof.checkpointEventID == checkpointEventID &&
		proof.checkpoint.CoveredAppliedLogIndex >=
			proof.liveConfigurationIndex &&
		proof.checkpoint.SessionID == state.sessionID &&
		proof.checkpoint.WorkspaceID == state.workspaceID &&
		proof.checkpoint.RecoveryGeneration == state.recoveryGeneration &&
		proof.checkpoint.AuthorityVoterSetVersion == authorityVersion
}

func verifyCheckpoint(
	state State,
	proof decodedVoterActivationProof,
) bool {
	signer, exists := state.devices[proof.checkpoint.SignerDeviceID]
	return exists &&
		signer.Status == device.StatusActive &&
		state.credentialAuthority.Contains(signer.ID) &&
		verifyLabeledSignature(
			signer.IdentityPublicKey,
			codec.SignatureCheckpoint,
			proof.checkpointBytes,
			proof.checkpointSignature[:],
		)
}

func verifyLabeledSignature(
	publicKey []byte,
	label codec.SignatureLabel,
	preimage []byte,
	signature []byte,
) bool {
	signedInput, err := codec.BuildSignedInput(label, preimage)
	return err == nil &&
		len(publicKey) == ed25519.PublicKeySize &&
		len(signature) == ed25519.SignatureSize &&
		ed25519.Verify(publicKey, signedInput, signature)
}

func deviceIDStrings(ids []domain.DeviceID) []string {
	result := make([]string, len(ids))
	for index, id := range ids {
		result[index] = string(id)
	}
	return result
}

func cloneRawMessages(values []json.RawMessage) []json.RawMessage {
	result := make([]json.RawMessage, len(values))
	for index, value := range values {
		result[index] = bytes.Clone(value)
	}
	return result
}
