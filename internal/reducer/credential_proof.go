package reducer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
)

var credentialAuthorizationFields = []string{
	"subject_device_id",
	"epoch_public_key",
	"key_digest",
	"epoch",
	"role",
	"issued_at",
	"not_before",
	"validity_seconds",
	"authority_voter_set_version",
	"clock_endorsements",
	"binding_signature",
}

var clockEndorsementFields = []string{
	"device_id",
	"signature",
}

type credentialTimeEndorsementWire struct {
	AuthorityVoterSetVersion uint64 `json:"authority_voter_set_version"`
	Epoch                    uint64 `json:"epoch"`
	IssuedAt                 string `json:"issued_at"`
	KeyDigest                string `json:"key_digest"`
	SessionID                string `json:"session_id"`
	SubjectDeviceID          string `json:"subject_device_id"`
}

func credentialBindingPreimageBytes(
	sessionID domain.UUIDv7,
	deviceID domain.DeviceID,
	epoch uint64,
	epochPublicKey [ed25519.PublicKeySize]byte,
) ([]byte, error) {
	binding := credential.Binding{
		SessionID: sessionID,
		DeviceID:  deviceID,
		Epoch:     epoch,
	}
	copy(binding.EpochPublicKey[:], epochPublicKey[:])
	return binding.CanonicalPreimage()
}

func credentialTimeEndorsementPreimageBytes(
	authorization credentialauthorization.Authorization,
) ([]byte, error) {
	encoded, err := json.Marshal(credentialTimeEndorsementWire{
		AuthorityVoterSetVersion: authorization.AuthorityVoterSetVersion,
		Epoch:                    authorization.Epoch,
		IssuedAt:                 string(authorization.IssuedAt),
		KeyDigest:                codec.EncodeBase64URL(authorization.KeyDigest[:]),
		SessionID:                string(authorization.SessionID),
		SubjectDeviceID:          string(authorization.DeviceID),
	})
	if err != nil {
		return nil, err
	}
	return codec.CanonicalizeSignedObject(encoded)
}

func verifyCredentialBinding(
	authorization credentialauthorization.Authorization,
	identityPublicKey ed25519.PublicKey,
) bool {
	binding := credential.Binding{
		SessionID:      authorization.SessionID,
		DeviceID:       authorization.DeviceID,
		Epoch:          authorization.Epoch,
		EpochPublicKey: authorization.EpochPublicKey,
		KeyDigest:      authorization.KeyDigest,
		Signature:      authorization.BindingSignature,
	}
	return binding.Validate(identityPublicKey) == nil
}

func decodeCredentialAuthorization(
	raw json.RawMessage,
	sessionID domain.UUIDv7,
	authorizationChainIndex uint64,
) (credentialauthorization.Authorization, bool) {
	object, code := decodePayload(
		raw,
		credentialAuthorizationFields,
		nil,
	)
	if code != "" {
		return credentialauthorization.Authorization{}, false
	}
	subjectText, subjectOK := decodeValue[string](
		object,
		"subject_device_id",
	)
	publicKeyText, publicKeyOK := decodeValue[string](
		object,
		"epoch_public_key",
	)
	digestText, digestOK := decodeValue[string](object, "key_digest")
	epoch, epochOK := decodeValue[uint64](object, "epoch")
	roleText, roleOK := decodeValue[string](object, "role")
	issuedAtText, issuedAtOK := decodeValue[string](object, "issued_at")
	notBeforeText, notBeforeOK := decodeValue[string](object, "not_before")
	validity, validityOK := decodeValue[uint64](object, "validity_seconds")
	authorityVersion, authorityOK := decodeValue[uint64](
		object,
		"authority_voter_set_version",
	)
	endorsementObjects, endorsementsOK := decodeValue[[]json.RawMessage](
		object,
		"clock_endorsements",
	)
	bindingText, bindingOK := decodeValue[string](
		object,
		"binding_signature",
	)
	publicKey, publicKeyErr := codec.DecodeBase64URLExact(
		publicKeyText,
		ed25519.PublicKeySize,
	)
	digest, digestErr := codec.DecodeBase64URLExact(digestText, sha256.Size)
	binding, bindingErr := codec.DecodeBase64URLExact(
		bindingText,
		ed25519.SignatureSize,
	)
	authorization := credentialauthorization.Authorization{
		SessionID:                sessionID,
		DeviceID:                 domain.DeviceID(subjectText),
		Epoch:                    epoch,
		Role:                     credentialauthorization.Role(roleText),
		IssuedAt:                 domain.WholeSecondTimestamp(issuedAtText),
		NotBefore:                domain.WholeSecondTimestamp(notBeforeText),
		ValiditySeconds:          validity,
		AuthorityVoterSetVersion: authorityVersion,
		AuthorizationChainIndex:  authorizationChainIndex,
	}
	if !subjectOK || !authorization.DeviceID.Valid() ||
		!publicKeyOK || publicKeyErr != nil ||
		!digestOK || digestErr != nil ||
		!epochOK || epoch < 1 || !domain.ValidUnsignedInteger(epoch) ||
		!roleOK || !authorization.Role.Valid() ||
		!issuedAtOK || !authorization.IssuedAt.Valid() ||
		!notBeforeOK || !authorization.NotBefore.Valid() ||
		!validityOK || !domain.ValidUnsignedInteger(validity) ||
		!authorityOK || authorityVersion < 1 ||
		!domain.ValidUnsignedInteger(authorityVersion) ||
		!endorsementsOK ||
		!bindingOK || bindingErr != nil {
		return credentialauthorization.Authorization{}, false
	}
	copy(authorization.EpochPublicKey[:], publicKey)
	copy(authorization.KeyDigest[:], digest)
	copy(authorization.BindingSignature[:], binding)

	authorization.ClockEndorsements = make(
		[]credentialauthorization.ClockEndorsement,
		len(endorsementObjects),
	)
	for index, endorsementRaw := range endorsementObjects {
		endorsementObject, endorsementCode := decodePayload(
			endorsementRaw,
			clockEndorsementFields,
			nil,
		)
		if endorsementCode != "" {
			return credentialauthorization.Authorization{}, false
		}
		deviceText, deviceOK := decodeValue[string](
			endorsementObject,
			"device_id",
		)
		signatureText, signatureOK := decodeValue[string](
			endorsementObject,
			"signature",
		)
		signature, signatureErr := codec.DecodeBase64URLExact(
			signatureText,
			ed25519.SignatureSize,
		)
		endorsement := credentialauthorization.ClockEndorsement{
			DeviceID: domain.DeviceID(deviceText),
		}
		if !deviceOK || !endorsement.DeviceID.Valid() ||
			!signatureOK || signatureErr != nil {
			return credentialauthorization.Authorization{}, false
		}
		copy(endorsement.Signature[:], signature)
		authorization.ClockEndorsements[index] = endorsement
	}
	return authorization, true
}
