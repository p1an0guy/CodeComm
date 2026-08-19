package credentialauthorization

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

// The field order is lexical. After validation, every string contains only
// unescaped ASCII and every number is in the I-JSON safe range, so
// encoding/json emits the exact RFC 8785 representation.
type endorsementPreimageWire struct {
	AuthorityVoterSetVersion uint64 `json:"authority_voter_set_version"`
	Epoch                    uint64 `json:"epoch"`
	IssuedAt                 string `json:"issued_at"`
	KeyDigest                string `json:"key_digest"`
	SessionID                string `json:"session_id"`
	SubjectDeviceID          string `json:"subject_device_id"`
}

// CanonicalEndorsementPreimage returns the canonical bytes signed by a
// credential-time endorser. The input is intentionally partial: SessionID,
// DeviceID, Epoch, EpochPublicKey, KeyDigest, IssuedAt, and
// AuthorityVoterSetVersion are required and validated. All other Authorization
// fields are ignored; in particular, ClockEndorsements and
// AuthorizationChainIndex need not exist yet.
func CanonicalEndorsementPreimage(
	authorization Authorization,
) ([]byte, error) {
	if !authorization.SessionID.Valid() {
		return nil, fmt.Errorf(
			"%w: %q",
			ErrInvalidSessionID,
			authorization.SessionID,
		)
	}
	if !authorization.DeviceID.Valid() {
		return nil, fmt.Errorf(
			"%w: %q",
			ErrInvalidDeviceID,
			authorization.DeviceID,
		)
	}
	if authorization.Epoch < 1 ||
		!domain.ValidUnsignedInteger(authorization.Epoch) {
		return nil, fmt.Errorf("%w: %d", ErrInvalidEpoch, authorization.Epoch)
	}
	if sha256.Sum256(authorization.EpochPublicKey[:]) !=
		authorization.KeyDigest {
		return nil, ErrKeyDigestMismatch
	}
	if !authorization.IssuedAt.Valid() {
		return nil, ErrInvalidTimestamp
	}
	if authorization.AuthorityVoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(
			authorization.AuthorityVoterSetVersion,
		) {
		return nil, fmt.Errorf(
			"%w: %d",
			ErrInvalidAuthorityVersion,
			authorization.AuthorityVoterSetVersion,
		)
	}

	encoded, err := json.Marshal(endorsementPreimageWire{
		AuthorityVoterSetVersion: authorization.AuthorityVoterSetVersion,
		Epoch:                    authorization.Epoch,
		IssuedAt:                 string(authorization.IssuedAt),
		KeyDigest: base64.RawURLEncoding.EncodeToString(
			authorization.KeyDigest[:],
		),
		SessionID:       string(authorization.SessionID),
		SubjectDeviceID: string(authorization.DeviceID),
	})
	if err != nil {
		return nil, fmt.Errorf(
			"credential authorization: encode endorsement preimage: %w",
			err,
		)
	}
	return encoded, nil
}
