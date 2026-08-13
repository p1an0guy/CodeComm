package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/store"
)

type proofKind uint8

const (
	proofLaunch proofKind = iota + 1
	proofResume
)

type agentProof struct {
	kind  proofKind
	value []byte
}

func (proof agentProof) flightKey() string {
	digest := sha256.Sum256(proof.value)
	return string(rune(proof.kind)) + ":" + hex.EncodeToString(digest[:])
}

func decodeProof(input json.RawMessage) (agentProof, error) {
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil || !bytes.Equal(canonical, input) {
		return agentProof{}, ErrInvalidProof
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil || len(members) != 1 {
		return agentProof{}, ErrInvalidProof
	}
	var (
		kind proofKind
		raw  json.RawMessage
	)
	if value, exists := members["launch_selector"]; exists {
		kind = proofLaunch
		raw = value
	} else if value, exists := members["resume_capability"]; exists {
		kind = proofResume
		raw = value
	} else {
		return agentProof{}, ErrInvalidProof
	}
	var encoded string
	if bytes.Equal(raw, []byte("null")) ||
		json.Unmarshal(raw, &encoded) != nil {
		return agentProof{}, ErrInvalidProof
	}
	value, err := codec.DecodeBase64URLExact(encoded, 32)
	if err != nil {
		return agentProof{}, ErrInvalidProof
	}
	return agentProof{kind: kind, value: value}, nil
}

func selectorDigest(selector []byte) store.Digest {
	return store.Digest(sha256.Sum256(selector))
}

func resumeDigest(token []byte) store.Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("codecomm/v1/agent-resume"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(token)
	var digest store.Digest
	copy(digest[:], hash.Sum(nil))
	return digest
}
