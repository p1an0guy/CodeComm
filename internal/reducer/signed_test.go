package reducer

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
)

func resignEvent(
	t *testing.T,
	fixture reducerFixture,
	original event.SignedEvent,
	mutate func(map[string]json.RawMessage),
) event.SignedEvent {
	t.Helper()

	proposal := original.Proposal()
	privateKey, exists := fixture.privateKeys[proposal.Origin.DeviceID()]
	if !exists {
		t.Fatalf("no private key for origin device %q", proposal.Origin.DeviceID())
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(original.CanonicalBytes(), &object); err != nil {
		t.Fatalf("decode signed event: %v", err)
	}
	delete(object, "origin_signature")
	mutate(object)

	unsignedJSON, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("encode signature preimage: %v", err)
	}
	signedBytes, err := codec.CanonicalizeSignedObject(unsignedJSON)
	if err != nil {
		t.Fatalf("canonicalize signature preimage: %v", err)
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureEventOrigin,
		signedBytes,
	)
	if err != nil {
		t.Fatalf("sign mutated event: %v", err)
	}
	signatureText, err := json.Marshal(codec.EncodeBase64URL(signature))
	if err != nil {
		t.Fatalf("encode origin signature: %v", err)
	}
	object["origin_signature"] = signatureText
	completeJSON, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("encode signed event: %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(completeJSON)
	if err != nil {
		t.Fatalf("canonicalize signed event: %v", err)
	}

	var sessionIDText string
	var workspaceIDText string
	if err := json.Unmarshal(object["session_id"], &sessionIDText); err != nil {
		t.Fatalf("decode mutated session ID: %v", err)
	}
	if err := json.Unmarshal(object["workspace_id"], &workspaceIDText); err != nil {
		t.Fatalf("decode mutated workspace ID: %v", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signed, err := event.ParseAndVerify(canonical, event.VerificationContext{
		SessionID:         domain.UUIDv7(sessionIDText),
		WorkspaceID:       domain.UUIDv4(workspaceIDText),
		IdentityPublicKey: publicKey,
	})
	if err != nil {
		t.Fatalf("parse mutated signed event: %v", err)
	}
	return signed
}
