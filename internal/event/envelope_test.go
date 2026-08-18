package event

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	testEventID     = domain.UUIDv7("01890f47-3e72-7000-8000-000000000001")
	testSessionID   = domain.UUIDv7("01890f47-3e72-7000-8000-000000000002")
	testWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
	testEntityID    = "01890f47-3e72-7000-8000-000000000006"
)

func TestDecodeLocalCommandRejectsEveryClientSuppliedOrigin(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{
		`null`,
		`{}`,
		`{"actor_type":"agent"}`,
		`{"actor_type":"human"}`,
	} {
		input := []byte(`{
			"kind":"task.created",
			"entity_id":"` + testEntityID + `",
			"rationale_summary":"",
			"actions":[],
			"payload":{},
			"redaction":{"policy":"default","fields_removed":[]},
			"origin":` + origin + `
		}`)
		if _, err := DecodeLocalCommand(input); !errors.Is(err, ErrClientSuppliedOrigin) {
			t.Errorf("origin %s error = %v, want ErrClientSuppliedOrigin", origin, err)
		}
	}
}

func TestBuildSignAndVerifyCanonicalProposal(t *testing.T) {
	t.Parallel()

	deviceID, publicKey, privateKey := testIdentity(t)
	profile := "codex/default"
	binding := mustMCPBinding(t, deviceID, testAgentSessionID, &profile)
	command := validCommand(KindTaskCreated)
	command.RationaleSummary = "Implement the signed event envelope."
	command.Actions = []Action{{
		Type:    ActionFileEdit,
		Target:  "internal/event/envelope.go",
		Summary: "implemented canonical signing",
		Status:  ActionSucceeded,
	}}

	proposal, err := BuildProposal(command, binding, validBuildContext())
	if err != nil {
		t.Fatalf("BuildProposal() error = %v", err)
	}
	signed, err := Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !bytes.Equal(signed.CanonicalBytes(), bytes.TrimSpace(signed.CanonicalBytes())) {
		t.Fatal("Sign() returned whitespace around canonical JSON")
	}
	if bytes.Contains(signed.SignedBytes(), []byte(`origin_signature`)) {
		t.Fatal("SignedBytes() includes origin_signature")
	}

	verified, err := ParseAndVerify(signed.CanonicalBytes(), VerificationContext{
		SessionID:         testSessionID,
		WorkspaceID:       testWorkspaceID,
		IdentityPublicKey: publicKey,
	})
	if err != nil {
		t.Fatalf("ParseAndVerify() error = %v", err)
	}
	if !bytes.Equal(verified.CanonicalBytes(), signed.CanonicalBytes()) ||
		!bytes.Equal(verified.SignedBytes(), signed.SignedBytes()) {
		t.Fatal("verified proposal did not preserve canonical bytes")
	}
	got := verified.Proposal()
	if got.EventID != testEventID ||
		got.SessionID != testSessionID ||
		got.WorkspaceID != testWorkspaceID ||
		got.Kind != KindTaskCreated ||
		got.CaptureLevel != CaptureAgentReported ||
		got.Origin.ActorType() != ActorAgent ||
		got.Origin.AgentSessionID() != testAgentSessionID {
		t.Fatalf("verified proposal = %#v", got)
	}
}

func TestParseAndVerifyChecksSignatureBeforeUnknownFieldRejection(t *testing.T) {
	t.Parallel()

	_, publicKey, privateKey := testIdentity(t)
	signed := mustSignedEvent(t, privateKey)

	changedWithoutResigning := addUnknownField(t, signed.CanonicalBytes(), json.RawMessage(`true`), nil)
	if _, err := ParseAndVerify(changedWithoutResigning, verificationContext(publicKey)); !errors.Is(err, codecommcrypto.ErrSignatureVerification) {
		t.Fatalf("changed unsigned extension error = %v, want signature verification failure", err)
	}

	signedWithUnknown := addUnknownField(t, signed.CanonicalBytes(), json.RawMessage(`true`), privateKey)
	if _, err := ParseAndVerify(signedWithUnknown, verificationContext(publicKey)); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("signed extension error = %v, want ErrUnknownField", err)
	}
}

func TestParseAndVerifyRejectsNoncanonicalWireJSON(t *testing.T) {
	t.Parallel()

	_, publicKey, privateKey := testIdentity(t)
	signed := mustSignedEvent(t, privateKey)
	noncanonical := append([]byte(" \n"), signed.CanonicalBytes()...)
	if _, err := ParseAndVerify(noncanonical, verificationContext(publicKey)); !errors.Is(err, ErrNoncanonicalEvent) {
		t.Fatalf("ParseAndVerify(noncanonical) error = %v, want ErrNoncanonicalEvent", err)
	}
}

func TestParseAndVerifyRejectsWrongBindingKeyAndSignatureEncoding(t *testing.T) {
	t.Parallel()

	_, publicKey, privateKey := testIdentity(t)
	_, otherPublicKey, _ := testIdentity(t)
	signed := mustSignedEvent(t, privateKey)

	tests := []struct {
		name    string
		input   []byte
		context VerificationContext
		want    error
	}{
		{"wrong session", signed.CanonicalBytes(), VerificationContext{SessionID: testEventID, WorkspaceID: testWorkspaceID, IdentityPublicKey: publicKey}, ErrSessionBinding},
		{"wrong workspace", signed.CanonicalBytes(), VerificationContext{SessionID: testSessionID, WorkspaceID: domain.UUIDv4("550e8400-e29b-41d4-a716-446655440001"), IdentityPublicKey: publicKey}, ErrSessionBinding},
		{"wrong public key", signed.CanonicalBytes(), verificationContext(otherPublicKey), ErrOriginKeyMismatch},
		{"padded signature", replaceSignature(t, signed.CanonicalBytes(), func(value string) string { return value + "=" }), verificationContext(publicKey), codec.ErrInvalidBase64URL},
		{"short signature", replaceSignature(t, signed.CanonicalBytes(), func(value string) string { return value[:len(value)-2] }), verificationContext(publicKey), codec.ErrDecodedLength},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseAndVerify(test.input, test.context); !errors.Is(err, test.want) {
				t.Fatalf("ParseAndVerify() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestInspectUnverifiedProposalIsStrictButDoesNotAuthenticate(
	t *testing.T,
) {
	t.Parallel()

	_, _, privateKey := testIdentity(t)
	signed := mustSignedEvent(t, privateKey)
	changedSignature := replaceSignature(
		t,
		signed.CanonicalBytes(),
		func(value string) string {
			replacement := byte('A')
			if value[0] == replacement {
				replacement = 'B'
			}
			return string(replacement) + value[1:]
		},
	)
	proposal, err := InspectUnverifiedProposal(changedSignature)
	if err != nil {
		t.Fatalf("InspectUnverifiedProposal(): %v", err)
	}
	if proposal.EventID != testEventID ||
		proposal.SessionID != testSessionID ||
		proposal.WorkspaceID != testWorkspaceID {
		t.Fatalf("inspected proposal = %#v", proposal)
	}

	withUnknown := addUnknownField(
		t,
		signed.CanonicalBytes(),
		json.RawMessage(`true`),
		nil,
	)
	if _, err := InspectUnverifiedProposal(
		withUnknown,
	); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("unknown field error = %v, want ErrUnknownField", err)
	}
	padded := replaceSignature(
		t,
		signed.CanonicalBytes(),
		func(value string) string { return value + "=" },
	)
	if _, err := InspectUnverifiedProposal(
		padded,
	); !errors.Is(err, codec.ErrInvalidBase64URL) {
		t.Fatalf(
			"padded signature error = %v, want ErrInvalidBase64URL",
			err,
		)
	}
}

func TestBuildProposalEnforcesKindCASAndEntityContracts(t *testing.T) {
	t.Parallel()

	deviceID, _, _ := testIdentity(t)
	agent := mustMCPBinding(t, deviceID, testAgentSessionID, nil)
	operator := mustOperatorBinding(t, deviceID, testBootID)

	missingCAS := validCommand(KindTaskUpdated)
	if _, err := BuildProposal(missingCAS, agent, validBuildContext()); !errors.Is(err, ErrExpectedEntityVersion) {
		t.Fatalf("missing CAS error = %v, want ErrExpectedEntityVersion", err)
	}

	unexpectedCAS := validCommand(KindTaskCreated)
	version := uint64(1)
	unexpectedCAS.ExpectedEntityVersion = &version
	if _, err := BuildProposal(unexpectedCAS, agent, validBuildContext()); !errors.Is(err, ErrExpectedEntityVersion) {
		t.Fatalf("unexpected CAS error = %v, want ErrExpectedEntityVersion", err)
	}

	wrongEntity := validCommand(KindMembershipRoleChanged)
	wrongEntity.ExpectedEntityVersion = &version
	if _, err := BuildProposal(wrongEntity, operator, validBuildContext()); !errors.Is(err, ErrInvalidEntityID) {
		t.Fatalf("wrong entity error = %v, want ErrInvalidEntityID", err)
	}
}

func TestAgentSessionStartBindsEntityAndFirstSequence(t *testing.T) {
	t.Parallel()

	deviceID, _, _ := testIdentity(t)
	binding := mustMCPBinding(t, deviceID, testAgentSessionID, nil)
	command := validCommand(KindAgentSessionStarted)

	if _, err := BuildProposal(command, binding, validBuildContext()); !errors.Is(err, ErrAgentStartBinding) {
		t.Fatalf("mismatched entity error = %v, want ErrAgentStartBinding", err)
	}

	command.EntityID = StringEntityID(string(testAgentSessionID))
	context := validBuildContext()
	context.OriginSequence = 2
	if _, err := BuildProposal(command, binding, context); !errors.Is(err, ErrAgentStartBinding) {
		t.Fatalf("sequence two error = %v, want ErrAgentStartBinding", err)
	}

	context.OriginSequence = 1
	if _, err := BuildProposal(command, binding, context); err != nil {
		t.Fatalf("valid agent start error = %v", err)
	}
}

func TestEventSizeLimitIncludesSignature(t *testing.T) {
	t.Parallel()

	deviceID, _, privateKey := testIdentity(t)
	binding := mustMCPBinding(t, deviceID, testAgentSessionID, nil)
	command := validCommand(KindTaskCreated)
	command.Payload = json.RawMessage(`{"body":"` + strings.Repeat("x", MaxEventBytes) + `"}`)
	if _, err := BuildProposal(command, binding, validBuildContext()); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("BuildProposal(oversized) error = %v, want ErrEventTooLarge", err)
	}

	command = validCommand(KindTaskCreated)
	proposal, err := BuildProposal(command, binding, validBuildContext())
	if err != nil {
		t.Fatalf("BuildProposal(valid) error = %v", err)
	}
	if _, err := Sign(proposal, privateKey); err != nil {
		t.Fatalf("Sign(valid) error = %v", err)
	}
}

func TestSignedProposalCopiesMutableInputsAndOutputs(t *testing.T) {
	t.Parallel()

	deviceID, publicKey, privateKey := testIdentity(t)
	binding := mustMCPBinding(t, deviceID, testAgentSessionID, nil)
	command := validCommand(KindTaskCreated)
	command.Actions = []Action{{
		Type:    ActionToolCall,
		Target:  "functions.exec_command",
		Summary: "ran a command",
		Status:  ActionSucceeded,
	}}
	proposal, err := BuildProposal(command, binding, validBuildContext())
	if err != nil {
		t.Fatalf("BuildProposal() error = %v", err)
	}
	command.Payload[0] = '['
	command.Actions[0].Summary = "changed"
	if string(proposal.Payload) != `{}` || proposal.Actions[0].Summary == "changed" {
		t.Fatal("BuildProposal aliases command storage")
	}

	signed, err := Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	bytesOne := signed.CanonicalBytes()
	bytesOne[0] = '['
	signatureOne := signed.OriginSignature()
	signatureOne[0] ^= 0xff
	proposalOne := signed.Proposal()
	proposalOne.Payload[0] = '['
	proposalOne.Actions[0].Summary = "changed"
	verified, err := ParseAndVerify(signed.CanonicalBytes(), verificationContext(publicKey))
	if err != nil {
		t.Fatalf("ParseAndVerify() after output mutation error = %v", err)
	}
	if string(verified.Proposal().Payload) != `{}` ||
		verified.Proposal().Actions[0].Summary == "changed" {
		t.Fatal("SignedEvent getters expose mutable internal storage")
	}
}

func TestBuildAndSignNormalizePayloadToSignedCanonicalBytes(t *testing.T) {
	t.Parallel()

	deviceID, publicKey, privateKey := testIdentity(t)
	binding := mustMCPBinding(t, deviceID, testAgentSessionID, nil)
	command := validCommand(KindTaskCreated)
	command.Payload = json.RawMessage("{ \"z\": 2, \"a\": 1 }")

	proposal, err := BuildProposal(command, binding, validBuildContext())
	if err != nil {
		t.Fatalf("BuildProposal() error = %v", err)
	}
	const want = `{"a":1,"z":2}`
	if string(proposal.Payload) != want {
		t.Fatalf("BuildProposal().Payload = %s, want %s", proposal.Payload, want)
	}

	proposal.Payload = json.RawMessage("{\n\"z\":2,\"a\":1}")
	signed, err := Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if string(signed.Proposal().Payload) != want {
		t.Fatalf("Sign().Proposal().Payload = %s, want %s", signed.Proposal().Payload, want)
	}
	verified, err := ParseAndVerify(signed.CanonicalBytes(), verificationContext(publicKey))
	if err != nil {
		t.Fatalf("ParseAndVerify() error = %v", err)
	}
	if string(verified.Proposal().Payload) != string(signed.Proposal().Payload) {
		t.Fatal("locally signed and parsed proposal payload bytes differ")
	}
}

func validCommand(kind Kind) Command {
	return Command{
		Kind:             kind,
		EntityID:         StringEntityID(testEntityID),
		RationaleSummary: "",
		Actions:          []Action{},
		Payload:          json.RawMessage(`{}`),
		Redaction: Redaction{
			Policy:        RedactionDefault,
			FieldsRemoved: []RedactionField{},
		},
	}
}

func validBuildContext() BuildContext {
	return BuildContext{
		EventID:        testEventID,
		SessionID:      testSessionID,
		WorkspaceID:    testWorkspaceID,
		CreatedAt:      domain.Timestamp("2026-08-10T12:13:14.123Z"),
		OriginSequence: 1,
	}
}

func testIdentity(t testing.TB) (domain.DeviceID, []byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := codecommcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() error = %v", err)
	}
	text, err := codec.DeriveDeviceID(ed25519.PublicKey(publicKey))
	if err != nil {
		t.Fatalf("DeriveDeviceID() error = %v", err)
	}
	deviceID, err := domain.ParseDeviceID(text)
	if err != nil {
		t.Fatalf("ParseDeviceID() error = %v", err)
	}
	return deviceID, publicKey, privateKey
}

func mustMCPBinding(
	t testing.TB,
	deviceID domain.DeviceID,
	agentSessionID domain.UUIDv7,
	profile *string,
) Binding {
	t.Helper()
	binding, err := NewMCPBinding(deviceID, agentSessionID, profile)
	if err != nil {
		t.Fatalf("NewMCPBinding() error = %v", err)
	}
	return binding
}

func mustOperatorBinding(t testing.TB, deviceID domain.DeviceID, bootID domain.UUIDv7) Binding {
	t.Helper()
	authority, err := NewLocalAuthority(deviceID, bootID)
	if err != nil {
		t.Fatalf("NewLocalAuthority() error = %v", err)
	}
	binding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatalf("OperatorBinding() error = %v", err)
	}
	return binding
}

func mustDaemonBinding(t testing.TB, deviceID domain.DeviceID, bootID domain.UUIDv7) Binding {
	t.Helper()
	authority, err := NewLocalAuthority(deviceID, bootID)
	if err != nil {
		t.Fatalf("NewLocalAuthority() error = %v", err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("DaemonBinding() error = %v", err)
	}
	return binding
}

func mustSignedEvent(t testing.TB, privateKey []byte) SignedEvent {
	t.Helper()
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Ed25519PublicKeyFromPrivateKey() error = %v", err)
	}
	text, err := codec.DeriveDeviceID(ed25519.PublicKey(publicKey))
	if err != nil {
		t.Fatalf("DeriveDeviceID() error = %v", err)
	}
	deviceID := domain.DeviceID(text)
	binding := mustMCPBinding(t, deviceID, testAgentSessionID, nil)
	proposal, err := BuildProposal(validCommand(KindTaskCreated), binding, validBuildContext())
	if err != nil {
		t.Fatalf("BuildProposal() error = %v", err)
	}
	signed, err := Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return signed
}

func verificationContext(publicKey []byte) VerificationContext {
	return VerificationContext{
		SessionID:         testSessionID,
		WorkspaceID:       testWorkspaceID,
		IdentityPublicKey: publicKey,
	}
}

func addUnknownField(
	t *testing.T,
	complete []byte,
	value json.RawMessage,
	privateKey []byte,
) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(complete, &object); err != nil {
		t.Fatalf("unmarshal signed event: %v", err)
	}
	delete(object, "origin_signature")
	object["unknown_extension"] = value
	bodyJSON, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal body with extension: %v", err)
	}
	body, err := codec.CanonicalizeSignedObject(bodyJSON)
	if err != nil {
		t.Fatalf("canonicalize body with extension: %v", err)
	}
	var signature []byte
	if privateKey == nil {
		var original map[string]json.RawMessage
		if err := json.Unmarshal(complete, &original); err != nil {
			t.Fatalf("unmarshal original event: %v", err)
		}
		var encoded string
		if err := json.Unmarshal(original["origin_signature"], &encoded); err != nil {
			t.Fatalf("decode original signature: %v", err)
		}
		signature, err = codec.DecodeBase64URLExact(encoded, codecommcrypto.Ed25519SignatureSize)
		if err != nil {
			t.Fatalf("decode original signature bytes: %v", err)
		}
	} else {
		signature, err = codecommcrypto.SignEd25519(
			privateKey,
			codec.SignatureEventOrigin,
			body,
		)
		if err != nil {
			t.Fatalf("sign body with extension: %v", err)
		}
	}
	object["origin_signature"] = json.RawMessage(`"` + codec.EncodeBase64URL(signature) + `"`)
	withSignature, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal complete event with extension: %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(withSignature)
	if err != nil {
		t.Fatalf("canonicalize complete event with extension: %v", err)
	}
	return canonical
}

func replaceSignature(t *testing.T, input []byte, replace func(string) string) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(input, &object); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	var signature string
	if err := json.Unmarshal(object["origin_signature"], &signature); err != nil {
		t.Fatalf("unmarshal signature: %v", err)
	}
	encoded, err := json.Marshal(replace(signature))
	if err != nil {
		t.Fatalf("marshal changed signature: %v", err)
	}
	object["origin_signature"] = encoded
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal changed event: %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		t.Fatalf("canonicalize changed event: %v", err)
	}
	return canonical
}
