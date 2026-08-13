package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
)

func TestEveryRegisteredKindCanBeConstructedOnlyUnderItsContract(t *testing.T) {
	t.Parallel()

	deviceID, _, _ := testIdentity(t)
	bindings := map[ActorType]Binding{
		ActorAgent:  mustMCPBinding(t, deviceID, testAgentSessionID, nil),
		ActorHuman:  mustOperatorBinding(t, deviceID, testBootID),
		ActorDaemon: mustDaemonBinding(t, deviceID, testBootID),
	}
	version := uint64(1)

	for _, kind := range Kinds() {
		spec, ok := LookupKind(kind)
		if !ok {
			t.Fatalf("LookupKind(%q) missing", kind)
		}
		command := validCommand(kind)
		command.EntityID = validEntityIDFor(spec.EntityIDType(), deviceID)
		switch spec.CASPolicy() {
		case CASRequired:
			command.ExpectedEntityVersion = &version
		case CASForbidden, CASConditional, CASPayload:
		default:
			t.Fatalf("unknown CAS policy %q", spec.CASPolicy())
		}
		if kind == KindActivityRecorded {
			command.RationaleSummary = "recorded activity"
		}
		if kind == KindAgentSessionStarted {
			command.EntityID = StringEntityID(string(testAgentSessionID))
		}
		allowedActors := spec.AllowedActors()
		if len(allowedActors) == 0 {
			t.Fatalf("%q has no actors", kind)
		}

		t.Run(string(kind), func(t *testing.T) {
			for _, actor := range allowedActors {
				if _, err := BuildProposal(
					command,
					bindings[actor],
					validBuildContext(),
				); err != nil {
					t.Errorf("BuildProposal(%q, %q) error = %v", kind, actor, err)
				}
			}
			for _, actor := range ActorTypes() {
				if spec.AllowsActor(actor) {
					continue
				}
				if _, err := BuildProposal(
					command,
					bindings[actor],
					validBuildContext(),
				); !errors.Is(err, ErrActorNotAllowed) {
					t.Errorf(
						"BuildProposal(%q, %q) error = %v, want ErrActorNotAllowed",
						kind,
						actor,
						err,
					)
				}
			}

			wrongCAS := command
			switch spec.CASPolicy() {
			case CASRequired:
				wrongCAS.ExpectedEntityVersion = nil
			case CASForbidden, CASPayload:
				wrongCAS.ExpectedEntityVersion = &version
			case CASConditional:
				if _, err := BuildProposal(
					wrongCAS,
					bindings[allowedActors[0]],
					validBuildContext(),
				); err != nil {
					t.Errorf("conditional CAS without token error = %v", err)
				}
				wrongCAS.ExpectedEntityVersion = &version
				if _, err := BuildProposal(
					wrongCAS,
					bindings[allowedActors[0]],
					validBuildContext(),
				); err != nil {
					t.Errorf("conditional CAS with token error = %v", err)
				}
				return
			}
			if _, err := BuildProposal(
				wrongCAS,
				bindings[allowedActors[0]],
				validBuildContext(),
			); !errors.Is(err, ErrExpectedEntityVersion) {
				t.Errorf("wrong CAS error = %v, want ErrExpectedEntityVersion", err)
			}
		})
	}
}

func TestEveryEntityIDTypeRejectsWrongSyntax(t *testing.T) {
	t.Parallel()

	deviceID, _, _ := testIdentity(t)
	bindings := map[ActorType]Binding{
		ActorAgent:  mustMCPBinding(t, deviceID, testAgentSessionID, nil),
		ActorHuman:  mustOperatorBinding(t, deviceID, testBootID),
		ActorDaemon: mustDaemonBinding(t, deviceID, testBootID),
	}
	version := uint64(1)
	representatives := []Kind{
		KindTaskUpdated,
		KindMembershipRoleChanged,
		KindPlanCurrentSelected,
		KindWorkspaceConflictResolved,
		KindControlFileChangeProposed,
		KindActivityRecorded,
	}
	for _, kind := range representatives {
		spec, _ := LookupKind(kind)
		command := validCommand(kind)
		command.EntityID = NullEntityID()
		if spec.EntityIDType() == EntityNull {
			command.EntityID = StringEntityID(testEntityID)
			command.RationaleSummary = "activity"
		}
		if spec.CASPolicy() == CASRequired {
			command.ExpectedEntityVersion = &version
		}
		actor := spec.AllowedActors()[0]
		if _, err := BuildProposal(
			command,
			bindings[actor],
			validBuildContext(),
		); !errors.Is(err, ErrInvalidEntityID) {
			t.Errorf("%q wrong entity error = %v, want ErrInvalidEntityID", kind, err)
		}
	}
}

func TestDecodeLocalCommandRoundTripAndCopiesInput(t *testing.T) {
	t.Parallel()

	input := []byte(`{
		"kind":"task.updated",
		"entity_id":"` + testEntityID + `",
		"expected_entity_version":7,
		"rationale_summary":"Applied the reviewed change.",
		"actions":[{
			"type":"artifact.created",
			"target":"build/report.json",
			"summary":"created report",
			"status":"succeeded",
			"task_id":"01890f47-3e72-7000-8000-000000000005",
			"artifact_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"started_at":"2026-08-10T12:13:14.123Z",
			"duration_ms":0
		}],
		"payload":{"title":"reviewed"},
		"redaction":{"policy":"default","fields_removed":["arguments","output"]}
	}`)
	command, err := DecodeLocalCommand(input)
	if err != nil {
		t.Fatalf("DecodeLocalCommand() error = %v", err)
	}
	if command.Kind != KindTaskUpdated ||
		command.ExpectedEntityVersion == nil ||
		*command.ExpectedEntityVersion != 7 ||
		len(command.Actions) != 1 ||
		command.Actions[0].ArtifactDigest == nil ||
		command.Actions[0].DurationMS == nil ||
		command.Redaction.FieldsRemoved[1] != RedactionOutput {
		t.Fatalf("decoded command = %#v", command)
	}
	input[0] = '['
	if string(command.Payload) != `{"title":"reviewed"}` {
		t.Fatalf("decoded payload changed after input mutation: %s", command.Payload)
	}
}

func TestDecodeLocalCommandRejectsClosedSchemaViolations(t *testing.T) {
	t.Parallel()

	valid := `{
		"kind":"task.created",
		"entity_id":"` + testEntityID + `",
		"rationale_summary":"",
		"actions":[],
		"payload":{},
		"redaction":{"policy":"default","fields_removed":[]}
	}`
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{"unknown field", strings.Replace(valid, `"kind":`, `"actor_type":"human","kind":`, 1), ErrUnknownField},
		{"missing field", strings.Replace(valid, `"actions":[],`, "", 1), ErrMissingField},
		{"null expected version", strings.Replace(valid, `"kind":`, `"expected_entity_version":null,"kind":`, 1), ErrExpectedEntityVersion},
		{"null rationale", strings.Replace(valid, `"rationale_summary":""`, `"rationale_summary":null`, 1), ErrInvalidEnvelope},
		{"unknown action field", strings.Replace(valid, `"actions":[]`, `"actions":[{"type":"tool.call","target":"tool","summary":"used","status":"succeeded","arguments":"secret"}]`, 1), ErrUnknownField},
		{"null optional action", strings.Replace(valid, `"actions":[]`, `"actions":[{"type":"tool.call","target":"tool","summary":"used","status":"succeeded","duration_ms":null}]`, 1), ErrInvalidEnvelope},
		{"unknown redaction field", strings.Replace(valid, `"fields_removed":[]`, `"fields_removed":[],"reason":"none"`, 1), ErrUnknownField},
		{"null redaction fields", strings.Replace(valid, `"fields_removed":[]`, `"fields_removed":null`, 1), ErrInvalidEnvelope},
		{"null actions", strings.Replace(valid, `"actions":[]`, `"actions":null`, 1), ErrInvalidEnvelope},
		{"array payload", strings.Replace(valid, `"payload":{}`, `"payload":[]`, 1), ErrInvalidPayload},
		{"unknown kind", strings.Replace(valid, `"task.created"`, `"task.deleted"`, 1), ErrInvalidKind},
		{"duplicate key", strings.Replace(valid, `"kind":"task.created",`, `"kind":"task.created","kind":"task.created",`, 1), codec.ErrDuplicateKey},
		{"trailing data", valid + `{}`, codec.ErrTrailingData},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeLocalCommand([]byte(test.input)); !errors.Is(err, test.want) {
				t.Fatalf("DecodeLocalCommand() error = %v, want %v", err, test.want)
			}
		})
	}

	oversized := bytes.Repeat([]byte{' '}, MaxLocalCommandBytes+1)
	if _, err := DecodeLocalCommand(oversized); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("oversized local command error = %v, want ErrEventTooLarge", err)
	}
}

func TestVerifiedDomainViolationsRemainAvailableToReducers(t *testing.T) {
	t.Parallel()

	_, publicKey, privateKey := testIdentity(t)
	base := mustSignedEvent(t, privateKey)
	version := json.RawMessage(`1`)
	tests := []struct {
		name   string
		mutate func(map[string]json.RawMessage)
		want   error
	}{
		{
			name: "disallowed actor for kind",
			mutate: func(object map[string]json.RawMessage) {
				object["kind"] = json.RawMessage(`"task.cancelled"`)
				object["expected_entity_version"] = version
			},
			want: ErrActorNotAllowed,
		},
		{
			name: "missing CAS",
			mutate: func(object map[string]json.RawMessage) {
				object["kind"] = json.RawMessage(`"task.updated"`)
			},
			want: ErrExpectedEntityVersion,
		},
		{
			name: "wrong entity type",
			mutate: func(object map[string]json.RawMessage) {
				object["kind"] = json.RawMessage(`"workspace.conflict.resolved"`)
				object["expected_entity_version"] = version
			},
			want: ErrInvalidEntityID,
		},
		{
			name: "unknown kind",
			mutate: func(object map[string]json.RawMessage) {
				object["kind"] = json.RawMessage(`"task.deleted"`)
			},
			want: ErrInvalidKind,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := resignEvent(t, base.CanonicalBytes(), privateKey, test.mutate)
			verified, err := ParseAndVerify(input, verificationContext(publicKey))
			if err != nil {
				t.Fatalf("ParseAndVerify() transport error = %v", err)
			}
			if err := verified.Proposal().ValidateKindContract(); !errors.Is(err, test.want) {
				t.Fatalf("ValidateKindContract() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseAndVerifyRejectsSignedNestedUnknownAndMalformedFields(t *testing.T) {
	t.Parallel()

	_, publicKey, privateKey := testIdentity(t)
	base := mustSignedEvent(t, privateKey)
	tests := []struct {
		name   string
		mutate func(map[string]json.RawMessage)
		want   error
	}{
		{
			name: "unknown origin field",
			mutate: func(object map[string]json.RawMessage) {
				var origin map[string]json.RawMessage
				if err := json.Unmarshal(object["origin"], &origin); err != nil {
					t.Fatal(err)
				}
				origin["claimed_role"] = json.RawMessage(`"owner"`)
				object["origin"] = mustJSON(t, origin)
			},
			want: ErrUnknownField,
		},
		{
			name: "capture mismatch",
			mutate: func(object map[string]json.RawMessage) {
				object["capture_level"] = json.RawMessage(`"human_reported"`)
			},
			want: ErrInvalidEnvelope,
		},
		{
			name: "null expected version",
			mutate: func(object map[string]json.RawMessage) {
				object["expected_entity_version"] = json.RawMessage(`null`)
			},
			want: ErrExpectedEntityVersion,
		},
		{
			name: "invalid payload",
			mutate: func(object map[string]json.RawMessage) {
				object["payload"] = json.RawMessage(`[]`)
			},
			want: ErrInvalidPayload,
		},
		{
			name: "wrong frozen apply level",
			mutate: func(object map[string]json.RawMessage) {
				object["min_apply_level"] = json.RawMessage(`2`)
			},
			want: ErrInvalidEnvelope,
		},
		{
			name: "null rationale",
			mutate: func(object map[string]json.RawMessage) {
				object["rationale_summary"] = json.RawMessage(`null`)
			},
			want: ErrInvalidEnvelope,
		},
		{
			name: "null redaction fields",
			mutate: func(object map[string]json.RawMessage) {
				var redaction map[string]json.RawMessage
				if err := json.Unmarshal(object["redaction"], &redaction); err != nil {
					t.Fatal(err)
				}
				redaction["fields_removed"] = json.RawMessage(`null`)
				object["redaction"] = mustJSON(t, redaction)
			},
			want: ErrInvalidEnvelope,
		},
		{
			name: "Raft provenance prohibited",
			mutate: func(object map[string]json.RawMessage) {
				object["log_index"] = json.RawMessage(`17`)
			},
			want: ErrUnknownField,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := resignEvent(t, base.CanonicalBytes(), privateKey, test.mutate)
			if _, err := ParseAndVerify(input, verificationContext(publicKey)); !errors.Is(err, test.want) {
				t.Fatalf("ParseAndVerify() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseAndVerifyChecksKnownBoundsBeforeSignatureWork(t *testing.T) {
	t.Parallel()

	_, publicKey, privateKey := testIdentity(t)
	base := mustSignedEvent(t, privateKey)
	oversizedRationale := replaceRawField(
		t,
		base.CanonicalBytes(),
		"rationale_summary",
		mustJSON(t, strings.Repeat("x", MaxRationaleSummaryBytes+1)),
	)
	if _, err := ParseAndVerify(
		oversizedRationale,
		verificationContext(publicKey),
	); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf(
			"oversized rationale with stale signature error = %v, want structural rejection",
			err,
		)
	}

	actions := make([]map[string]string, MaxActions+1)
	for index := range actions {
		actions[index] = map[string]string{
			"type":    "tool.call",
			"target":  "tool",
			"summary": "called tool",
			"status":  "succeeded",
		}
	}
	tooManyActions := replaceRawField(
		t,
		base.CanonicalBytes(),
		"actions",
		mustJSON(t, actions),
	)
	if _, err := ParseAndVerify(
		tooManyActions,
		verificationContext(publicKey),
	); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf(
			"too many actions with stale signature error = %v, want structural rejection",
			err,
		)
	}
}

func TestProposalEnvelopeValidationRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	deviceID, _, _ := testIdentity(t)
	binding := mustMCPBinding(t, deviceID, testAgentSessionID, nil)
	valid, err := BuildProposal(validCommand(KindTaskCreated), binding, validBuildContext())
	if err != nil {
		t.Fatalf("BuildProposal() error = %v", err)
	}
	invalidUTF8 := string([]byte{0xff})
	zero := uint64(0)
	tests := []struct {
		name   string
		mutate func(*Proposal)
		want   error
	}{
		{"schema", func(p *Proposal) { p.SchemaVersion = 2 }, ErrInvalidEnvelope},
		{"apply level zero", func(p *Proposal) { p.MinApplyLevel = 0 }, ErrInvalidEnvelope},
		{"apply level high", func(p *Proposal) { p.MinApplyLevel = MaxApplyLevel + 1 }, ErrInvalidEnvelope},
		{"event ID", func(p *Proposal) { p.EventID = "" }, ErrInvalidEnvelope},
		{"session ID", func(p *Proposal) { p.SessionID = "" }, ErrInvalidEnvelope},
		{"workspace ID", func(p *Proposal) { p.WorkspaceID = "" }, ErrInvalidEnvelope},
		{"timestamp", func(p *Proposal) { p.CreatedAt = "2026-08-10T12:13:14+00:00" }, ErrInvalidEnvelope},
		{"kind grammar", func(p *Proposal) { p.Kind = "Task.Created" }, ErrInvalidEnvelope},
		{"entity general form", func(p *Proposal) { p.EntityID = StringEntityID("") }, ErrInvalidEnvelope},
		{"origin", func(p *Proposal) { p.Origin = Origin{} }, ErrInvalidOrigin},
		{"expected version", func(p *Proposal) { p.ExpectedEntityVersion = &zero }, ErrExpectedEntityVersion},
		{"rationale UTF-8", func(p *Proposal) { p.RationaleSummary = invalidUTF8 }, ErrInvalidEnvelope},
		{"capture mismatch", func(p *Proposal) { p.CaptureLevel = CaptureHumanReported }, ErrInvalidEnvelope},
		{"nil actions", func(p *Proposal) { p.Actions = nil }, ErrInvalidEnvelope},
		{"too many actions", func(p *Proposal) { p.Actions = make([]Action, MaxActions+1) }, ErrInvalidEnvelope},
		{"invalid action", func(p *Proposal) { p.Actions = []Action{{}} }, ErrInvalidAction},
		{"nil payload", func(p *Proposal) { p.Payload = nil }, ErrInvalidPayload},
		{"bad redaction", func(p *Proposal) { p.Redaction = Redaction{} }, ErrInvalidRedaction},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			proposal := cloneProposal(valid)
			test.mutate(&proposal)
			if err := proposal.ValidateEnvelope(); !errors.Is(err, test.want) {
				t.Fatalf("ValidateEnvelope() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSignRejectsInvalidProposalKeyAndKeyBinding(t *testing.T) {
	t.Parallel()

	deviceID, _, privateKey := testIdentity(t)
	binding := mustMCPBinding(t, deviceID, testAgentSessionID, nil)
	proposal, err := BuildProposal(validCommand(KindTaskCreated), binding, validBuildContext())
	if err != nil {
		t.Fatalf("BuildProposal() error = %v", err)
	}
	_, _, otherPrivateKey := testIdentity(t)

	if _, err := Sign(proposal, otherPrivateKey); !errors.Is(err, ErrOriginKeyMismatch) {
		t.Fatalf("Sign(other key) error = %v, want ErrOriginKeyMismatch", err)
	}
	if _, err := Sign(proposal, privateKey[:len(privateKey)-1]); !errors.Is(err, codecommcrypto.ErrInvalidEd25519PrivateKey) {
		t.Fatalf("Sign(short key) error = %v, want invalid key", err)
	}
	proposal.SchemaVersion = 2
	if _, err := Sign(proposal, privateKey); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Sign(invalid proposal) error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestEntityIDJSONAndCaptureEnums(t *testing.T) {
	t.Parallel()

	nullID := NullEntityID()
	if !nullID.IsNull() {
		t.Fatal("NullEntityID is not null")
	}
	encoded, err := json.Marshal(nullID)
	if err != nil || string(encoded) != "null" {
		t.Fatalf("Marshal(null) = %s, %v", encoded, err)
	}
	var decoded EntityID
	if err := json.Unmarshal([]byte(`"`+testEntityID+`"`), &decoded); err != nil {
		t.Fatalf("Unmarshal(string entity) error = %v", err)
	}
	if value, present := decoded.Value(); !present || value != testEntityID {
		t.Fatalf("decoded entity = %q, %t", value, present)
	}
	if err := json.Unmarshal([]byte(`7`), &decoded); !errors.Is(err, ErrInvalidEntityID) {
		t.Fatalf("Unmarshal(number) error = %v, want ErrInvalidEntityID", err)
	}
	var nilEntity *EntityID
	if err := nilEntity.UnmarshalJSON([]byte(`null`)); !errors.Is(err, ErrInvalidEntityID) {
		t.Fatalf("nil UnmarshalJSON error = %v, want ErrInvalidEntityID", err)
	}

	for _, level := range []CaptureLevel{
		CaptureAgentReported,
		CaptureHumanReported,
		CaptureDaemonObserved,
	} {
		if !level.Valid() {
			t.Errorf("%q is not valid", level)
		}
	}
	if CaptureLevel("reported").Valid() {
		t.Fatal("unknown capture level is valid")
	}
}

func TestParseAndVerifyMalformedOuterContract(t *testing.T) {
	t.Parallel()

	_, publicKey, privateKey := testIdentity(t)
	base := mustSignedEvent(t, privateKey)
	tests := []struct {
		name    string
		input   []byte
		context VerificationContext
		want    error
	}{
		{
			name:    "missing signature",
			input:   canonicalWithoutField(t, base.CanonicalBytes(), "origin_signature"),
			context: verificationContext(publicKey),
			want:    ErrMissingField,
		},
		{
			name: "signature wrong JSON type",
			input: replaceRawField(
				t,
				base.CanonicalBytes(),
				"origin_signature",
				json.RawMessage(`7`),
			),
			context: verificationContext(publicKey),
			want:    ErrInvalidEnvelope,
		},
		{
			name:    "invalid session context",
			input:   base.CanonicalBytes(),
			context: VerificationContext{WorkspaceID: testWorkspaceID, IdentityPublicKey: publicKey},
			want:    ErrSessionBinding,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseAndVerify(test.input, test.context); !errors.Is(err, test.want) {
				t.Fatalf("ParseAndVerify() error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := ParseAndVerify(
		bytes.Repeat([]byte{'x'}, MaxEventBytes+1),
		verificationContext(publicKey),
	); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("oversized event error = %v, want ErrEventTooLarge", err)
	}
}

func validEntityIDFor(entityType EntityIDType, deviceID domain.DeviceID) EntityID {
	switch entityType {
	case EntityUUIDv7:
		return StringEntityID(testEntityID)
	case EntityDeviceID:
		return StringEntityID(string(deviceID))
	case EntitySessionID:
		return StringEntityID(string(testSessionID))
	case EntityConflictID:
		return StringEntityID("ccf1" + strings.Repeat("b", 64))
	case EntityRepositoryPath:
		return StringEntityID("AGENTS.md")
	case EntityNull:
		return NullEntityID()
	default:
		return StringEntityID("invalid")
	}
}

func resignEvent(
	t *testing.T,
	complete []byte,
	privateKey []byte,
	mutate func(map[string]json.RawMessage),
) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(complete, &object); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	delete(object, "origin_signature")
	mutate(object)
	bodyJSON, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal mutated body: %v", err)
	}
	body, err := codec.CanonicalizeSignedObject(bodyJSON)
	if err != nil {
		t.Fatalf("canonicalize mutated body: %v", err)
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureEventOrigin,
		body,
	)
	if err != nil {
		t.Fatalf("sign mutated body: %v", err)
	}
	object["origin_signature"] = mustJSON(t, codec.EncodeBase64URL(signature))
	completeJSON, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal mutated event: %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(completeJSON)
	if err != nil {
		t.Fatalf("canonicalize mutated event: %v", err)
	}
	return canonical
}

func canonicalWithoutField(t *testing.T, input []byte, field string) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(input, &object); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	delete(object, field)
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		t.Fatalf("canonicalize event: %v", err)
	}
	return canonical
}

func replaceRawField(
	t *testing.T,
	input []byte,
	field string,
	value json.RawMessage,
) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(input, &object); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	object[field] = value
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		t.Fatalf("canonicalize event: %v", err)
	}
	return canonical
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T): %v", value, err)
	}
	return raw
}
