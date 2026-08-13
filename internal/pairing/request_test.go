package pairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const testAttemptID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000301")

func TestPairingRequestBuildParseVerify(t *testing.T) {
	t.Parallel()

	invite, core, exporter := validRequestFixture(t)
	request, err := BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}
	inviteValue := invite.Invite()
	inviteSecretText := codec.EncodeBase64URL(inviteValue.Secret[:])
	if bytes.Contains(request.CanonicalBytes(), []byte(inviteSecretText)) {
		t.Fatal("pairing request transmitted the invite secret")
	}

	parsed, err := ParseRequest(request.CanonicalBytes())
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if parsed.InviteID() != invite.Invite().InviteID {
		t.Fatalf("InviteID() = %q, want %q", parsed.InviteID(), invite.Invite().InviteID)
	}
	verified, err := parsed.Verify(invite, exporter)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !reflect.DeepEqual(verified.Core().Value(), core.Value()) {
		t.Fatalf("verified core = %#v, want %#v", verified.Core().Value(), core.Value())
	}
	if verified.SAS() == "" || verified.TranscriptHash() == [sha256.Size]byte{} {
		t.Fatal("verified request omitted transcript outputs")
	}

	mutatedCore := verified.Core()
	mutatedBytes := mutatedCore.CanonicalBytes()
	mutatedBytes[0] ^= 1
	if bytes.Equal(verified.Core().CanonicalBytes(), mutatedBytes) {
		t.Fatal("verified core exposes mutable canonical storage")
	}
	mutatedRequest := parsed.CanonicalBytes()
	mutatedRequest[0] ^= 1
	if bytes.Equal(parsed.CanonicalBytes(), mutatedRequest) {
		t.Fatal("request exposes mutable canonical storage")
	}
}

func TestPairingTranscriptGoldenVector(t *testing.T) {
	t.Parallel()

	invite, core, exporter := validRequestFixture(t)
	request, err := BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}
	verified, err := request.Verify(invite, exporter)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	const wantCore = `{"attempt_id":"01890f47-3e72-7000-8000-000000000301","daemon_version":"1.2.3-rc.1+build.7","initial_epoch_binding":{"binding_signature":"vN4vdVudOatrsqS3Skic53kf9tHxizkgtxprBcAIrg5Gt-CfzZVZ6hk8zitPsEwGrTohnXQFQctpu564Eio-BA","epoch":1,"epoch_public_key":"ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw","key_digest":"xblA7T9lw5GWXegpX8XSX0dPpXtI026xCtNjuFOcG3k"},"joiner_device_id":"cc1b62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b76709","joiner_identity_public_key":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E","max_apply_level":1,"schema_version":1}`
	const wantRequest = `{"invite_digest":"Iwa8gQWPBKn29AVAJobw4hj1cEha_KYzTWE0olL1g9g","invite_id":"01890f47-3e72-7000-8000-000000000101","proof":"E40I9sGMJM1-o9RMrs5jdjdRxu4CcF2H3logdGM8Ae0","request_core":{"attempt_id":"01890f47-3e72-7000-8000-000000000301","daemon_version":"1.2.3-rc.1+build.7","initial_epoch_binding":{"binding_signature":"vN4vdVudOatrsqS3Skic53kf9tHxizkgtxprBcAIrg5Gt-CfzZVZ6hk8zitPsEwGrTohnXQFQctpu564Eio-BA","epoch":1,"epoch_public_key":"ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw","key_digest":"xblA7T9lw5GWXegpX8XSX0dPpXtI026xCtNjuFOcG3k"},"joiner_device_id":"cc1b62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b76709","joiner_identity_public_key":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E","max_apply_level":1,"schema_version":1},"schema_version":1}`
	const wantTranscript = "a11be63c6068abe2cae9010e519a3a99893d76c6e237ce4f5b4f0c3016201858"
	const wantSAS = "7027 3918 8059 0607 6520"
	if string(core.CanonicalBytes()) != wantCore {
		t.Fatalf("golden request core = %s", core.CanonicalBytes())
	}
	if string(request.CanonicalBytes()) != wantRequest {
		t.Fatalf("golden request = %s", request.CanonicalBytes())
	}
	transcriptHash := verified.TranscriptHash()
	if got := hex.EncodeToString(transcriptHash[:]); got != wantTranscript {
		t.Fatalf("golden transcript = %s", got)
	}
	if verified.SAS() != wantSAS {
		t.Fatalf("golden SAS = %s", verified.SAS())
	}
}

func TestPairingProofIsConnectionBound(t *testing.T) {
	t.Parallel()

	invite, core, exporter := validRequestFixture(t)
	request, err := BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}
	otherExporter := bytes.Repeat([]byte{0x56}, ExporterSize)
	if _, err := request.Verify(invite, otherExporter); !errors.Is(err, ErrInviteProof) {
		t.Fatalf("Verify(second connection) error = %v, want %v", err, ErrInviteProof)
	}
	if _, err := BuildRequest(invite, core, exporter[:ExporterSize-1]); !errors.Is(err, ErrInvalidTranscript) {
		t.Fatalf("BuildRequest(short exporter) error = %v, want %v", err, ErrInvalidTranscript)
	}
}

func TestFailedProofRetainsDurableAttemptContext(t *testing.T) {
	t.Parallel()

	invite, core, exporter := validRequestFixture(t)
	request, err := BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}
	request.proof[0] ^= 1
	request.canonical, err = encodeRequest(request)
	if err != nil {
		t.Fatalf("encodeRequest() error = %v", err)
	}
	parsed, err := ParseRequest(request.CanonicalBytes())
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	verificationContext, err := invite.VerificationContext()
	if err != nil {
		t.Fatalf("VerificationContext() error = %v", err)
	}
	attempt, err := parsed.PrepareVerification(verificationContext, exporter)
	if err != nil {
		t.Fatalf("PrepareVerification() error = %v", err)
	}
	inviteValue := invite.Invite()
	defer clear(inviteValue.Secret[:])
	if _, err := attempt.VerifyProof(inviteValue.Secret); !errors.Is(err, ErrInviteProof) {
		t.Fatalf("VerifyProof() error = %v, want %v", err, ErrInviteProof)
	}
	if !reflect.DeepEqual(attempt.Core().Value(), core.Value()) ||
		attempt.InviteID() != inviteValue.InviteID ||
		attempt.InviteDigest() != invite.Digest() ||
		attempt.RequestDigest() != request.Digest() ||
		attempt.TranscriptHash() == [sha256.Size]byte{} {
		t.Fatalf("failed proof attempt lost durable context: %#v", attempt)
	}
}

func TestVerificationContextReconstructsPersistedInviteFields(t *testing.T) {
	t.Parallel()

	invite, core, exporter := validRequestFixture(t)
	request, err := BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}
	value := invite.Invite()
	defer clear(value.Secret[:])
	verificationContext, err := NewVerificationContext(
		value.InviteID,
		value.SessionID,
		invite.Digest(),
		value.InviterIdentityPublicKey[:],
		value.SubjectDeviceID,
		value.InitialCredentialEpoch,
	)
	if err != nil {
		t.Fatalf("NewVerificationContext() error = %v", err)
	}
	attempt, err := request.PrepareVerification(verificationContext, exporter)
	if err != nil {
		t.Fatalf("PrepareVerification() error = %v", err)
	}
	verified, err := attempt.VerifyProof(value.Secret)
	if err != nil {
		t.Fatalf("VerifyProof() error = %v", err)
	}
	if verified.SAS() == "" {
		t.Fatal("reconstructed verification omitted SAS")
	}
}

func TestPairingRequestRejectsProofAndInviteMutation(t *testing.T) {
	t.Parallel()

	invite, core, exporter := validRequestFixture(t)
	request, err := BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}
	mutated := request.clone()
	mutated.proof[0] ^= 1
	mutated.canonical, err = encodeRequest(mutated)
	if err != nil {
		t.Fatalf("encodeRequest() error = %v", err)
	}
	parsed, err := ParseRequest(mutated.CanonicalBytes())
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if _, err := parsed.Verify(invite, exporter); !errors.Is(err, ErrInviteProof) {
		t.Fatalf("Verify(mutated proof) error = %v, want %v", err, ErrInviteProof)
	}

	otherValue := invite.Invite()
	otherValue.InviteID = "01890f47-3e72-7000-8000-000000000302"
	_, _, inviterPrivateKey := validInvite(t)
	otherInvite, err := SignInvite(otherValue, inviterPrivateKey)
	if err != nil {
		t.Fatalf("SignInvite(other) error = %v", err)
	}
	if _, err := request.Verify(otherInvite, exporter); !errors.Is(err, ErrRequestInvite) {
		t.Fatalf("Verify(other invite) error = %v, want %v", err, ErrRequestInvite)
	}
}

func TestPairingRequestCoreRejectsMutations(t *testing.T) {
	t.Parallel()

	_, core, _ := validRequestFixture(t)
	base := core.Value()
	tests := []struct {
		name   string
		mutate func(*RequestCore)
	}{
		{name: "attempt", mutate: func(value *RequestCore) { value.AttemptID = "" }},
		{name: "device", mutate: func(value *RequestCore) { value.JoinerDeviceID = "" }},
		{name: "identity", mutate: func(value *RequestCore) { value.JoinerIdentityPublicKey[0] ^= 1 }},
		{name: "version", mutate: func(value *RequestCore) { value.DaemonVersion = "v1" }},
		{name: "level", mutate: func(value *RequestCore) { value.MaxApplyLevel = 0 }},
		{name: "binding device", mutate: func(value *RequestCore) { value.InitialEpochBinding.DeviceID = "" }},
		{name: "binding signature", mutate: func(value *RequestCore) { value.InitialEpochBinding.Signature[0] ^= 1 }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := base
			test.mutate(&value)
			if _, err := NewRequestCore(value); !errors.Is(err, ErrRequestCore) {
				t.Fatalf("NewRequestCore() error = %v, want %v", err, ErrRequestCore)
			}
		})
	}
}

func TestPairingRequestRejectsClosedSchemaViolations(t *testing.T) {
	t.Parallel()

	invite, core, exporter := validRequestFixture(t)
	request, err := BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(request.CanonicalBytes(), &members); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	members["future"] = json.RawMessage(`1`)
	unknown := canonicalObject(t, members)
	if _, err := ParseRequest(unknown); !errors.Is(err, ErrRequestUnknownField) {
		t.Fatalf("ParseRequest(unknown field) error = %v, want %v", err, ErrRequestUnknownField)
	}
	delete(members, "future")
	delete(members, "proof")
	missing := canonicalObject(t, members)
	if _, err := ParseRequest(missing); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ParseRequest(missing field) error = %v, want %v", err, ErrInvalidRequest)
	}
	if _, err := ParseRequest(append(request.CanonicalBytes(), 0x0a)); !errors.Is(err, ErrRequestNoncanonical) {
		t.Fatalf("ParseRequest(noncanonical) error = %v, want %v", err, ErrRequestNoncanonical)
	}
}

func TestPairingRequestRejectsNestedUnknownField(t *testing.T) {
	t.Parallel()

	invite, core, exporter := validRequestFixture(t)
	var coreMembers map[string]json.RawMessage
	if err := json.Unmarshal(core.CanonicalBytes(), &coreMembers); err != nil {
		t.Fatalf("json.Unmarshal(core) error = %v", err)
	}
	var bindingMembers map[string]json.RawMessage
	if err := json.Unmarshal(coreMembers["initial_epoch_binding"], &bindingMembers); err != nil {
		t.Fatalf("json.Unmarshal(binding) error = %v", err)
	}
	bindingMembers["future"] = json.RawMessage(`1`)
	coreMembers["initial_epoch_binding"] = canonicalObject(t, bindingMembers)
	mutatedCore := canonicalObject(t, coreMembers)

	inviteValue := invite.Invite()
	coreValue := core.Value()
	transcript, err := buildTranscriptHash(
		exporter,
		inviteValue.InviterIdentityPublicKey[:],
		coreValue.JoinerIdentityPublicKey[:],
		invite.Digest(),
		mutatedCore,
	)
	if err != nil {
		t.Fatalf("buildTranscriptHash() error = %v", err)
	}
	forged := Request{
		inviteID: inviteValue.InviteID, inviteDigest: invite.Digest(),
		coreRaw: mutatedCore, proof: inviteProof(inviteValue.Secret, transcript),
	}
	forged.canonical, err = encodeRequest(forged)
	if err != nil {
		t.Fatalf("encodeRequest() error = %v", err)
	}
	parsed, err := ParseRequest(forged.CanonicalBytes())
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if _, err := parsed.Verify(invite, exporter); !errors.Is(err, ErrRequestUnknownField) {
		t.Fatalf("Verify(nested unknown) error = %v, want %v", err, ErrRequestUnknownField)
	}
}

func FuzzParsePairingRequest(f *testing.F) {
	invite, core, exporter := validRequestFixture(f)
	request, err := BuildRequest(invite, core, exporter)
	if err != nil {
		f.Fatalf("BuildRequest() error = %v", err)
	}
	f.Add(request.CanonicalBytes())
	f.Add([]byte{})
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		parsed, err := ParseRequest(input)
		if err != nil {
			return
		}
		if !bytes.Equal(parsed.CanonicalBytes(), input) {
			t.Fatal("successful request parse did not preserve exact bytes")
		}
	})
}

func validRequestFixture(
	t testing.TB,
) (SignedInvite, CanonicalRequestCore, []byte) {
	t.Helper()
	inviteValue, _, inviterPrivateKey := validInvite(t)
	invite, err := SignInvite(inviteValue, inviterPrivateKey)
	if err != nil {
		t.Fatalf("SignInvite() error = %v", err)
	}
	joinerPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	joinerPublicKey := joinerPrivateKey.Public().(ed25519.PublicKey)
	joinerDeviceID, err := device.DeriveID(joinerPublicKey)
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}
	epochPublicKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{4}, ed25519.SeedSize),
	).Public().(ed25519.PublicKey)
	binding, err := credential.SignBinding(
		inviteValue.SessionID,
		joinerDeviceID,
		inviteValue.InitialCredentialEpoch,
		epochPublicKey,
		joinerPrivateKey,
	)
	if err != nil {
		t.Fatalf("SignBinding() error = %v", err)
	}
	value := RequestCore{
		AttemptID: testAttemptID, JoinerDeviceID: joinerDeviceID,
		DaemonVersion: "1.2.3-rc.1+build.7", MaxApplyLevel: 1,
		InitialEpochBinding: binding,
	}
	copy(value.JoinerIdentityPublicKey[:], joinerPublicKey)
	core, err := NewRequestCore(value)
	if err != nil {
		t.Fatalf("NewRequestCore() error = %v", err)
	}
	return invite, core, bytes.Repeat([]byte{0x55}, ExporterSize)
}

func canonicalObject(t testing.TB, members map[string]json.RawMessage) []byte {
	t.Helper()
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject() error = %v", err)
	}
	return canonical
}
