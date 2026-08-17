package canonicalcoverage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

const (
	unitSessionID   = domain.UUIDv7("018f47de-89ab-7def-8123-456789abcdef")
	unitWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
)

type unitIdentity struct {
	id      domain.DeviceID
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

type strictUnitProvider struct {
	expected Subject
	err      error
	calls    int
}

func (provider *strictUnitProvider) capability() *Provider {
	return newProvider(func(
		_ context.Context,
		subject Subject,
		issue func() error,
	) error {
		provider.calls++
		if subject != provider.expected {
			return fmt.Errorf("unexpected subject: %#v", subject)
		}
		if provider.err != nil {
			return provider.err
		}
		return issue()
	})
}

type blockingUnitProvider struct {
	expected Subject
	entered  chan struct{}
	release  chan struct{}
}

func (provider *blockingUnitProvider) capability() *Provider {
	return newProvider(func(
		ctx context.Context,
		subject Subject,
		issue func() error,
	) error {
		if subject != provider.expected {
			return errors.New("unexpected subject")
		}
		close(provider.entered)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-provider.release:
			return issue()
		}
	})
}

func TestReceiptWireAndSignatureGolden(t *testing.T) {
	identity := unitIdentities(t, 1)[0]
	requirement := unitRequirement(
		t,
		[]unitIdentity{identity},
		3,
		7,
		domain.GitOID("sha1:"+strings.Repeat("a", 40)),
	)
	subject, err := requirement.Subject()
	if err != nil {
		t.Fatalf("Requirement.Subject(): %v", err)
	}
	provider := &strictUnitProvider{expected: subject}
	signer, err := NewSigner(
		provider.capability(),
		unitSnapshot(t, requirement, []unitIdentity{identity}),
		identity.id,
		identity.private,
	)
	if err != nil {
		t.Fatalf("NewSigner(): %v", err)
	}
	defer signer.Close()

	receipt, err := signer.Sign(context.Background())
	if err != nil {
		t.Fatalf("Signer.Sign(): %v", err)
	}
	const wantSigned = `{"canonical_ref_version":7,"commit_oid":"sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_id":"018f47de-89ab-7def-8123-456789abcdef","voter_device_id":"cc134750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e","voter_set_version":3,"workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	const wantCanonical = `{"canonical_ref_version":7,"commit_oid":"sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_id":"018f47de-89ab-7def-8123-456789abcdef","signature":"bfDxtXozkDzREVD0AzYW52zuqE5rQbs2P7vlHYwRqdbnE4veoO1jvHD6A4lJ6QvyYgDRceHQIQI8BH16v0dJBg","voter_device_id":"cc134750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e","voter_set_version":3,"workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	if got := string(receipt.SignedBytes()); got != wantSigned {
		t.Fatalf("signed bytes = %q", got)
	}
	if got := string(receipt.CanonicalBytes()); got != wantCanonical {
		t.Fatalf("canonical bytes = %q", got)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls)
	}
	if err := receipt.Verify(identity.public); err != nil {
		t.Fatalf("Receipt.Verify(): %v", err)
	}
	parsed, err := ParseReceipt(receipt.CanonicalBytes())
	if err != nil {
		t.Fatalf("ParseReceipt(): %v", err)
	}
	if parsed.Subject() != subject ||
		parsed.VoterDeviceID() != identity.id ||
		!bytes.Equal(parsed.SignedBytes(), receipt.SignedBytes()) {
		t.Fatalf("parsed receipt differs: %#v", parsed)
	}

	canonical := receipt.CanonicalBytes()
	signed := receipt.SignedBytes()
	canonical[0] ^= 0xff
	signed[0] ^= 0xff
	if !bytes.Equal(parsed.CanonicalBytes(), receipt.CanonicalBytes()) ||
		!bytes.Equal(parsed.SignedBytes(), receipt.SignedBytes()) {
		t.Fatal("receipt byte accessors alias retained wire bytes")
	}
}

func TestParseReceiptRejectsMalformedWire(t *testing.T) {
	identity := unitIdentities(t, 1)[0]
	requirement := unitRequirement(
		t,
		[]unitIdentity{identity},
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("1", 40)),
	)
	receipt := unitSignReceipt(t, identity, requirement)
	valid := receipt.CanonicalBytes()

	tests := []struct {
		name  string
		input func() []byte
		want  error
	}{
		{"empty", func() []byte { return nil }, ErrInvalidReceipt},
		{"too large", func() []byte {
			return bytes.Repeat([]byte{' '}, MaxReceiptBytes+1)
		}, ErrReceiptTooLarge},
		{"noncanonical", func() []byte {
			return append([]byte(" "), valid...)
		}, ErrReceiptCanonical},
		{"missing field", func() []byte {
			return unitMutateReceipt(t, valid, func(object map[string]json.RawMessage) {
				delete(object, "commit_oid")
			})
		}, ErrInvalidReceipt},
		{"wrong session", func() []byte {
			return unitReplaceReceiptString(t, valid, "session_id", "bad")
		}, ErrInvalidReceipt},
		{"wrong workspace", func() []byte {
			return unitReplaceReceiptString(t, valid, "workspace_id", "bad")
		}, ErrInvalidReceipt},
		{"wrong voter", func() []byte {
			return unitReplaceReceiptString(t, valid, "voter_device_id", "bad")
		}, ErrInvalidReceipt},
		{"wrong oid", func() []byte {
			return unitReplaceReceiptString(t, valid, "commit_oid", "bad")
		}, ErrInvalidReceipt},
		{"zero target version", func() []byte {
			return unitMutateReceipt(t, valid, func(object map[string]json.RawMessage) {
				object["voter_set_version"] = json.RawMessage("0")
			})
		}, ErrInvalidReceipt},
		{"large ref version", func() []byte {
			return bytes.Replace(
				valid,
				[]byte(`"canonical_ref_version":1`),
				[]byte(`"canonical_ref_version":9007199254740992`),
				1,
			)
		}, ErrInvalidReceipt},
		{"padded signature", func() []byte {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(valid, &object); err != nil {
				t.Fatal(err)
			}
			var signature string
			if err := json.Unmarshal(object["signature"], &signature); err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(signature + "=")
			object["signature"] = encoded
			return unitCanonicalObject(t, object)
		}, ErrInvalidReceipt},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseReceipt(test.input()); !errors.Is(err, test.want) {
				t.Fatalf("ParseReceipt() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestReceiptUnknownFieldsAreVerifiedBeforeSchema(t *testing.T) {
	identity := unitIdentities(t, 1)[0]
	requirement := unitRequirement(
		t,
		[]unitIdentity{identity},
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("2", 40)),
	)
	receipt := unitSignReceipt(t, identity, requirement)
	withUnsignedExtension := unitMutateReceipt(
		t,
		receipt.CanonicalBytes(),
		func(object map[string]json.RawMessage) {
			object["future_capability"] = json.RawMessage("true")
		},
	)
	parsed, err := ParseReceipt(withUnsignedExtension)
	if err != nil {
		t.Fatalf("ParseReceipt(unsigned extension): %v", err)
	}
	if err := parsed.Verify(identity.public); !errors.Is(
		err,
		ErrReceiptSignature,
	) {
		t.Fatalf(
			"Verify(unsigned extension) error = %v, want signature failure",
			err,
		)
	}

	withSignedExtension := unitResignReceiptObject(
		t,
		withUnsignedExtension,
		identity.private,
		codec.SignatureGitCanonicalCoverage,
	)
	parsed, err = ParseReceipt(withSignedExtension)
	if err != nil {
		t.Fatalf("ParseReceipt(signed extension): %v", err)
	}
	if err := parsed.Verify(identity.public); !errors.Is(
		err,
		ErrReceiptSchema,
	) {
		t.Fatalf(
			"Verify(signed extension) error = %v, want schema rejection",
			err,
		)
	}
}

func TestReceiptVerifyBindsIdentityAndSignature(t *testing.T) {
	identities := unitIdentities(t, 2)
	requirement := unitRequirement(
		t,
		identities[:1],
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("2", 40)),
	)
	receipt := unitSignReceipt(t, identities[0], requirement)

	if err := receipt.Verify(identities[1].public); !errors.Is(
		err,
		ErrReceiptIdentity,
	) {
		t.Fatalf("Verify(wrong identity) error = %v", err)
	}
	mutated := unitMutateReceipt(
		t,
		receipt.CanonicalBytes(),
		func(object map[string]json.RawMessage) {
			var encoded string
			if err := json.Unmarshal(object["signature"], &encoded); err != nil {
				t.Fatal(err)
			}
			signature, err := codec.DecodeBase64URLExact(
				encoded,
				ed25519.SignatureSize,
			)
			if err != nil {
				t.Fatal(err)
			}
			signature[0] ^= 0x80
			raw, _ := json.Marshal(codec.EncodeBase64URL(signature))
			object["signature"] = raw
		},
	)
	forged, err := ParseReceipt(mutated)
	if err != nil {
		t.Fatalf("ParseReceipt(forged): %v", err)
	}
	if err := forged.Verify(identities[0].public); !errors.Is(
		err,
		ErrReceiptSignature,
	) {
		t.Fatalf("Verify(forged) error = %v", err)
	}

	wrongLabelSignature, err := codecommcrypto.SignEd25519(
		identities[0].private,
		codec.SignatureGitStageReceipt,
		receipt.SignedBytes(),
	)
	if err != nil {
		t.Fatalf("SignEd25519(wrong label): %v", err)
	}
	wrongLabel, err := newReceipt(
		receipt.Subject(),
		receipt.VoterDeviceID(),
		wrongLabelSignature,
	)
	if err != nil {
		t.Fatalf("newReceipt(wrong label): %v", err)
	}
	if err := wrongLabel.Verify(identities[0].public); !errors.Is(
		err,
		ErrReceiptSignature,
	) {
		t.Fatalf("Verify(wrong label) error = %v", err)
	}
}

func TestReceiptSignatureCoversEveryProtocolField(t *testing.T) {
	identities := unitIdentities(t, 2)
	requirement := unitRequirement(
		t,
		identities[:1],
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("3", 40)),
	)
	receipt := unitSignReceipt(t, identities[0], requirement)
	tests := []struct {
		field     string
		value     json.RawMessage
		publicKey ed25519.PublicKey
	}{
		{"canonical_ref_version", json.RawMessage("2"), identities[0].public},
		{
			"commit_oid",
			unitJSONString(t, "sha1:"+strings.Repeat("4", 40)),
			identities[0].public,
		},
		{
			"session_id",
			unitJSONString(t, "018f47de-89ab-7def-8123-456789abcdee"),
			identities[0].public,
		},
		{
			"voter_device_id",
			unitJSONString(t, string(identities[1].id)),
			identities[1].public,
		},
		{"voter_set_version", json.RawMessage("2"), identities[0].public},
		{
			"workspace_id",
			unitJSONString(t, "550e8400-e29b-41d4-a716-446655440001"),
			identities[0].public,
		},
	}
	for _, test := range tests {
		t.Run(test.field, func(t *testing.T) {
			mutated := unitMutateReceipt(
				t,
				receipt.CanonicalBytes(),
				func(object map[string]json.RawMessage) {
					object[test.field] = bytes.Clone(test.value)
				},
			)
			parsed, err := ParseReceipt(mutated)
			if err != nil {
				t.Fatalf("ParseReceipt(): %v", err)
			}
			if err := parsed.Verify(test.publicKey); !errors.Is(
				err,
				ErrReceiptSignature,
			) {
				t.Fatalf("Verify() error = %v, want signature failure", err)
			}
		})
	}
}

func TestSignerFailsClosedAndClearsPrivateKey(t *testing.T) {
	identities := unitIdentities(t, 2)
	requirement := unitRequirement(
		t,
		identities[:1],
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("3", 40)),
	)
	subject, _ := requirement.Subject()
	snapshot := unitSnapshot(t, requirement, identities[:1])

	if _, err := NewSigner(
		nil,
		snapshot,
		identities[0].id,
		identities[0].private,
	); !errors.Is(err, ErrObjectCoverageDegraded) ||
		!errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("NewSigner(nil) error = %v", err)
	}
	var typedNil *Provider
	if _, err := NewSigner(
		typedNil,
		snapshot,
		identities[0].id,
		identities[0].private,
	); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("NewSigner(typed nil) error = %v", err)
	}
	if _, err := NewSigner(
		&Provider{},
		snapshot,
		identities[0].id,
		identities[0].private,
	); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("NewSigner(zero provider) error = %v", err)
	}
	provider := &strictUnitProvider{expected: subject}
	if _, err := NewSigner(
		provider.capability(),
		snapshot,
		identities[0].id,
		identities[1].private,
	); !errors.Is(err, ErrSignerIdentity) {
		t.Fatalf("NewSigner(mismatched identity) error = %v", err)
	}
	signer, err := NewSigner(
		provider.capability(),
		snapshot,
		identities[0].id,
		identities[0].private,
	)
	if err != nil {
		t.Fatalf("NewSigner(): %v", err)
	}
	callerKey := bytes.Clone(identities[0].private)
	signer.Close()
	signer.Close()
	if !bytes.Equal(callerKey, identities[0].private) {
		t.Fatal("Signer.Close() cleared caller-owned private key")
	}
	if _, err := signer.Sign(context.Background()); !errors.Is(
		err,
		ErrProviderUnavailable,
	) {
		t.Fatalf("closed Signer.Sign() error = %v", err)
	}
}

func TestSignerRequiresTargetAndSuccessfulVerification(t *testing.T) {
	identities := unitIdentities(t, 2)
	requirement := unitRequirement(
		t,
		identities[:1],
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("4", 40)),
	)
	subject, _ := requirement.Subject()
	provider := &strictUnitProvider{expected: subject}
	snapshot := unitSnapshot(t, requirement, identities[:1])
	if _, err := NewSigner(
		provider.capability(),
		snapshot,
		identities[1].id,
		identities[1].private,
	); !errors.Is(err, ErrSignerOutsideTarget) {
		t.Fatalf("NewSigner(outsider) error = %v", err)
	}

	injected := errors.New("object absent")
	provider.err = injected
	signer, err := NewSigner(
		provider.capability(),
		snapshot,
		identities[0].id,
		identities[0].private,
	)
	if err != nil {
		t.Fatalf("NewSigner(target): %v", err)
	}
	if _, err := signer.Sign(context.Background()); !errors.Is(
		err,
		ErrObjectCoverageDegraded,
	) ||
		!errors.Is(err, ErrObjectVerification) ||
		!errors.Is(err, injected) {
		t.Fatalf("Sign(provider failure) error = %v", err)
	}
}

func TestSignerIsBoundToItsAppliedSnapshot(t *testing.T) {
	identity := unitIdentities(t, 1)[0]
	requirement := unitRequirement(
		t,
		[]unitIdentity{identity},
		4,
		7,
		domain.GitOID("sha1:"+strings.Repeat("4", 40)),
	)
	subject, _ := requirement.Subject()
	provider := &strictUnitProvider{expected: subject}
	signer, err := NewSigner(
		provider.capability(),
		unitSnapshot(t, requirement, []unitIdentity{identity}),
		identity.id,
		identity.private,
	)
	if err != nil {
		t.Fatalf("NewSigner(): %v", err)
	}
	defer signer.Close()

	requirement.CanonicalRef.EntityVersion++
	requirement.CanonicalRef.CommitOID =
		domain.GitOID("sha1:" + strings.Repeat("5", 40))
	receipt, err := signer.Sign(context.Background())
	if err != nil {
		t.Fatalf("Signer.Sign(): %v", err)
	}
	if receipt.Subject() != subject {
		t.Fatalf("receipt subject = %#v, want bound %#v", receipt.Subject(), subject)
	}
}

func TestSignerCloseWaitsForInFlightVerification(t *testing.T) {
	identity := unitIdentities(t, 1)[0]
	requirement := unitRequirement(
		t,
		[]unitIdentity{identity},
		1,
		1,
		domain.GitOID("sha1:"+strings.Repeat("5", 40)),
	)
	subject, _ := requirement.Subject()
	provider := &blockingUnitProvider{
		expected: subject,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	signer, err := NewSigner(
		provider.capability(),
		unitSnapshot(t, requirement, []unitIdentity{identity}),
		identity.id,
		identity.private,
	)
	if err != nil {
		t.Fatalf("NewSigner(): %v", err)
	}
	signDone := make(chan error, 1)
	go func() {
		_, err := signer.Sign(context.Background())
		signDone <- err
	}()
	<-provider.entered

	closeStarted := make(chan struct{})
	closeDone := make(chan struct{})
	go func() {
		close(closeStarted)
		signer.Close()
		close(closeDone)
	}()
	<-closeStarted
	select {
	case <-closeDone:
		t.Fatal("Signer.Close() returned during provider verification")
	default:
	}
	close(provider.release)
	if err := <-signDone; err != nil {
		t.Fatalf("Signer.Sign(): %v", err)
	}
	<-closeDone
	if _, err := signer.Sign(context.Background()); !errors.Is(
		err,
		ErrProviderUnavailable,
	) {
		t.Fatalf("Signer.Sign(after Close) error = %v", err)
	}
}

func unitIdentities(t *testing.T, count int) []unitIdentity {
	t.Helper()
	identities := make([]unitIdentity, count)
	for index := range count {
		privateKey := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{byte(index + 1)}, ed25519.SeedSize),
		)
		publicKey := bytes.Clone(privateKey.Public().(ed25519.PublicKey))
		id, err := device.DeriveID(publicKey)
		if err != nil {
			t.Fatalf("device.DeriveID(): %v", err)
		}
		identities[index] = unitIdentity{
			id:      id,
			public:  publicKey,
			private: privateKey,
		}
	}
	sort.Slice(identities, func(left, right int) bool {
		return identities[left].id < identities[right].id
	})
	return identities
}

func unitRequirement(
	t *testing.T,
	identities []unitIdentity,
	voterSetVersion uint64,
	canonicalRefVersion uint64,
	commitOID domain.GitOID,
) Requirement {
	t.Helper()
	ids := make([]domain.DeviceID, len(identities))
	for index, identity := range identities {
		ids[index] = identity.id
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	target, err := voterset.New(unitSessionID, ids, voterSetVersion)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	requirement := Requirement{
		SessionID:   unitSessionID,
		WorkspaceID: unitWorkspaceID,
		VoterSet:    target,
		CanonicalRef: publication.CanonicalRef{
			RefName:       publication.CanonicalRefName,
			CommitOID:     commitOID,
			EntityVersion: canonicalRefVersion,
		},
	}
	if err := requirement.Validate(); err != nil {
		t.Fatalf("Requirement.Validate(): %v", err)
	}
	return requirement
}

func unitSignReceipt(
	t *testing.T,
	identity unitIdentity,
	requirement Requirement,
) Receipt {
	t.Helper()
	subject, err := requirement.Subject()
	if err != nil {
		t.Fatalf("Requirement.Subject(): %v", err)
	}
	signer, err := NewSigner(
		(&strictUnitProvider{expected: subject}).capability(),
		unitSnapshot(t, requirement, identitiesForRequirement(t, requirement, identity)),
		identity.id,
		identity.private,
	)
	if err != nil {
		t.Fatalf("NewSigner(): %v", err)
	}
	defer signer.Close()
	receipt, err := signer.Sign(context.Background())
	if err != nil {
		t.Fatalf("Signer.Sign(): %v", err)
	}
	return receipt
}

func identitiesForRequirement(
	t *testing.T,
	requirement Requirement,
	signingIdentity unitIdentity,
) []unitIdentity {
	t.Helper()
	candidates := unitIdentities(t, voterset.MaxVoters)
	byID := make(map[domain.DeviceID]unitIdentity, len(candidates)+1)
	for _, candidate := range candidates {
		byID[candidate.id] = candidate
	}
	byID[signingIdentity.id] = signingIdentity
	target := requirement.VoterSet.VoterDeviceIDs()
	result := make([]unitIdentity, len(target))
	for index, deviceID := range target {
		identity, exists := byID[deviceID]
		if !exists {
			t.Fatalf("no unit identity for target voter %s", deviceID)
		}
		result[index] = identity
	}
	return result
}

func unitMutateReceipt(
	t *testing.T,
	input []byte,
	mutate func(map[string]json.RawMessage),
) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(input, &object); err != nil {
		t.Fatalf("json.Unmarshal(receipt): %v", err)
	}
	mutate(object)
	return unitCanonicalObject(t, object)
}

func unitReplaceReceiptString(
	t *testing.T,
	input []byte,
	field string,
	value string,
) []byte {
	t.Helper()
	return unitMutateReceipt(t, input, func(object map[string]json.RawMessage) {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		object[field] = raw
	})
}

func unitCanonicalObject(
	t *testing.T,
	object map[string]json.RawMessage,
) []byte {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("json.Marshal(receipt): %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(receipt): %v", err)
	}
	return canonical
}

func unitJSONString(t *testing.T, value string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(string): %v", err)
	}
	return raw
}

func unitResignReceiptObject(
	t *testing.T,
	input []byte,
	privateKey ed25519.PrivateKey,
	label codec.SignatureLabel,
) []byte {
	t.Helper()
	unsigned, _, err := codec.RemoveCanonicalObjectMember(input, "signature")
	if err != nil {
		t.Fatalf("RemoveCanonicalObjectMember(signature): %v", err)
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		label,
		unsigned,
	)
	if err != nil {
		t.Fatalf("SignEd25519(receipt): %v", err)
	}
	return unitMutateReceipt(t, input, func(object map[string]json.RawMessage) {
		raw, marshalErr := json.Marshal(codec.EncodeBase64URL(signature))
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		object["signature"] = raw
	})
}
