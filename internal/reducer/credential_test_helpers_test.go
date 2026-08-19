package reducer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
)

const (
	testCredentialIssuedAt  = domain.WholeSecondTimestamp("2024-01-01T00:00:00Z")
	testCredentialNotBefore = domain.WholeSecondTimestamp("2024-01-01T00:00:00Z")
)

type credentialPayloadOptions struct {
	subject          domain.DeviceID
	epoch            uint64
	keySeed          byte
	role             device.Role
	issuedAt         domain.WholeSecondTimestamp
	notBefore        domain.WholeSecondTimestamp
	validitySeconds  uint64
	authorityVersion uint64
	endorsers        []domain.DeviceID
}

func defaultCredentialPayloadOptions(
	fixture reducerFixture,
) credentialPayloadOptions {
	subject := fixture.editorDevice
	return credentialPayloadOptions{
		subject:          subject,
		epoch:            fixture.state.auditCounters[subject].CredentialEpoch + 1,
		keySeed:          0x61,
		role:             fixture.state.devices[subject].Role,
		issuedAt:         testCredentialIssuedAt,
		notBefore:        testCredentialNotBefore,
		validitySeconds:  credentialauthorization.ValiditySeconds,
		authorityVersion: fixture.state.credentialAuthority.VoterSetVersion,
		endorsers:        fixture.state.credentialAuthority.VoterIDs(),
	}
}

func credentialPayload(
	t *testing.T,
	fixture reducerFixture,
	options credentialPayloadOptions,
) (map[string]any, credentialauthorization.Authorization) {
	t.Helper()

	epochPrivateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{options.keySeed}, ed25519.SeedSize),
	)
	epochPublicKey := epochPrivateKey.Public().(ed25519.PublicKey)
	authorization := credentialauthorization.Authorization{
		SessionID:                fixture.state.sessionID,
		DeviceID:                 options.subject,
		Epoch:                    options.epoch,
		Role:                     credentialauthorization.Role(options.role),
		IssuedAt:                 options.issuedAt,
		NotBefore:                options.notBefore,
		ValiditySeconds:          options.validitySeconds,
		AuthorityVoterSetVersion: options.authorityVersion,
		AuthorizationChainIndex:  fixture.state.currentChainIndex + 1,
	}
	copy(authorization.EpochPublicKey[:], epochPublicKey)
	authorization.KeyDigest = sha256.Sum256(epochPublicKey)

	bindingPreimage, err := credentialBindingPreimageBytes(
		authorization.SessionID,
		authorization.DeviceID,
		authorization.Epoch,
		authorization.EpochPublicKey,
	)
	if err != nil {
		t.Fatalf("credentialBindingPreimageBytes() error = %v", err)
	}
	subjectPrivateKey, exists := fixture.privateKeys[options.subject]
	if !exists {
		t.Fatalf("missing subject private key for %q", options.subject)
	}
	bindingSignature, err := codecommcrypto.SignEd25519(
		subjectPrivateKey,
		codec.SignatureCredentialBinding,
		bindingPreimage,
	)
	if err != nil {
		t.Fatalf("sign credential binding: %v", err)
	}
	copy(authorization.BindingSignature[:], bindingSignature)

	endorsementPreimage, err :=
		credentialauthorization.CanonicalEndorsementPreimage(authorization)
	if err != nil {
		t.Fatalf("CanonicalEndorsementPreimage() error = %v", err)
	}
	endorsementPayloads := make([]map[string]any, len(options.endorsers))
	authorization.ClockEndorsements = make(
		[]credentialauthorization.ClockEndorsement,
		len(options.endorsers),
	)
	for index, endorserID := range options.endorsers {
		privateKey, exists := fixture.privateKeys[endorserID]
		if !exists {
			t.Fatalf("missing endorser private key for %q", endorserID)
		}
		signature, signErr := codecommcrypto.SignEd25519(
			privateKey,
			codec.SignatureCredentialTimeEndorsement,
			endorsementPreimage,
		)
		if signErr != nil {
			t.Fatalf("sign clock endorsement: %v", signErr)
		}
		endorsement := credentialauthorization.ClockEndorsement{
			DeviceID: endorserID,
		}
		copy(endorsement.Signature[:], signature)
		authorization.ClockEndorsements[index] = endorsement
		endorsementPayloads[index] = map[string]any{
			"device_id": endorserID,
			"signature": codec.EncodeBase64URL(signature),
		}
	}
	return map[string]any{
		"subject_device_id":           options.subject,
		"epoch_public_key":            codec.EncodeBase64URL(epochPublicKey),
		"key_digest":                  codec.EncodeBase64URL(authorization.KeyDigest[:]),
		"epoch":                       options.epoch,
		"role":                        options.role,
		"issued_at":                   options.issuedAt,
		"not_before":                  options.notBefore,
		"validity_seconds":            options.validitySeconds,
		"authority_voter_set_version": options.authorityVersion,
		"clock_endorsements":          endorsementPayloads,
		"binding_signature": codec.EncodeBase64URL(
			authorization.BindingSignature[:],
		),
	}, authorization
}

func buildCredentialProposal(
	t *testing.T,
	fixture reducerFixture,
	originDeviceID domain.DeviceID,
	entityID domain.DeviceID,
	sequence uint64,
	payload map[string]any,
) event.SignedEvent {
	t.Helper()

	authority, err := event.NewLocalAuthority(originDeviceID, testBootID)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority() error = %v", err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("DaemonBinding() error = %v", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal(payload) error = %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             event.KindCredentialAuthorized,
			EntityID:         event.StringEntityID(string(entityID)),
			RationaleSummary: "",
			Actions:          []event.Action{},
			Payload:          encoded,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        domainEventID(130 + int(sequence)),
			SessionID:      fixture.state.sessionID,
			WorkspaceID:    fixture.state.workspaceID,
			CreatedAt:      testTimestamp,
			OriginSequence: sequence,
		},
	)
	if err != nil {
		t.Fatalf("event.BuildProposal() error = %v", err)
	}
	signed, err := event.Sign(proposal, fixture.privateKeys[originDeviceID])
	if err != nil {
		t.Fatalf("event.Sign() error = %v", err)
	}
	return signed
}

func reduceCredentialPayload(
	t *testing.T,
	fixture reducerFixture,
	options credentialPayloadOptions,
	payloadMutation func(map[string]any),
) Outcome {
	t.Helper()
	payload, _ := credentialPayload(t, fixture, options)
	if payloadMutation != nil {
		payloadMutation(payload)
	}
	signed := buildCredentialProposal(
		t,
		fixture,
		fixture.ownerDevice,
		options.subject,
		2,
		payload,
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	return outcome
}

func assertCredentialRejection(t *testing.T, outcome Outcome, want Code) {
	t.Helper()
	if outcome.Status != StatusRejected ||
		outcome.Code != want ||
		outcome.Changes.AdvancesEventChain ||
		len(outcome.Changes.OriginScopes) != 1 ||
		len(outcome.Changes.AuditCounters) != 0 ||
		len(outcome.Changes.CredentialAuthorizations) != 0 {
		t.Fatalf("credential rejection = %#v, want %q", outcome, want)
	}
}
