package reducer

import (
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
)

func TestCredentialProofGoldenVectors(t *testing.T) {
	t.Parallel()

	const (
		wantBindingPreimage      = `{"device_id":"cc16a3803d5f059902a1c6dafbc9ba4729212f7caac08634cc3ae76b27529f03827","epoch":1,"epoch_public_key":"rwaj4ykXFOTzVsGcmxXNGVHsbmZiqne-B1R_KJODNB0","session_id":"01890f47-3e72-7000-8000-000000000001"}`
		wantBindingSignature     = "8K9MdYSudS7crUmX4jNpEXzJgQRtRuK4KbrTX4VICbx3zJbMzKReCGUEQFFa23Ej6ZCbXqme39TKcvctiZWaAQ"
		wantEndorsementPreimage  = `{"authority_voter_set_version":1,"epoch":1,"issued_at":"2024-01-01T00:00:00Z","key_digest":"o8dh5W1V9F4Goxw8fjL3nPukF9Pi4jl3Z-9aRT81_-c","session_id":"01890f47-3e72-7000-8000-000000000001","subject_device_id":"cc16a3803d5f059902a1c6dafbc9ba4729212f7caac08634cc3ae76b27529f03827"}`
		wantEndorsementSignature = "gB2AvmLtqcByAxJfhE1m65SP_ZM_Rylow1nSvRmbMPqVoglgdCGJShPUpNZuUKcLLpBd-T1bHKVRK_LTTv1cAA"
	)
	fixture := newReducerFixture(t)
	options := defaultCredentialPayloadOptions(fixture)
	_, authorization := credentialPayload(t, fixture, options)

	bindingPreimage, err := credentialBindingPreimageBytes(
		authorization.SessionID,
		authorization.DeviceID,
		authorization.Epoch,
		authorization.EpochPublicKey,
	)
	if err != nil {
		t.Fatalf("credentialBindingPreimageBytes() error = %v", err)
	}
	endorsementPreimage, err := credentialTimeEndorsementPreimageBytes(
		authorization,
	)
	if err != nil {
		t.Fatalf("credentialTimeEndorsementPreimageBytes() error = %v", err)
	}

	assertGoldenCredentialValue(
		t,
		"binding preimage",
		string(bindingPreimage),
		wantBindingPreimage,
	)
	assertGoldenCredentialValue(
		t,
		"binding signature",
		codec.EncodeBase64URL(authorization.BindingSignature[:]),
		wantBindingSignature,
	)
	assertGoldenCredentialValue(
		t,
		"endorsement preimage",
		string(endorsementPreimage),
		wantEndorsementPreimage,
	)
	assertGoldenCredentialValue(
		t,
		"endorsement signature",
		codec.EncodeBase64URL(
			authorization.ClockEndorsements[0].Signature[:],
		),
		wantEndorsementSignature,
	)
	if !verifyCredentialBinding(
		authorization,
		fixture.state.devices[authorization.DeviceID].IdentityPublicKey,
	) {
		t.Fatal("golden binding did not verify")
	}
	if err := validateCredentialEndorsements(
		fixture.state,
		authorization,
	); err != nil {
		t.Fatalf("golden endorsements did not verify: %v", err)
	}
}

func assertGoldenCredentialValue(
	t *testing.T,
	name,
	got,
	want string,
) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}
