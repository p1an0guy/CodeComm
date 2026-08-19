package credentialauthorization

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const goldenEndorsementDeviceID = domain.DeviceID(
	"cc16a3803d5f059902a1c6dafbc9ba4729212f7caac08634cc3ae76b27529f03827",
)

func TestCanonicalEndorsementPreimageGolden(t *testing.T) {
	t.Parallel()

	authorization := validTimeEndorsementAuthorization()
	got, err := CanonicalEndorsementPreimage(authorization)
	if err != nil {
		t.Fatalf("CanonicalEndorsementPreimage() error = %v", err)
	}
	const want = `{"authority_voter_set_version":1,"epoch":1,"issued_at":"2024-01-01T00:00:00Z","key_digest":"o8dh5W1V9F4Goxw8fjL3nPukF9Pi4jl3Z-9aRT81_-c","session_id":"01890f47-3e72-7000-8000-000000000001","subject_device_id":"cc16a3803d5f059902a1c6dafbc9ba4729212f7caac08634cc3ae76b27529f03827"}`
	if string(got) != want {
		t.Fatalf("CanonicalEndorsementPreimage() = %s, want %s", got, want)
	}
}

func TestCanonicalEndorsementPreimageAcceptsPartialAuthorization(
	t *testing.T,
) {
	t.Parallel()

	partial := validTimeEndorsementAuthorization()
	got, err := CanonicalEndorsementPreimage(partial)
	if err != nil {
		t.Fatalf("CanonicalEndorsementPreimage(partial) error = %v", err)
	}

	completed := partial
	completed.Role = RoleEditor
	completed.NotBefore = completed.IssuedAt
	completed.ValiditySeconds = ValiditySeconds
	completed.ClockEndorsements = []ClockEndorsement{{
		DeviceID: testDeviceID,
	}}
	completed.BindingSignature[0] = 1
	completed.AuthorizationChainIndex = 42
	withRemainingFields, err := CanonicalEndorsementPreimage(completed)
	if err != nil {
		t.Fatalf("CanonicalEndorsementPreimage(completed) error = %v", err)
	}
	if !bytes.Equal(withRemainingFields, got) {
		t.Fatal("fields outside the partial contract changed the preimage")
	}
}

func TestCanonicalEndorsementPreimageCoversEveryField(t *testing.T) {
	t.Parallel()

	authorization := validTimeEndorsementAuthorization()
	baseline, err := CanonicalEndorsementPreimage(authorization)
	if err != nil {
		t.Fatalf("CanonicalEndorsementPreimage() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Authorization)
	}{
		{
			name: "authority voter-set version",
			mutate: func(value *Authorization) {
				value.AuthorityVoterSetVersion++
			},
		},
		{
			name: "epoch",
			mutate: func(value *Authorization) {
				value.Epoch++
			},
		},
		{
			name: "issued at",
			mutate: func(value *Authorization) {
				value.IssuedAt = "2024-01-01T00:00:01Z"
			},
		},
		{
			name: "key digest",
			mutate: func(value *Authorization) {
				value.EpochPublicKey[0] ^= 0xff
				value.KeyDigest = sha256.Sum256(value.EpochPublicKey[:])
			},
		},
		{
			name: "session ID",
			mutate: func(value *Authorization) {
				value.SessionID =
					"01890f47-3e72-7000-8000-000000000002"
			},
		},
		{
			name: "subject device ID",
			mutate: func(value *Authorization) {
				value.DeviceID = testDeviceID
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mutated := authorization
			test.mutate(&mutated)
			got, err := CanonicalEndorsementPreimage(mutated)
			if err != nil {
				t.Fatalf("CanonicalEndorsementPreimage() error = %v", err)
			}
			if bytes.Equal(got, baseline) {
				t.Fatal("covered-field mutation did not change preimage")
			}
		})
	}
}

func TestCanonicalEndorsementPreimageRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Authorization)
		want   error
	}{
		{
			name: "session ID",
			mutate: func(value *Authorization) {
				value.SessionID = ""
			},
			want: ErrInvalidSessionID,
		},
		{
			name: "device ID",
			mutate: func(value *Authorization) {
				value.DeviceID = ""
			},
			want: ErrInvalidDeviceID,
		},
		{
			name: "zero epoch",
			mutate: func(value *Authorization) {
				value.Epoch = 0
			},
			want: ErrInvalidEpoch,
		},
		{
			name: "oversized epoch",
			mutate: func(value *Authorization) {
				value.Epoch = domain.MaxSafeInteger + 1
			},
			want: ErrInvalidEpoch,
		},
		{
			name: "key digest mismatch",
			mutate: func(value *Authorization) {
				value.KeyDigest[0] ^= 0xff
			},
			want: ErrKeyDigestMismatch,
		},
		{
			name: "issued at",
			mutate: func(value *Authorization) {
				value.IssuedAt = "2024-01-01T00:00:00+00:00"
			},
			want: ErrInvalidTimestamp,
		},
		{
			name: "zero authority version",
			mutate: func(value *Authorization) {
				value.AuthorityVoterSetVersion = 0
			},
			want: ErrInvalidAuthorityVersion,
		},
		{
			name: "oversized authority version",
			mutate: func(value *Authorization) {
				value.AuthorityVoterSetVersion =
					domain.MaxSafeInteger + 1
			},
			want: ErrInvalidAuthorityVersion,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			authorization := validTimeEndorsementAuthorization()
			test.mutate(&authorization)
			_, err := CanonicalEndorsementPreimage(authorization)
			if !errors.Is(err, test.want) {
				t.Fatalf(
					"CanonicalEndorsementPreimage() error = %v, want %v",
					err,
					test.want,
				)
			}
		})
	}
}

func validTimeEndorsementAuthorization() Authorization {
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x61}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	authorization := Authorization{
		SessionID:                testSessionID,
		DeviceID:                 goldenEndorsementDeviceID,
		Epoch:                    1,
		IssuedAt:                 "2024-01-01T00:00:00Z",
		AuthorityVoterSetVersion: 1,
	}
	copy(authorization.EpochPublicKey[:], publicKey)
	authorization.KeyDigest = sha256.Sum256(
		authorization.EpochPublicKey[:],
	)
	return authorization
}
