package codec

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestDeriveDeviceIDGoldenVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		publicKey string
		want      string
	}{
		{
			name:      "zero key",
			publicKey: "0000000000000000000000000000000000000000000000000000000000000000",
			want:      "cc166687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
		},
		{
			name:      "incrementing key",
			publicKey: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			want:      "cc1630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd",
		},
		{
			name:      "RFC 8032 test key",
			publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			want:      "cc121fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			publicKey, err := hex.DecodeString(test.publicKey)
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			got, err := DeriveDeviceID(ed25519.PublicKey(publicKey))
			if err != nil {
				t.Fatalf("DeriveDeviceID() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("DeriveDeviceID() = %q, want %q", got, test.want)
			}
			if !domain.DeviceID(got).Valid() {
				t.Fatalf("derived device ID %q is not canonical", got)
			}
		})
	}
}

func TestDeriveDeviceIDRequiresExactEd25519PublicKey(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, ed25519.PublicKeySize - 1, ed25519.PublicKeySize + 1} {
		key := make(ed25519.PublicKey, size)
		if _, err := DeriveDeviceID(key); !errors.Is(err, ErrInvalidEd25519PublicKey) {
			t.Errorf(
				"DeriveDeviceID(key size %d) error = %v, want ErrInvalidEd25519PublicKey",
				size,
				err,
			)
		}
	}
}
