package codec

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	referencejcs "github.com/gowebpki/jcs"
)

func FuzzCanonicalizeDifferential(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`null`),
		[]byte(`{"z":[1,2,3],"a":"value"}`),
		[]byte(`{"numbers":[333333333.33333329,1E30,4.50,2e-3,1e-27]}`),
		[]byte(`{"\ud83d\ude00":"emoji","\u20ac":"euro"}`),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		boundedInput := input
		if len(boundedInput) > 4<<10 {
			boundedInput = boundedInput[:4<<10]
		}

		// Always exercise a known-valid object so a validator regression that
		// rejects every input cannot turn the differential target into a no-op.
		validInput, err := json.Marshal(map[string]any{
			"future": map[string]any{"bytes": string(boundedInput)},
			"known":  "value",
		})
		if err != nil {
			t.Fatalf("construct valid JSON: %v", err)
		}
		compareCanonicalizers(t, validInput, false)

		digest := sha256.Sum256(boundedInput)
		unsigned := binary.BigEndian.Uint64(digest[:8]) % uint64(2*maxSafeInteger+1)
		integer := int64(unsigned) - maxSafeInteger
		signedInput, err := json.Marshal(map[string]any{
			"future": map[string]any{"text": string(boundedInput)},
			"n":      integer,
		})
		if err != nil {
			t.Fatalf("construct valid signed JSON: %v", err)
		}
		compareCanonicalizers(t, signedInput, true)

		// The independent oracle uses quadratic key insertion. Keep the
		// differential target focused; production canonicalization is sort-based.
		if len(input) > 8<<10 {
			return
		}
		if _, _, err := validateJSON(input, false, maxCanonicalJSONBytes); err != nil {
			return
		}
		compareCanonicalizers(t, input, false)
	})
}

func FuzzCanonicalizeIntegerProfile(f *testing.F) {
	for _, seed := range []int64{
		0,
		1,
		-1,
		maxSafeInteger,
		-maxSafeInteger,
		maxSafeInteger + 1,
		-maxSafeInteger - 1,
		1<<63 - 1,
		-1 << 63,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value int64) {
		input := []byte(`{"n":` + strconv.FormatInt(value, 10) + `}`)
		if value < -maxSafeInteger || value > maxSafeInteger {
			if _, err := Canonicalize(input); !errors.Is(err, ErrIntegerOutOfRange) {
				t.Fatalf("Canonicalize(%q) error = %v, want %v", input, err, ErrIntegerOutOfRange)
			}
			return
		}
		compareCanonicalizers(t, input, false)
	})
}

func compareCanonicalizers(t *testing.T, input []byte, signed bool) {
	t.Helper()

	var (
		got []byte
		err error
	)
	if signed {
		got, err = CanonicalizeSignedObject(input)
	} else {
		got, err = canonicalizeRFC8785(input)
	}
	if err != nil {
		t.Fatalf("canonicalizer rejected valid input: %v", err)
	}

	want, err := referencejcs.Transform(bytes.TrimSpace(input))
	if err != nil {
		t.Fatalf("reference canonicalizer rejected valid input: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonicalization mismatch:\ngot  %q\nwant %q", got, want)
	}
}
