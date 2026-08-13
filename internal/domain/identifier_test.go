package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestParseUUIDv7AcceptsCanonicalBoundaries(t *testing.T) {
	t.Parallel()

	tests := []string{
		"00000000-0000-7000-8000-000000000000",
		"017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
		"ffffffff-ffff-7fff-bfff-ffffffffffff",
	}
	for _, input := range tests {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseUUIDv7(input)
			if err != nil {
				t.Fatalf("ParseUUIDv7(%q) error = %v", input, err)
			}
			if got != UUIDv7(input) {
				t.Fatalf("ParseUUIDv7(%q) = %q", input, got)
			}
			if !got.Valid() {
				t.Fatalf("UUIDv7(%q).Valid() = false", input)
			}
		})
	}
}

func TestParseUUIDv4AcceptsCanonicalBoundaries(t *testing.T) {
	t.Parallel()

	tests := []string{
		"00000000-0000-4000-8000-000000000000",
		"550e8400-e29b-41d4-a716-446655440000",
		"ffffffff-ffff-4fff-bfff-ffffffffffff",
	}
	for _, input := range tests {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseUUIDv4(input)
			if err != nil {
				t.Fatalf("ParseUUIDv4(%q) error = %v", input, err)
			}
			if got != UUIDv4(input) {
				t.Fatalf("ParseUUIDv4(%q) = %q", input, got)
			}
			if !got.Valid() {
				t.Fatalf("UUIDv4(%q).Valid() = false", input)
			}
		})
	}
}

func TestUUIDParsersRejectNoncanonicalAndWrongVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "one byte short", input: "00000000-0000-7000-8000-00000000000"},
		{name: "one byte long", input: "00000000-0000-7000-8000-0000000000000"},
		{name: "uppercase hex", input: "017F22e2-79b0-7cc3-98c4-dc0c0c07398f"},
		{name: "braced", input: "{017f22e2-79b0-7cc3-98c4-dc0c0c07398f}"},
		{name: "URN prefix", input: "urn:uuid:017f22e2-79b0-7cc3-98c4-dc0c0c07398f"},
		{name: "missing hyphen", input: "017f22e279b0-7cc3-98c4-dc0c0c07398f"},
		{name: "misplaced hyphen", input: "017f22e-279b0-7cc3-98c4-dc0c0c07398f"},
		{name: "non-hex", input: "g17f22e2-79b0-7cc3-98c4-dc0c0c07398f"},
		{name: "leading space", input: " 017f22e2-79b0-7cc3-98c4-dc0c0c07398f"},
		{name: "trailing space", input: "017f22e2-79b0-7cc3-98c4-dc0c0c07398f "},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertInvalidUUIDv7(t, test.input)

			v4Input := strings.Replace(test.input, "7cc3", "4cc3", 1)
			assertInvalidUUIDv4(t, v4Input)
		})
	}

	assertInvalidUUIDv7(t, "017f22e2-79b0-4cc3-98c4-dc0c0c07398f")
	assertInvalidUUIDv4(t, "550e8400-e29b-71d4-a716-446655440000")
}

func TestUUIDParsersEnforceRFC9562Variant(t *testing.T) {
	t.Parallel()

	const variantNibbles = "0123456789abcdef"
	for _, version := range []byte{'4', '7'} {
		version := version
		t.Run("version_"+string(version), func(t *testing.T) {
			t.Parallel()
			for i := range variantNibbles {
				nibble := variantNibbles[i]
				input := "00000000-0000-" + string(version) + "000-" +
					string(nibble) + "000-000000000000"
				wantValid := strings.ContainsRune("89ab", rune(nibble))

				switch version {
				case '4':
					_, err := ParseUUIDv4(input)
					if (err == nil) != wantValid {
						t.Errorf("ParseUUIDv4(%q) error = %v, want valid %t", input, err, wantValid)
					}
				case '7':
					_, err := ParseUUIDv7(input)
					if (err == nil) != wantValid {
						t.Errorf("ParseUUIDv7(%q) error = %v, want valid %t", input, err, wantValid)
					}
				}
			}
		})
	}
}

func TestParseDeviceIDAcceptsCanonicalBoundaries(t *testing.T) {
	t.Parallel()

	tests := []string{
		"cc1" + strings.Repeat("0", 64),
		"cc1" + "0123456789abcdef" + strings.Repeat("0", 48),
		"cc1" + strings.Repeat("f", 64),
	}
	for _, input := range tests {
		input := input
		t.Run(input[:19], func(t *testing.T) {
			t.Parallel()
			got, err := ParseDeviceID(input)
			if err != nil {
				t.Fatalf("ParseDeviceID(%q) error = %v", input, err)
			}
			if got != DeviceID(input) {
				t.Fatalf("ParseDeviceID(%q) = %q", input, got)
			}
			if !got.Valid() {
				t.Fatalf("DeviceID(%q).Valid() = false", input)
			}
		})
	}
}

func TestParseDeviceIDRejectsBoundariesAndNoncanonicalText(t *testing.T) {
	t.Parallel()

	valid := "cc1" + strings.Repeat("a", 64)
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "prefix only", input: "cc1"},
		{name: "one byte short", input: valid[:len(valid)-1]},
		{name: "one byte long", input: valid + "0"},
		{name: "wrong prefix", input: "cc2" + valid[3:]},
		{name: "uppercase prefix", input: "CC1" + valid[3:]},
		{name: "uppercase hex", input: "cc1A" + valid[4:]},
		{name: "non-hex", input: "cc1g" + valid[4:]},
		{name: "leading space", input: " " + valid},
		{name: "trailing space", input: valid + " "},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseDeviceID(test.input)
			if !errors.Is(err, ErrInvalidDeviceID) {
				t.Fatalf("ParseDeviceID(%q) error = %v, want %v", test.input, err, ErrInvalidDeviceID)
			}
			if got != "" {
				t.Fatalf("ParseDeviceID(%q) = %q after error, want zero value", test.input, got)
			}
			if DeviceID(test.input).Valid() {
				t.Fatalf("DeviceID(%q).Valid() = true", test.input)
			}
		})
	}
}

func TestIdentifierZeroValuesAreInvalid(t *testing.T) {
	t.Parallel()

	if UUIDv7("").Valid() {
		t.Error("zero UUIDv7 is valid")
	}
	if UUIDv4("").Valid() {
		t.Error("zero UUIDv4 is valid")
	}
	if DeviceID("").Valid() {
		t.Error("zero DeviceID is valid")
	}
}

func assertInvalidUUIDv7(t *testing.T, input string) {
	t.Helper()

	got, err := ParseUUIDv7(input)
	if !errors.Is(err, ErrInvalidUUIDv7) {
		t.Fatalf("ParseUUIDv7(%q) error = %v, want %v", input, err, ErrInvalidUUIDv7)
	}
	if got != "" {
		t.Fatalf("ParseUUIDv7(%q) = %q after error, want zero value", input, got)
	}
	if UUIDv7(input).Valid() {
		t.Fatalf("UUIDv7(%q).Valid() = true", input)
	}
}

func assertInvalidUUIDv4(t *testing.T, input string) {
	t.Helper()

	got, err := ParseUUIDv4(input)
	if !errors.Is(err, ErrInvalidUUIDv4) {
		t.Fatalf("ParseUUIDv4(%q) error = %v, want %v", input, err, ErrInvalidUUIDv4)
	}
	if got != "" {
		t.Fatalf("ParseUUIDv4(%q) = %q after error, want zero value", input, got)
	}
	if UUIDv4(input).Valid() {
		t.Fatalf("UUIDv4(%q).Valid() = true", input)
	}
}
