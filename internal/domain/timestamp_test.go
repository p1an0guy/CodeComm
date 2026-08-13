package domain

import (
	"errors"
	"testing"
	"time"
)

func TestParseTimestampAcceptsCanonicalForms(t *testing.T) {
	t.Parallel()

	tests := []string{
		"0000-01-01T00:00:00Z",
		"2026-08-10T20:45:01Z",
		"2026-08-10T20:45:01.1Z",
		"2026-08-10T20:45:01.123456789Z",
		"9999-12-31T23:59:59.000000001Z",
	}
	for _, input := range tests {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseTimestamp(input)
			if err != nil {
				t.Fatalf("ParseTimestamp(%q) error = %v", input, err)
			}
			if got != Timestamp(input) {
				t.Fatalf("ParseTimestamp(%q) = %q", input, got)
			}
			if !got.Valid() {
				t.Fatalf("Timestamp(%q).Valid() = false", input)
			}
			parsed, err := got.Time()
			if err != nil {
				t.Fatalf("Timestamp(%q).Time() error = %v", input, err)
			}
			if parsed.Location() != time.UTC {
				t.Fatalf("Timestamp(%q).Time().Location() = %v, want UTC", input, parsed.Location())
			}
		})
	}
}

func TestParseTimestampRejectsNoncanonicalAndInvalidForms(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"2026-08-10 20:45:01Z",
		"2026-08-10t20:45:01z",
		"2026-08-10T20:45:01+00:00",
		"2026-08-10T13:45:01-07:00",
		"2026-08-10T20:45:01.0Z",
		"2026-08-10T20:45:01.100Z",
		"2026-08-10T20:45:01.Z",
		"2026-08-10T20:45:01,1Z",
		"2026-08-10T20:45:01.1234567890Z",
		"2026-02-29T20:45:01Z",
		"2024-02-30T20:45:01Z",
		"2026-13-10T20:45:01Z",
		"2026-08-10T24:00:00Z",
		"2026-08-10T20:60:00Z",
		"2026-08-10T20:45:60Z",
	}
	for _, input := range tests {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseTimestamp(input)
			if !errors.Is(err, ErrInvalidTimestamp) {
				t.Fatalf("ParseTimestamp(%q) error = %v, want ErrInvalidTimestamp", input, err)
			}
			if got != "" {
				t.Fatalf("ParseTimestamp(%q) = %q after error, want zero value", input, got)
			}
			if Timestamp(input).Valid() {
				t.Fatalf("Timestamp(%q).Valid() = true", input)
			}
		})
	}
}

func TestParseWholeSecondTimestamp(t *testing.T) {
	t.Parallel()

	const canonical = "2026-08-10T20:45:01Z"
	got, err := ParseWholeSecondTimestamp(canonical)
	if err != nil {
		t.Fatalf("ParseWholeSecondTimestamp(%q) error = %v", canonical, err)
	}
	if got != WholeSecondTimestamp(canonical) || !got.Valid() {
		t.Fatalf("ParseWholeSecondTimestamp(%q) = %q, valid = %t", canonical, got, got.Valid())
	}
	parsed, err := got.Time()
	if err != nil {
		t.Fatalf("WholeSecondTimestamp.Time() error = %v", err)
	}
	if parsed.Location() != time.UTC {
		t.Fatalf("WholeSecondTimestamp.Time().Location() = %v, want UTC", parsed.Location())
	}

	for _, input := range []string{
		"",
		"2026-08-10T20:45:01.1Z",
		"2026-08-10T20:45:01+00:00",
		"2026-08-10T20:45:60Z",
	} {
		input := input
		t.Run("reject_"+input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseWholeSecondTimestamp(input)
			if !errors.Is(err, ErrInvalidWholeSecondTimestamp) {
				t.Fatalf(
					"ParseWholeSecondTimestamp(%q) error = %v, want ErrInvalidWholeSecondTimestamp",
					input,
					err,
				)
			}
			if got != "" {
				t.Fatalf("ParseWholeSecondTimestamp(%q) = %q after error", input, got)
			}
		})
	}
}

func TestTimestampZeroValuesAreInvalid(t *testing.T) {
	t.Parallel()

	if Timestamp("").Valid() {
		t.Error("zero Timestamp is valid")
	}
	if WholeSecondTimestamp("").Valid() {
		t.Error("zero WholeSecondTimestamp is valid")
	}
	if _, err := Timestamp("invalid").Time(); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("invalid Timestamp.Time() error = %v, want ErrInvalidTimestamp", err)
	}
	if _, err := WholeSecondTimestamp("invalid").Time(); !errors.Is(err, ErrInvalidWholeSecondTimestamp) {
		t.Fatalf("invalid WholeSecondTimestamp.Time() error = %v, want ErrInvalidWholeSecondTimestamp", err)
	}
}
