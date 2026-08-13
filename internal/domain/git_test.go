package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestGitObjectFormatValid(t *testing.T) {
	t.Parallel()

	if !GitObjectSHA1.Valid() || !GitObjectSHA256.Valid() {
		t.Fatal("GitObjectFormat.Valid() rejected a supported format")
	}
	for _, format := range []GitObjectFormat{"", "SHA1", "sha512"} {
		if format.Valid() {
			t.Errorf("GitObjectFormat(%q).Valid() = true", format)
		}
	}
}

func TestParseGitOIDAcceptsCanonicalForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input     string
		algorithm GitObjectFormat
		hex       string
	}{
		{
			input:     "sha1:" + strings.Repeat("0", 40),
			algorithm: GitObjectSHA1,
			hex:       strings.Repeat("0", 40),
		},
		{
			input:     "sha1:0123456789abcdef0123456789abcdef01234567",
			algorithm: GitObjectSHA1,
			hex:       "0123456789abcdef0123456789abcdef01234567",
		},
		{
			input:     "sha256:" + strings.Repeat("f", 64),
			algorithm: GitObjectSHA256,
			hex:       strings.Repeat("f", 64),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.algorithm), func(t *testing.T) {
			t.Parallel()
			got, err := ParseGitOID(test.input)
			if err != nil {
				t.Fatalf("ParseGitOID(%q) error = %v", test.input, err)
			}
			if got != GitOID(test.input) || !got.Valid() {
				t.Fatalf("ParseGitOID(%q) = %q, valid = %t", test.input, got, got.Valid())
			}
			if got.ObjectFormat() != test.algorithm {
				t.Fatalf("GitOID.ObjectFormat() = %q, want %q", got.ObjectFormat(), test.algorithm)
			}
			if got.Hex() != test.hex {
				t.Fatalf("GitOID.Hex() = %q, want %q", got.Hex(), test.hex)
			}
		})
	}
}

func TestParseGitOIDRejectsNoncanonicalForms(t *testing.T) {
	t.Parallel()

	validSHA1 := "sha1:" + strings.Repeat("a", 40)
	validSHA256 := "sha256:" + strings.Repeat("b", 64)
	tests := []string{
		"",
		strings.Repeat("a", 40),
		"SHA1:" + strings.Repeat("a", 40),
		"sha-1:" + strings.Repeat("a", 40),
		"sha1:" + strings.Repeat("a", 39),
		"sha1:" + strings.Repeat("a", 41),
		"sha1:A" + strings.Repeat("a", 39),
		"sha1:g" + strings.Repeat("a", 39),
		"sha256:" + strings.Repeat("b", 63),
		"sha256:" + strings.Repeat("b", 65),
		"sha256:B" + strings.Repeat("b", 63),
		" " + validSHA1,
		validSHA256 + " ",
	}
	for _, input := range tests {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseGitOID(input)
			if !errors.Is(err, ErrInvalidGitOID) {
				t.Fatalf("ParseGitOID(%q) error = %v, want ErrInvalidGitOID", input, err)
			}
			if got != "" {
				t.Fatalf("ParseGitOID(%q) = %q after error, want zero value", input, got)
			}
			if GitOID(input).Valid() {
				t.Fatalf("GitOID(%q).Valid() = true", input)
			}
			if got := GitOID(input).ObjectFormat(); got != "" {
				t.Fatalf("GitOID(%q).ObjectFormat() = %q, want zero value", input, got)
			}
			if got := GitOID(input).Hex(); got != "" {
				t.Fatalf("GitOID(%q).Hex() = %q, want empty", input, got)
			}
		})
	}
}

func TestParseConflictID(t *testing.T) {
	t.Parallel()

	canonical := "ccf1" + strings.Repeat("a", 64)
	got, err := ParseConflictID(canonical)
	if err != nil {
		t.Fatalf("ParseConflictID(%q) error = %v", canonical, err)
	}
	if got != ConflictID(canonical) || !got.Valid() {
		t.Fatalf("ParseConflictID(%q) = %q, valid = %t", canonical, got, got.Valid())
	}

	for _, input := range []string{
		"",
		"ccf1" + strings.Repeat("a", 63),
		"ccf1" + strings.Repeat("a", 65),
		"ccf2" + strings.Repeat("a", 64),
		"ccf1A" + strings.Repeat("a", 63),
		"ccf1g" + strings.Repeat("a", 63),
	} {
		input := input
		t.Run("reject_"+input, func(t *testing.T) {
			t.Parallel()
			parsed, err := ParseConflictID(input)
			if !errors.Is(err, ErrInvalidConflictID) {
				t.Fatalf("ParseConflictID(%q) error = %v, want ErrInvalidConflictID", input, err)
			}
			if parsed != "" || ConflictID(input).Valid() {
				t.Fatalf("invalid ConflictID %q was accepted", input)
			}
		})
	}
}
