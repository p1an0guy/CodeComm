package codec

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestBase64URLEncodeDecodeRFC4648Vectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		plain string
		text  string
	}{
		{"", ""},
		{"f", "Zg"},
		{"fo", "Zm8"},
		{"foo", "Zm9v"},
		{"foob", "Zm9vYg"},
		{"fooba", "Zm9vYmE"},
		{"foobar", "Zm9vYmFy"},
		{string([]byte{0xfb, 0xff, 0xef}), "-__v"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.text, func(t *testing.T) {
			t.Parallel()

			if got := EncodeBase64URL([]byte(test.plain)); got != test.text {
				t.Fatalf("EncodeBase64URL() = %q, want %q", got, test.text)
			}
			got, err := DecodeBase64URL(test.text)
			if err != nil {
				t.Fatalf("DecodeBase64URL() error = %v", err)
			}
			if !bytes.Equal(got, []byte(test.plain)) {
				t.Fatalf("DecodeBase64URL() = %x, want %x", got, test.plain)
			}
		})
	}
}

func TestBase64URLRejectsNoncanonicalText(t *testing.T) {
	t.Parallel()

	for _, text := range []string{
		"Zg=",
		"Zg==",
		"Zm+8",
		"Zm/8",
		"Z g",
		"Zg\n",
		"Zg\r\n",
		"A",
		"AB",
		"AAB",
		"é",
	} {
		text := text
		t.Run(text, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeBase64URL(text); !errors.Is(err, ErrInvalidBase64URL) {
				t.Fatalf("DecodeBase64URL(%q) error = %v, want ErrInvalidBase64URL", text, err)
			}
		})
	}
}

func TestBase64URLDecodeErrorDoesNotEchoInput(t *testing.T) {
	t.Parallel()

	text := "c2Vuc2l0aXZlLXZhbHVl="
	_, err := DecodeBase64URL(text)
	if !errors.Is(err, ErrInvalidBase64URL) {
		t.Fatalf("DecodeBase64URL() error = %v, want ErrInvalidBase64URL", err)
	}
	if strings.Contains(err.Error(), text) {
		t.Fatal("DecodeBase64URL() error echoed potentially sensitive input")
	}
}

func TestDecodeBase64URLExactEnforcesDecodedLength(t *testing.T) {
	t.Parallel()

	got, err := DecodeBase64URLExact("AAEC", 3)
	if err != nil {
		t.Fatalf("DecodeBase64URLExact() error = %v", err)
	}
	if want := []byte{0, 1, 2}; !bytes.Equal(got, want) {
		t.Fatalf("DecodeBase64URLExact() = %x, want %x", got, want)
	}

	for _, size := range []int{-1, 0, 2, 4} {
		if _, err := DecodeBase64URLExact("AAEC", size); !errors.Is(err, ErrDecodedLength) {
			t.Errorf(
				"DecodeBase64URLExact(size=%d) error = %v, want ErrDecodedLength",
				size,
				err,
			)
		}
	}
	if _, err := DecodeBase64URLExact("not padded=", 7); !errors.Is(err, ErrInvalidBase64URL) {
		t.Fatalf("invalid text error = %v, want ErrInvalidBase64URL", err)
	}
}
