package codec

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCanonicalizeOfficialRFC8785Corpus(t *testing.T) {
	t.Parallel()

	inputDir := filepath.Join("testdata", "rfc8785", "input")
	outputDir := filepath.Join("testdata", "rfc8785", "output")
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		entry := entry
		t.Run(entry.Name(), func(t *testing.T) {
			t.Parallel()
			input, err := os.ReadFile(filepath.Join(inputDir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(outputDir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			got, err := canonicalizeRFC8785(input)
			if err != nil {
				t.Fatalf("canonicalizeRFC8785() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("canonicalizeRFC8785() = %q, want %q", got, want)
			}
		})
	}
}

func TestCanonicalizeRFC8785Vectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "appendix sample",
			in: `{
				"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
				"string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
				"literals": [null, true, false]
			}`,
			want: `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		},
		{
			name: "recursive object ordering",
			in:   `{"z":{"b":2,"a":1},"a":[3,2,1]}`,
			want: `{"a":[3,2,1],"z":{"a":1,"b":2}}`,
		},
		{
			name: "negative zero",
			in:   " \n\t{\"n\":-0}\r ",
			want: `{"n":0}`,
		},
		{
			name: "top-level primitive with whitespace",
			in:   " \n null\t",
			want: `null`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := canonicalizeRFC8785([]byte(test.in))
			if err != nil {
				t.Fatalf("canonicalizeRFC8785() error = %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("canonicalizeRFC8785() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCanonicalizeUTF16KeyOrdering(t *testing.T) {
	t.Parallel()

	input := `{
		"\ufb33":"hebrew",
		"\u20ac":"euro",
		"\ud83d\ude00":"emoji",
		"\u00f6":"latin",
		"\u0080":"control",
		"\r":"CR",
		"1":"one"
	}`
	want := "{\"\\r\":\"CR\",\"1\":\"one\",\"\u0080\":\"control\",\"\u00f6\":\"latin\",\"\u20ac\":\"euro\",\"\U0001f600\":\"emoji\",\"\ufb33\":\"hebrew\"}"

	got, err := Canonicalize([]byte(input))
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	if string(got) != want {
		t.Fatalf("Canonicalize() = %q, want %q", got, want)
	}
}

func TestCanonicalizeRFC8785AppendixBNumbers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		bits uint64
		want string
	}{
		{bits: 0x0000000000000000, want: "0"},
		{bits: 0x8000000000000000, want: "0"},
		{bits: 0x0000000000000001, want: "5e-324"},
		{bits: 0x8000000000000001, want: "-5e-324"},
		{bits: 0x7fefffffffffffff, want: "1.7976931348623157e+308"},
		{bits: 0xffefffffffffffff, want: "-1.7976931348623157e+308"},
		{bits: 0x4340000000000000, want: "9007199254740992"},
		{bits: 0xc340000000000000, want: "-9007199254740992"},
		{bits: 0x4430000000000000, want: "295147905179352830000"},
		{bits: 0x44b52d02c7e14af5, want: "9.999999999999997e+22"},
		{bits: 0x44b52d02c7e14af6, want: "1e+23"},
		{bits: 0x44b52d02c7e14af7, want: "1.0000000000000001e+23"},
		{bits: 0x444b1ae4d6e2ef4e, want: "999999999999999700000"},
		{bits: 0x444b1ae4d6e2ef4f, want: "999999999999999900000"},
		{bits: 0x444b1ae4d6e2ef50, want: "1e+21"},
		{bits: 0x3eb0c6f7a0b5ed8c, want: "9.999999999999997e-7"},
		{bits: 0x3eb0c6f7a0b5ed8d, want: "0.000001"},
		{bits: 0x41b3de4355555553, want: "333333333.3333332"},
		{bits: 0x41b3de4355555554, want: "333333333.33333325"},
		{bits: 0x41b3de4355555555, want: "333333333.3333333"},
		{bits: 0x41b3de4355555556, want: "333333333.3333334"},
		{bits: 0x41b3de4355555557, want: "333333333.33333343"},
		{bits: 0xbecbf647612f3696, want: "-0.0000033333333333333333"},
		{bits: 0x43143ff3c1cb0959, want: "1424953923781206.2"},
	}

	for _, test := range tests {
		test := test
		t.Run(strconv.FormatUint(test.bits, 16), func(t *testing.T) {
			t.Parallel()
			token := strconv.FormatFloat(math.Float64frombits(test.bits), 'e', 17, 64)
			if test.bits == 0x8000000000000000 {
				token = "-0"
			}
			got, err := canonicalizeRFC8785([]byte(`{"n":` + token + `}`))
			if err != nil {
				t.Fatalf("canonicalizeRFC8785() error = %v", err)
			}
			want := `{"n":` + test.want + `}`
			if string(got) != want {
				t.Fatalf("Canonicalize() = %q, want %q", got, want)
			}
		})
	}
}

func TestCanonicalizeIntegerSafety(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "positive safe boundary",
			in:   `{"n":9007199254740991}`,
			want: `{"n":9007199254740991}`,
		},
		{
			name: "negative safe boundary",
			in:   `{"n":-9007199254740991}`,
			want: `{"n":-9007199254740991}`,
		},
	}
	for _, test := range valid {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := Canonicalize([]byte(test.in))
			if err != nil {
				t.Fatalf("Canonicalize() error = %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("Canonicalize() = %q, want %q", got, test.want)
			}
		})
	}

	invalid := []struct {
		name string
		in   string
		err  error
	}{
		{name: "positive unsafe boundary", in: `{"n":9007199254740992}`, err: ErrIntegerOutOfRange},
		{name: "positive collision value", in: `{"n":9007199254740993}`, err: ErrIntegerOutOfRange},
		{name: "negative unsafe boundary", in: `{"n":-9007199254740992}`, err: ErrIntegerOutOfRange},
		{name: "negative collision value", in: `{"n":-9007199254740993}`, err: ErrIntegerOutOfRange},
		{name: "larger than int64", in: `{"n":18446744073709551616}`, err: ErrIntegerOutOfRange},
		{name: "fraction", in: `{"n":1.5}`, err: ErrNonInteger},
		{name: "decimal collision spelling", in: `{"n":9007199254740993.0}`, err: ErrNonInteger},
		{name: "exponent collision spelling", in: `{"n":9.007199254740993e15}`, err: ErrNonInteger},
	}
	for _, test := range invalid {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Canonicalize([]byte(test.in)); !errors.Is(err, test.err) {
				t.Fatalf("Canonicalize() error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestCanonicalizeRejectsIntegerCollisionPair(t *testing.T) {
	t.Parallel()

	inputs := []string{
		`{"a":9007199254740992}`,
		`{"a":9007199254740993}`,
	}
	for _, input := range inputs {
		if output, err := Canonicalize([]byte(input)); !errors.Is(err, ErrIntegerOutOfRange) {
			t.Fatalf("Canonicalize(%s) = %q, %v; want %v", input, output, err, ErrIntegerOutOfRange)
		}
	}
	for _, input := range []string{
		`{"a":9007199254740992.0}`,
		`{"a":9007199254740993.0}`,
		`{"a":9.007199254740992e15}`,
		`{"a":9.007199254740993e15}`,
	} {
		if output, err := Canonicalize([]byte(input)); !errors.Is(err, ErrNonInteger) {
			t.Fatalf("Canonicalize(%s) = %q, %v; want %v", input, output, err, ErrNonInteger)
		}
	}
}

func TestCanonicalizeRejectsNonFiniteNumbers(t *testing.T) {
	t.Parallel()

	for _, token := range []string{"NaN", "Infinity", "-Infinity", "1e400", "-1e400"} {
		token := token
		t.Run(token, func(t *testing.T) {
			t.Parallel()
			if _, err := Canonicalize([]byte(`{"n":` + token + `}`)); err == nil {
				t.Fatalf("Canonicalize(%q) accepted a non-finite number", token)
			}
		})
	}
}

func TestCanonicalizeRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	depth32 := strings.Repeat("[", 32) + "0" + strings.Repeat("]", 32)
	depth33 := strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33)
	tests := []struct {
		name string
		in   []byte
		err  error
	}{
		{name: "invalid UTF-8", in: []byte{'"', 0xff, '"'}, err: ErrInvalidUTF8},
		{name: "duplicate escaped key", in: []byte(`{"a":1,"\u0061":2}`), err: ErrDuplicateKey},
		{name: "trailing value", in: []byte(`{} []`), err: ErrTrailingData},
		{name: "trailing malformed data", in: []byte(`{} x`), err: ErrTrailingData},
		{name: "lone high surrogate", in: []byte(`"\ud800"`), err: ErrInvalidSurrogate},
		{name: "lone low surrogate", in: []byte(`"\udc00"`), err: ErrInvalidSurrogate},
		{name: "reversed surrogates", in: []byte(`"\udc00\ud800"`), err: ErrInvalidSurrogate},
		{name: "high followed by non-low", in: []byte(`"\ud800\u0041"`), err: ErrInvalidSurrogate},
		{name: "malformed Unicode escape", in: []byte(`"\u12xz"`), err: ErrInvalidSurrogate},
		{name: "depth 33", in: []byte(depth33), err: ErrNestingTooDeep},
	}

	if _, err := Canonicalize([]byte(depth32)); err != nil {
		t.Fatalf("Canonicalize(depth 32) error = %v", err)
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Canonicalize(test.in); !errors.Is(err, test.err) {
				t.Fatalf("Canonicalize() error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestCanonicalizeEnforcesInputLimitsBeforeDecode(t *testing.T) {
	t.Parallel()

	canonicalAtLimit := append(bytes.Repeat([]byte(" "), maxCanonicalJSONBytes-2), '{', '}')
	if got, err := Canonicalize(canonicalAtLimit); err != nil || string(got) != "{}" {
		t.Fatalf("Canonicalize(at limit) = %q, %v", got, err)
	}
	if _, err := Canonicalize(append(canonicalAtLimit, ' ')); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("Canonicalize(over limit) error = %v, want %v", err, ErrInputTooLarge)
	}

	signedAtLimit := append(bytes.Repeat([]byte(" "), maxSignedObjectJSONBytes-2), '{', '}')
	if got, err := CanonicalizeSignedObject(signedAtLimit); err != nil || string(got) != "{}" {
		t.Fatalf("CanonicalizeSignedObject(at limit) = %q, %v", got, err)
	}
	if _, err := CanonicalizeSignedObject(append(signedAtLimit, ' ')); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("CanonicalizeSignedObject(over limit) error = %v, want %v", err, ErrInputTooLarge)
	}
}

func TestCanonicalizeSignedObjectNumbers(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name string
		in   string
		want string
	}{
		{name: "positive boundary", in: `{"n":9007199254740991}`, want: `{"n":9007199254740991}`},
		{name: "negative boundary", in: `{"n":-9007199254740991}`, want: `{"n":-9007199254740991}`},
		{name: "negative zero", in: `{"n":-0}`, want: `{"n":0}`},
		{
			name: "unknown fields retained",
			in:   `{"known":"value","future":{"z":2,"a":[1,true,null]}}`,
			want: `{"future":{"a":[1,true,null],"z":2},"known":"value"}`,
		},
	}
	for _, test := range valid {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := CanonicalizeSignedObject([]byte(test.in))
			if err != nil {
				t.Fatalf("CanonicalizeSignedObject() error = %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("CanonicalizeSignedObject() = %q, want %q", got, test.want)
			}
		})
	}

	invalid := []struct {
		name string
		in   string
		err  error
	}{
		{name: "fraction", in: `{"n":1.0}`, err: ErrNonInteger},
		{name: "positive exponent", in: `{"n":1e0}`, err: ErrNonInteger},
		{name: "negative exponent", in: `{"n":1e-1}`, err: ErrNonInteger},
		{name: "positive overflow", in: `{"n":9007199254740992}`, err: ErrIntegerOutOfRange},
		{name: "negative overflow", in: `{"n":-9007199254740992}`, err: ErrIntegerOutOfRange},
		{name: "integer token overflow", in: `{"n":999999999999999999999999}`, err: ErrIntegerOutOfRange},
		{name: "non-object root", in: `[1,2,3]`, err: ErrSignedObject},
	}
	for _, test := range invalid {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := CanonicalizeSignedObject([]byte(test.in)); !errors.Is(err, test.err) {
				t.Fatalf("CanonicalizeSignedObject() error = %v, want %v", err, test.err)
			}
		})
	}
}
