package codec

import (
	"bytes"
	"errors"
	"testing"
)

func TestRemoveCanonicalObjectMemberPreservesExactUnknownValues(t *testing.T) {
	t.Parallel()

	input := []byte(
		`{"a":[{"escaped":"\u0000"}],"signature":"AQ","z":{"n":9007199254740991}}`,
	)
	original := bytes.Clone(input)
	unsigned, value, err := RemoveCanonicalObjectMember(input, "signature")
	if err != nil {
		t.Fatalf("RemoveCanonicalObjectMember() error = %v", err)
	}
	if want := []byte(`{"a":[{"escaped":"\u0000"}],"z":{"n":9007199254740991}}`); !bytes.Equal(unsigned, want) {
		t.Fatalf("unsigned = %s, want %s", unsigned, want)
	}
	if want := []byte(`"AQ"`); !bytes.Equal(value, want) {
		t.Fatalf("value = %s, want %s", value, want)
	}

	unsigned[0] = '['
	value[0] = 'x'
	if !bytes.Equal(input, original) {
		t.Fatal("returned buffers alias input")
	}
}

func TestRemoveCanonicalObjectMemberHandlesEveryPosition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		target string
		want   string
		value  string
	}{
		{
			name:   "only",
			input:  `{"signature":"AQ"}`,
			target: "signature",
			want:   `{}`,
			value:  `"AQ"`,
		},
		{
			name:   "first",
			input:  `{"a":1,"b":2}`,
			target: "a",
			want:   `{"b":2}`,
			value:  `1`,
		},
		{
			name:   "last",
			input:  `{"a":1,"b":2}`,
			target: "b",
			want:   `{"a":1}`,
			value:  `2`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, value, err := RemoveCanonicalObjectMember(
				[]byte(test.input),
				test.target,
			)
			if err != nil {
				t.Fatalf("RemoveCanonicalObjectMember() error = %v", err)
			}
			if string(got) != test.want || string(value) != test.value {
				t.Fatalf(
					"RemoveCanonicalObjectMember() = (%s, %s), want (%s, %s)",
					got,
					value,
					test.want,
					test.value,
				)
			}
		})
	}
}

func TestRemoveCanonicalObjectMemberRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		target string
		want   error
	}{
		{
			name:   "noncanonical",
			input:  `{"z":1, "a":2}`,
			target: "z",
			want:   ErrNoncanonicalObject,
		},
		{
			name:   "missing",
			input:  `{"a":1}`,
			target: "signature",
			want:   ErrObjectMemberAbsent,
		},
		{
			name:   "empty target",
			input:  `{"a":1}`,
			target: "",
			want:   ErrObjectMember,
		},
		{
			name:   "not object",
			input:  `[]`,
			target: "signature",
			want:   ErrSignedObject,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			unsigned, value, err := RemoveCanonicalObjectMember(
				[]byte(test.input),
				test.target,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if unsigned != nil || value != nil {
				t.Fatalf("result = (%s, %s), want nil buffers", unsigned, value)
			}
		})
	}
}
