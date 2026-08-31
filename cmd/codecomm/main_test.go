package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestParseVoterTargetSortsAndRejectsInvalidSets(t *testing.T) {
	first := "cc1" + strings.Repeat("1", 64)
	second := "cc1" + strings.Repeat("2", 64)
	third := "cc1" + strings.Repeat("3", 64)
	target, err := parseVoterTarget([]string{third, first, second})
	if err != nil {
		t.Fatalf("parseVoterTarget(): %v", err)
	}
	want := []domain.DeviceID{
		domain.DeviceID(first),
		domain.DeviceID(second),
		domain.DeviceID(third),
	}
	for index := range want {
		if target[index] != want[index] {
			t.Fatalf("target = %#v, want %#v", target, want)
		}
	}
	for _, values := range [][]string{
		{first, first, second},
		{first, second},
		{"invalid"},
	} {
		if _, err := parseVoterTarget(values); err == nil {
			t.Fatalf("parseVoterTarget(%q) succeeded", values)
		}
	}
}

func TestConfirmOperatorActionRequiresExactYes(t *testing.T) {
	for _, test := range []struct {
		input string
		want  bool
	}{
		{input: "yes\n", want: true},
		{input: " yes \n", want: true},
		{input: "y\n"},
		{input: "YES\n"},
		{input: ""},
	} {
		var output bytes.Buffer
		got, err := confirmOperatorAction(
			t.Context(),
			strings.NewReader(test.input),
			&output,
			"confirm: ",
		)
		if err != nil {
			t.Fatalf("confirmOperatorAction(%q): %v", test.input, err)
		}
		if got != test.want || output.String() != "confirm: " {
			t.Fatalf(
				"confirmOperatorAction(%q) = %t, output %q",
				test.input,
				got,
				output.String(),
			)
		}
	}
}

func TestEqualDeviceIDsRequiresExactOrderedTarget(t *testing.T) {
	first := domain.DeviceID("cc1" + strings.Repeat("1", 64))
	second := domain.DeviceID("cc1" + strings.Repeat("2", 64))
	if !equalDeviceIDs(
		[]domain.DeviceID{first, second},
		[]domain.DeviceID{first, second},
	) {
		t.Fatal("equal target was rejected")
	}
	for _, candidate := range [][]domain.DeviceID{
		{second, first},
		{first},
		{first, first},
	} {
		if equalDeviceIDs(
			[]domain.DeviceID{first, second},
			candidate,
		) {
			t.Fatalf("unequal target was accepted: %v", candidate)
		}
	}
}
