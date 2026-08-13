package transport

import (
	"errors"
	"testing"
)

func TestSelectPlaneRequiresOneExactALPN(t *testing.T) {
	t.Parallel()

	valid := []struct {
		protocol string
		plane    Plane
	}{
		{protocol: ALPNPairing, plane: PlanePairing},
		{protocol: ALPNConsensus, plane: PlaneConsensus},
		{protocol: ALPNContent, plane: PlaneContent},
	}
	for _, test := range valid {
		got, err := SelectPlane([]string{test.protocol})
		if err != nil || got != test.plane {
			t.Errorf("SelectPlane(%q) = (%q, %v), want %q", test.protocol, got, err, test.plane)
		}
		protocol, err := test.plane.ALPN()
		if err != nil || protocol != test.protocol {
			t.Errorf("Plane(%q).ALPN() = (%q, %v), want %q", test.plane, protocol, err, test.protocol)
		}
	}

	for _, offered := range [][]string{
		nil,
		{},
		{"h2"},
		{ALPNPairing, "h2"},
		{ALPNConsensus, ALPNContent},
		{"CODECOMM-CONTENT/1"},
	} {
		if _, err := SelectPlane(offered); !errors.Is(err, ErrInvalidALPNOffer) {
			t.Errorf("SelectPlane(%q) error = %v, want %v", offered, err, ErrInvalidALPNOffer)
		}
	}
	if _, err := Plane("future").ALPN(); !errors.Is(err, ErrInvalidALPNOffer) {
		t.Fatalf("unknown Plane.ALPN() error = %v, want %v", err, ErrInvalidALPNOffer)
	}
}
