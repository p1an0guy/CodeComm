package joinbootstrap

import (
	"net/netip"
	"testing"
)

func TestValidJoinEndpointAllowsIPv4LinkLocalAndRejectsUnsafeAddresses(
	t *testing.T,
) {
	t.Parallel()

	for raw, expected := range map[string]bool{
		"169.254.10.20:47831": true,
		"10.0.0.5:47831":      true,
		"127.0.0.1:47831":     false,
		"224.0.0.1:47831":     false,
		"[fe80::1]:47831":     false,
		"[2001:db8::1]:47831": true,
	} {
		endpoint := netip.MustParseAddrPort(raw)
		if got := validJoinEndpoint(endpoint); got != expected {
			t.Errorf("validJoinEndpoint(%q) = %t, want %t", raw, got, expected)
		}
	}
}
