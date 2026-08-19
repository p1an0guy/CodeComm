package main

import (
	"bytes"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestParseDaemonOptionsAcceptsRepeatedMeshFlags(t *testing.T) {
	root := t.TempDir()
	peerID := daemonMeshTestDeviceID('1')
	options, err := parseDaemonOptions([]string{
		"--foreground",
		"--state", filepath.Join(root, "state.db"),
		"--consensus-dir", filepath.Join(root, "consensus"),
		"--endpoint", daemonTestEndpoint(t).String(),
		"--session", string(daemonTestSessionID),
		"--workspace", string(daemonTestWorkspaceID),
		"--peer-listen", "192.0.2.10:47831",
		"--peer-listen", "[2001:db8::10]:47831",
		"--peer-route", strings.Join([]string{
			string(peerID),
			"198.51.100.20:47831",
			"192.0.2.10",
		}, ","),
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseDaemonOptions() error = %v", err)
	}
	if len(options.peerListeners) != 2 ||
		len(options.peerRoutes) != 1 ||
		options.peerRoutes[0].deviceID != peerID {
		t.Fatalf("mesh options = %#v", options)
	}
}

func TestParseDaemonMeshOptionsCanonicalizesSelectedRoutes(t *testing.T) {
	firstID := daemonMeshTestDeviceID('1')
	secondID := daemonMeshTestDeviceID('2')
	listeners, routes, err := parseDaemonMeshOptions(
		[]string{"[2001:db8::10]:47831", "192.0.2.10:47831"},
		[]string{
			strings.Join(
				[]string{
					string(secondID),
					"[2001:db8::20]:47831",
					"2001:db8::10",
				},
				",",
			),
			strings.Join(
				[]string{
					string(firstID),
					"198.51.100.20:47831",
					"192.0.2.10",
				},
				",",
			),
		},
	)
	if err != nil {
		t.Fatalf("parseDaemonMeshOptions() error = %v", err)
	}
	wantListeners := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:47831"),
		netip.MustParseAddrPort("[2001:db8::10]:47831"),
	}
	if !sameDaemonListeners(listeners, wantListeners) {
		t.Fatalf("listeners = %v, want %v", listeners, wantListeners)
	}
	if len(routes) != 2 ||
		routes[0].deviceID != firstID ||
		routes[0].remote !=
			netip.MustParseAddrPort("198.51.100.20:47831") ||
		routes[0].local != netip.MustParseAddr("192.0.2.10") ||
		routes[1].deviceID != secondID {
		t.Fatalf("routes = %#v", routes)
	}
}

func TestParseDaemonMeshOptionsRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	firstID := daemonMeshTestDeviceID('1')
	secondID := daemonMeshTestDeviceID('2')
	validListener := []string{"192.0.2.10:47831"}
	validRoute := strings.Join([]string{
		string(firstID),
		"198.51.100.20:47831",
		"192.0.2.10",
	}, ",")
	tests := []struct {
		name      string
		listeners []string
		routes    []string
	}{
		{
			name:   "route without listener",
			routes: []string{validRoute},
		},
		{
			name:      "duplicate listener",
			listeners: append(validListener, validListener...),
		},
		{
			name:      "wildcard listener",
			listeners: []string{"0.0.0.0:47831"},
		},
		{
			name:      "loopback listener",
			listeners: []string{"127.0.0.1:47831"},
		},
		{
			name:      "malformed route",
			listeners: validListener,
			routes:    []string{"not,a,complete,route"},
		},
		{
			name:      "family mismatch",
			listeners: validListener,
			routes: []string{strings.Join([]string{
				string(firstID),
				"[2001:db8::20]:47831",
				"192.0.2.10",
			}, ",")},
		},
		{
			name:      "link local zone mismatch",
			listeners: validListener,
			routes: []string{strings.Join([]string{
				string(firstID),
				"[fe80::20%en0]:47831",
				"fe80::10%en1",
			}, ",")},
		},
		{
			name:      "endpoint assigned to two peers",
			listeners: validListener,
			routes: []string{
				validRoute,
				strings.Join([]string{
					string(secondID),
					"198.51.100.20:47831",
					"192.0.2.10",
				}, ","),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := parseDaemonMeshOptions(
				test.listeners,
				test.routes,
			); !errors.Is(err, errInvalidDaemonOptions) {
				t.Fatalf(
					"parseDaemonMeshOptions() error = %v, want %v",
					err,
					errInvalidDaemonOptions,
				)
			}
		})
	}
}

func TestValidateDaemonMeshOptionsRejectsNoncanonicalTypedInput(
	t *testing.T,
) {
	options := daemonOptions{
		peerListeners: []netip.AddrPort{
			netip.MustParseAddrPort("[2001:db8::10]:47831"),
			netip.MustParseAddrPort("192.0.2.10:47831"),
		},
	}
	if err := validateDaemonMeshOptions(options); err == nil {
		t.Fatal("validateDaemonMeshOptions() accepted unsorted listeners")
	}
}

func daemonMeshTestDeviceID(fill byte) domain.DeviceID {
	return domain.DeviceID("cc1" + strings.Repeat(string(fill), 64))
}
