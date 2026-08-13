package discovery

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const (
	endpointTestSessionID   = domain.UUIDv7("01890f47-3e72-7000-8000-000000000011")
	endpointTestWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440011")
	endpointTestInterval    = 20 * time.Second
)

var endpointTestNow = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

func TestEndpointSetSignParseValidateAndRelay(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 1)
	member := endpointMember(t, publicKey)
	value := validEndpointSet(member.ID)
	encoded, err := signEndpointSet(value, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet() error = %v", err)
	}
	if len(encoded) > MaxEndpointSetBytes {
		t.Fatalf("encoded length = %d, limit %d", len(encoded), MaxEndpointSetBytes)
	}

	unverified, err := ParseEndpointSet(encoded)
	if err != nil {
		t.Fatalf("ParseEndpointSet() error = %v", err)
	}
	original := bytes.Clone(encoded)
	encoded[0] = '['
	if got := unverified.EndpointSet(); !reflect.DeepEqual(got, value) {
		t.Fatalf("unverified endpoint set = %#v, want %#v", got, value)
	}
	verified, err := unverified.Verify(endpointExpectation(member))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got := verified.EndpointSet(); !reflect.DeepEqual(got, value) {
		t.Fatalf("verified endpoint set = %#v, want %#v", got, value)
	}
	if !bytes.Equal(verified.CanonicalBytes(), original) {
		t.Fatalf("CanonicalBytes() = %s, want %s", verified.CanonicalBytes(), original)
	}
	relayed, err := codec.DecodeBase64URL(verified.OpaqueRelay())
	if err != nil {
		t.Fatalf("DecodeBase64URL(OpaqueRelay()) error = %v", err)
	}
	if !bytes.Equal(relayed, original) {
		t.Fatalf("opaque relay decoded = %s, want %s", relayed, original)
	}

	decodedCopy := verified.EndpointSet()
	decodedCopy.Endpoints[0].Port++
	canonicalCopy := verified.CanonicalBytes()
	canonicalCopy[0] = '['
	if reflect.DeepEqual(verified.EndpointSet(), decodedCopy) {
		t.Fatal("EndpointSet() returned aliased endpoint storage")
	}
	if verified.CanonicalBytes()[0] != '{' {
		t.Fatal("CanonicalBytes() returned aliased storage")
	}
}

func TestEndpointSignerRestrictsPublicationToSelectedListener(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 33)
	member := endpointMember(t, publicKey)
	value := validEndpointSet(member.ID)
	value.Endpoints[1].Port = 47831
	signer, err := NewEndpointSigner(
		endpointTestInterval,
		47831,
		[]netip.Addr{
			netip.MustParseAddr("192.0.2.4"),
			netip.MustParseAddr("2001:db8::1"),
		},
	)
	if err != nil {
		t.Fatalf("NewEndpointSigner() error = %v", err)
	}
	encoded, err := signer.Sign(value, privateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := ValidateEndpointSet(
		encoded,
		endpointExpectation(member),
	); err != nil {
		t.Fatalf("ValidateEndpointSet() error = %v", err)
	}

	unselected := value
	unselected.Endpoints = append([]Endpoint(nil), value.Endpoints...)
	unselected.Endpoints[1].IP = netip.MustParseAddr("2001:db8::2")
	if _, err := signer.Sign(unselected, privateKey); !errors.Is(
		err,
		ErrEndpointNotSelected,
	) {
		t.Fatalf("Sign(unselected) error = %v, want %v", err, ErrEndpointNotSelected)
	}
	wrongPort := value
	wrongPort.Endpoints = append([]Endpoint(nil), value.Endpoints...)
	wrongPort.Endpoints[0].Port = 443
	if _, err := signer.Sign(wrongPort, privateKey); !errors.Is(
		err,
		ErrEndpointNotSelected,
	) {
		t.Fatalf("Sign(wrong port) error = %v, want %v", err, ErrEndpointNotSelected)
	}
}

func TestEndpointSignerRejectsInvalidSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		port      uint16
		addresses []netip.Addr
	}{
		{name: "zero port", addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
		{name: "empty", port: 47831},
		{
			name: "duplicate",
			port: 47831,
			addresses: []netip.Addr{
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("192.0.2.1"),
			},
		},
		{
			name:      "link local IPv6",
			port:      47831,
			addresses: []netip.Addr{netip.MustParseAddr("fe80::1")},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if signer, err := NewEndpointSigner(
				endpointTestInterval,
				test.port,
				test.addresses,
			); !errors.Is(err, ErrEndpointSigner) || signer != nil {
				t.Fatalf("NewEndpointSigner() = (%#v, %v), want ErrEndpointSigner", signer, err)
			}
		})
	}
}

func TestEndpointSetGoldenVector(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 7)
	value := validEndpointSet(endpointMember(t, publicKey).ID)
	encoded, err := signEndpointSet(value, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet() error = %v", err)
	}
	const want = `{"device_id":"cc1fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889","endpoint_sequence":1786123456789,"endpoints":[{"ip":"192.0.2.4","port":47831},{"ip":"2001:db8::1","port":443}],"expires_at":"2026-08-13T12:02:40Z","issued_at":"2026-08-13T12:00:00Z","recovery_generation":0,"schema_version":1,"session_id":"01890f47-3e72-7000-8000-000000000011","signature":"eKt6WGJir6j4rs3EA7TMF_AB4D_Q_BhBDcOcQujnWkc_ND389NIhl5k5xn18PqAc_uIdHT3g4fEKXmfAmu9HCg","workspace_id":"550e8400-e29b-41d4-a716-446655440011"}`
	if string(encoded) != want {
		t.Fatalf("golden endpoint set = %s\nwant = %s", encoded, want)
	}
}

func TestEndpointSetAddressValidation(t *testing.T) {
	t.Parallel()

	_, privateKey := endpointIdentityKey(t, 1)
	member := endpointMemberFromPrivate(t, privateKey)
	value := validEndpointSet(member.ID)
	tests := []struct {
		name string
		ip   string
	}{
		{name: "IPv4 loopback", ip: "127.0.0.1"},
		{name: "IPv4 unspecified", ip: "0.0.0.0"},
		{name: "IPv4 multicast", ip: "224.0.0.1"},
		{name: "IPv4 broadcast", ip: "255.255.255.255"},
		{name: "IPv4 leading zero", ip: "192.168.001.1"},
		{name: "IPv6 loopback", ip: "::1"},
		{name: "IPv6 unspecified", ip: "::"},
		{name: "IPv6 multicast", ip: "ff02::1"},
		{name: "IPv4 mapped IPv6", ip: "::ffff:192.0.2.1"},
		{name: "IPv6 link local", ip: "fe80::1"},
		{name: "IPv6 link-local zone", ip: "fe80::1%eth0"},
		{name: "IPv6 global zone", ip: "2001:db8::1%eth0"},
		{name: "IPv6 uppercase", ip: "2001:DB8::1"},
		{name: "IPv6 brackets", ip: "[2001:db8::1]"},
		{name: "hostname", ip: "example.test"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire := endpointSetToWire(value)
			wire.Endpoints = []endpointWire{{IP: test.ip, Port: 47831}}
			encoded := signEndpointWire(
				t,
				wire,
				privateKey,
				codec.SignatureEndpointHints,
			)
			if _, err := ParseEndpointSet(encoded); !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("ParseEndpointSet(%q) error = %v, want %v", test.ip, err, ErrInvalidEndpoint)
			}
		})
	}
}

func TestEndpointSetAllowsCanonicalUnicastAddresses(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 1)
	member := endpointMember(t, publicKey)
	value := validEndpointSet(member.ID)
	value.Endpoints = []Endpoint{
		{IP: netip.MustParseAddr("169.254.1.2"), Port: 1},
		{IP: netip.MustParseAddr("192.0.2.4"), Port: 65535},
		{IP: netip.MustParseAddr("2001:db8::1"), Port: 47831},
	}
	encoded, err := signEndpointSet(value, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet() error = %v", err)
	}
	if _, err := ValidateEndpointSet(
		encoded,
		endpointExpectation(member),
	); err != nil {
		t.Fatalf("ValidateEndpointSet() error = %v", err)
	}
}

func TestEndpointSetRequiresCanonicalOrderAndUniqueEndpoints(t *testing.T) {
	t.Parallel()

	_, privateKey := endpointIdentityKey(t, 1)
	member := endpointMemberFromPrivate(t, privateKey)
	base := validEndpointSet(member.ID)
	tests := []struct {
		name      string
		endpoints []Endpoint
		want      error
	}{
		{
			name: "IPv6 before IPv4",
			endpoints: []Endpoint{
				{IP: netip.MustParseAddr("2001:db8::1"), Port: 1},
				{IP: netip.MustParseAddr("192.0.2.1"), Port: 1},
			},
			want: ErrEndpointOrder,
		},
		{
			name: "IPv4 bytes descending",
			endpoints: []Endpoint{
				{IP: netip.MustParseAddr("192.0.2.2"), Port: 1},
				{IP: netip.MustParseAddr("192.0.2.1"), Port: 1},
			},
			want: ErrEndpointOrder,
		},
		{
			name: "IPv6 bytes descending",
			endpoints: []Endpoint{
				{IP: netip.MustParseAddr("2001:db8::2"), Port: 1},
				{IP: netip.MustParseAddr("2001:db8::1"), Port: 1},
			},
			want: ErrEndpointOrder,
		},
		{
			name: "ports descending",
			endpoints: []Endpoint{
				{IP: netip.MustParseAddr("192.0.2.1"), Port: 2},
				{IP: netip.MustParseAddr("192.0.2.1"), Port: 1},
			},
			want: ErrEndpointOrder,
		},
		{
			name: "duplicate",
			endpoints: []Endpoint{
				{IP: netip.MustParseAddr("192.0.2.1"), Port: 1},
				{IP: netip.MustParseAddr("192.0.2.1"), Port: 1},
			},
			want: ErrDuplicateEndpoint,
		},
		{
			name: "same address ports ascending",
			endpoints: []Endpoint{
				{IP: netip.MustParseAddr("192.0.2.1"), Port: 1},
				{IP: netip.MustParseAddr("192.0.2.1"), Port: 2},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := base
			value.Endpoints = test.endpoints
			_, err := signEndpointSet(value, privateKey, endpointTestInterval)
			if !errors.Is(err, test.want) {
				t.Fatalf("signEndpointSet() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestEndpointSetBoundsAndCanonicalEncoding(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 1)
	member := endpointMember(t, publicKey)
	base := validEndpointSet(member.ID)

	encoded, err := signEndpointSet(base, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet() error = %v", err)
	}
	if _, err := ParseEndpointSet(append(encoded, '\n')); !errors.Is(err, ErrNoncanonicalMessage) {
		t.Fatalf("ParseEndpointSet(noncanonical) error = %v, want %v", err, ErrNoncanonicalMessage)
	}
	if _, err := ParseEndpointSet(
		[]byte(strings.Repeat("x", MaxEndpointSetBytes+1)),
	); !errors.Is(err, ErrEndpointSetTooLarge) {
		t.Fatalf("ParseEndpointSet(oversized) error = %v, want %v", err, ErrEndpointSetTooLarge)
	}
	if _, err := ParseEndpointSet(nil); !errors.Is(err, ErrInvalidEndpointSet) {
		t.Fatalf("ParseEndpointSet(nil) error = %v, want %v", err, ErrInvalidEndpointSet)
	}

	for _, count := range []int{0, MaxEndpointsPerSet + 1} {
		value := base
		value.Endpoints = endpointCount(count)
		if _, err := signEndpointSet(
			value,
			privateKey,
			endpointTestInterval,
		); !errors.Is(err, ErrInvalidEndpointSet) {
			t.Errorf("signEndpointSet(%d endpoints) error = %v, want %v", count, err, ErrInvalidEndpointSet)
		}
	}
	value := base
	value.Endpoints = endpointCount(MaxEndpointsPerSet)
	if _, err := signEndpointSet(value, privateKey, endpointTestInterval); err != nil {
		t.Fatalf("signEndpointSet(max endpoints) error = %v", err)
	}

	value = base
	value.EndpointSequence = 0
	if _, err := signEndpointSet(value, privateKey, endpointTestInterval); !errors.Is(err, ErrEndpointSequence) {
		t.Errorf("signEndpointSet(sequence 0) error = %v, want %v", err, ErrEndpointSequence)
	}
	value.EndpointSequence = domain.MaxSafeInteger + 1
	if _, err := signEndpointSet(value, privateKey, endpointTestInterval); !errors.Is(err, ErrEndpointSequence) {
		t.Errorf("signEndpointSet(sequence too large) error = %v, want %v", err, ErrEndpointSequence)
	}
	value = base
	value.RecoveryGeneration = domain.MaxSafeInteger + 1
	if _, err := signEndpointSet(value, privateKey, endpointTestInterval); !errors.Is(err, ErrInvalidEndpointSet) {
		t.Errorf("signEndpointSet(generation too large) error = %v, want %v", err, ErrInvalidEndpointSet)
	}
	value = base
	value.EndpointSequence = domain.MaxSafeInteger
	value.RecoveryGeneration = domain.MaxSafeInteger
	maximums, err := signEndpointSet(value, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet(maximum integers) error = %v", err)
	}
	if _, err := ValidateEndpointSet(
		maximums,
		func() EndpointSetExpectation {
			expected := endpointExpectation(member)
			expected.RecoveryGeneration = domain.MaxSafeInteger
			return expected
		}(),
	); err != nil {
		t.Fatalf("ValidateEndpointSet(maximum integers) error = %v", err)
	}

	invalidValues := []struct {
		name   string
		change func(*EndpointSet)
		want   error
	}{
		{
			name: "session ID",
			change: func(value *EndpointSet) {
				value.SessionID = "not-a-session"
			},
			want: ErrInvalidEndpointSet,
		},
		{
			name: "workspace ID",
			change: func(value *EndpointSet) {
				value.WorkspaceID = "not-a-workspace"
			},
			want: ErrInvalidEndpointSet,
		},
		{
			name: "device ID",
			change: func(value *EndpointSet) {
				value.DeviceID = "not-a-device"
			},
			want: ErrInvalidEndpointSet,
		},
		{
			name: "zero port",
			change: func(value *EndpointSet) {
				value.Endpoints[0].Port = 0
			},
			want: ErrInvalidEndpoint,
		},
		{
			name: "invalid netip address",
			change: func(value *EndpointSet) {
				value.Endpoints[0].IP = netip.Addr{}
			},
			want: ErrInvalidEndpoint,
		},
	}
	for _, test := range invalidValues {
		value := base.clone()
		test.change(&value)
		if _, err := signEndpointSet(
			value,
			privateKey,
			endpointTestInterval,
		); !errors.Is(err, test.want) {
			t.Errorf("signEndpointSet(invalid %s) error = %v, want %v", test.name, err, test.want)
		}
	}

	wire := endpointSetToWire(base)
	wire.SchemaVersion++
	schemaObject := signEndpointWire(
		t,
		wire,
		privateKey,
		codec.SignatureEndpointHints,
	)
	if _, err := ParseEndpointSet(schemaObject); !errors.Is(err, ErrEndpointSetSchema) {
		t.Errorf("ParseEndpointSet(schema 2) error = %v, want %v", err, ErrEndpointSetSchema)
	}
	wire = endpointSetToWire(base)
	wire.Signature = "not-base64!"
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	malformedSignature := mustCanonicalEndpointObject(t, raw)
	if _, err := ParseEndpointSet(malformedSignature); !errors.Is(err, ErrInvalidEndpointSet) {
		t.Errorf("ParseEndpointSet(malformed signature) error = %v, want %v", err, ErrInvalidEndpointSet)
	}

	members := endpointMembers(t, base)
	rawUnsigned, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal(unsigned) error = %v", err)
	}
	if _, err := ParseEndpointSet(
		mustCanonicalEndpointObject(t, rawUnsigned),
	); !errors.Is(err, ErrInvalidEndpointSet) {
		t.Errorf("ParseEndpointSet(missing signature) error = %v, want %v", err, ErrInvalidEndpointSet)
	}

	members = endpointMembers(t, base)
	var endpointMembersValue []map[string]json.RawMessage
	if err := json.Unmarshal(
		members["endpoints"],
		&endpointMembersValue,
	); err != nil {
		t.Fatalf("json.Unmarshal(endpoints) error = %v", err)
	}
	endpointMembersValue[0]["port"] = json.RawMessage(`65536`)
	members["endpoints"], err = json.Marshal(endpointMembersValue)
	if err != nil {
		t.Fatalf("json.Marshal(endpoints) error = %v", err)
	}
	oversizedPort := signEndpointMembers(
		t,
		members,
		privateKey,
		codec.SignatureEndpointHints,
	)
	if _, err := ParseEndpointSet(oversizedPort); !errors.Is(err, ErrInvalidEndpointSet) {
		t.Errorf("ParseEndpointSet(port 65536) error = %v, want %v", err, ErrInvalidEndpointSet)
	}
}

func TestEndpointSetTimeWindows(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 1)
	member := endpointMember(t, publicKey)
	base := validEndpointSet(member.ID)

	signTests := []struct {
		name     string
		issuedAt domain.WholeSecondTimestamp
		expires  domain.WholeSecondTimestamp
		interval time.Duration
		want     error
	}{
		{
			name:     "exact TTL",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:02:40Z",
			interval: endpointTestInterval,
		},
		{
			name:     "TTL one second over",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:02:41Z",
			interval: endpointTestInterval,
			want:     ErrEndpointSetTime,
		},
		{
			name:     "zero duration",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:00:00Z",
			interval: endpointTestInterval,
			want:     ErrEndpointSetTime,
		},
		{
			name:     "negative duration",
			issuedAt: "2026-08-13T12:00:01Z",
			expires:  "2026-08-13T12:00:00Z",
			interval: endpointTestInterval,
			want:     ErrEndpointSetTime,
		},
		{
			name:     "fractional issued at",
			issuedAt: "2026-08-13T12:00:00.1Z",
			expires:  "2026-08-13T12:00:01Z",
			interval: endpointTestInterval,
			want:     ErrEndpointSetTime,
		},
		{
			name:     "fractional expires at",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:00:01.1Z",
			interval: endpointTestInterval,
			want:     ErrEndpointSetTime,
		},
		{
			name:     "zero interval",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:00:01Z",
			want:     ErrEndpointAdvertisementInterval,
		},
		{
			name:     "fractional interval",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:00:01Z",
			interval: 5*time.Second + time.Nanosecond,
			want:     ErrEndpointAdvertisementInterval,
		},
		{
			name:     "negative interval",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:00:01Z",
			interval: -time.Second,
			want:     ErrEndpointAdvertisementInterval,
		},
		{
			name:     "minimum interval",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:00:01Z",
			interval: 5 * time.Second,
		},
		{
			name:     "below minimum interval",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:00:01Z",
			interval: 4 * time.Second,
			want:     ErrEndpointAdvertisementInterval,
		},
		{
			name:     "maximum interval",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:00:01Z",
			interval: 300 * time.Second,
		},
		{
			name:     "above maximum interval",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:00:01Z",
			interval: 301 * time.Second,
			want:     ErrEndpointAdvertisementInterval,
		},
		{
			name:     "extreme interval",
			issuedAt: "2026-08-13T12:00:00Z",
			expires:  "2026-08-13T12:00:01Z",
			interval: time.Duration(1<<63 - 1),
			want:     ErrEndpointAdvertisementInterval,
		},
	}
	for _, test := range signTests {
		test := test
		t.Run("sign/"+test.name, func(t *testing.T) {
			t.Parallel()
			value := base
			value.IssuedAt = test.issuedAt
			value.ExpiresAt = test.expires
			_, err := signEndpointSet(value, privateKey, test.interval)
			if !errors.Is(err, test.want) {
				t.Fatalf("signEndpointSet() error = %v, want %v", err, test.want)
			}
		})
	}

	verifyTests := []struct {
		name     string
		issuedAt domain.WholeSecondTimestamp
		expires  domain.WholeSecondTimestamp
		now      time.Time
		want     error
	}{
		{
			name:     "issued at exact future skew",
			issuedAt: "2026-08-13T12:02:00Z",
			expires:  "2026-08-13T12:02:01Z",
			now:      endpointTestNow,
		},
		{
			name:     "issued one second past future skew",
			issuedAt: "2026-08-13T12:02:01Z",
			expires:  "2026-08-13T12:02:02Z",
			now:      endpointTestNow,
			want:     ErrEndpointSetFuture,
		},
		{
			name:     "expiry one second future",
			issuedAt: "2026-08-13T11:59:59Z",
			expires:  "2026-08-13T12:00:01Z",
			now:      endpointTestNow,
		},
		{
			name:     "expiry equal now",
			issuedAt: "2026-08-13T11:59:59Z",
			expires:  "2026-08-13T12:00:00Z",
			now:      endpointTestNow,
			want:     ErrEndpointSetExpired,
		},
		{
			name:     "expiry in past",
			issuedAt: "2026-08-13T11:59:58Z",
			expires:  "2026-08-13T11:59:59Z",
			now:      endpointTestNow,
			want:     ErrEndpointSetExpired,
		},
	}
	for _, test := range verifyTests {
		test := test
		t.Run("verify/"+test.name, func(t *testing.T) {
			t.Parallel()
			value := base
			value.IssuedAt = test.issuedAt
			value.ExpiresAt = test.expires
			encoded, err := signEndpointSet(
				value,
				privateKey,
				endpointTestInterval,
			)
			if err != nil {
				t.Fatalf("signEndpointSet() error = %v", err)
			}
			expected := endpointExpectation(member)
			expected.Now = test.now
			_, err = ValidateEndpointSet(encoded, expected)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateEndpointSet() error = %v, want %v", err, test.want)
			}
		})
	}

	localBoundary := base
	localBoundary.ExpiresAt = domain.WholeSecondTimestamp(
		endpointTestNow.Add(
			EndpointHintTTLIntervals*endpointTestInterval +
				EndpointSetClockSkew,
		).Format(time.RFC3339),
	)
	if err := localBoundary.validateLocalTime(
		endpointTestNow,
		endpointTestInterval,
	); err != nil {
		t.Fatalf("validateLocalTime(exact upper bound) error = %v", err)
	}
	localBoundary.ExpiresAt = domain.WholeSecondTimestamp(
		endpointTestNow.Add(
			EndpointHintTTLIntervals*endpointTestInterval +
				EndpointSetClockSkew +
				time.Second,
		).Format(time.RFC3339),
	)
	if err := localBoundary.validateLocalTime(
		endpointTestNow,
		endpointTestInterval,
	); !errors.Is(err, ErrEndpointSetFuture) {
		t.Fatalf("validateLocalTime(past upper bound) error = %v, want %v", err, ErrEndpointSetFuture)
	}
}

func TestEndpointSetBindsActiveMemberAndLineage(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 1)
	member := endpointMember(t, publicKey)
	value := validEndpointSet(member.ID)
	encoded, err := signEndpointSet(value, privateKey, endpointTestInterval)
	if err != nil {
		t.Fatalf("signEndpointSet() error = %v", err)
	}
	tests := []struct {
		name   string
		change func(*EndpointSetExpectation)
		want   error
	}{
		{
			name: "session",
			change: func(value *EndpointSetExpectation) {
				value.SessionID = "01890f47-3e72-7000-8000-000000000012"
			},
			want: ErrEndpointSetLineage,
		},
		{
			name: "workspace",
			change: func(value *EndpointSetExpectation) {
				value.WorkspaceID = "550e8400-e29b-41d4-a716-446655440012"
			},
			want: ErrEndpointSetLineage,
		},
		{
			name: "generation",
			change: func(value *EndpointSetExpectation) {
				value.RecoveryGeneration++
			},
			want: ErrEndpointSetLineage,
		},
		{
			name: "revoked member",
			change: func(value *EndpointSetExpectation) {
				value.Member.Status = device.StatusRevoked
			},
			want: ErrEndpointSetMember,
		},
		{
			name: "member requiring readmission",
			change: func(value *EndpointSetExpectation) {
				value.Member.Status = device.StatusRequiresReadmission
			},
			want: ErrEndpointSetMember,
		},
		{
			name: "invalid member identity",
			change: func(value *EndpointSetExpectation) {
				value.Member.IdentityPublicKey[0] ^= 1
			},
			want: ErrEndpointSetMember,
		},
		{
			name: "zero local time",
			change: func(value *EndpointSetExpectation) {
				value.Now = time.Time{}
			},
			want: ErrEndpointSetTime,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			expected := endpointExpectation(member)
			expected.Member.IdentityPublicKey = bytes.Clone(
				expected.Member.IdentityPublicKey,
			)
			test.change(&expected)
			_, err := ValidateEndpointSet(encoded, expected)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateEndpointSet() error = %v, want %v", err, test.want)
			}
		})
	}

	otherPublicKey, _ := endpointIdentityKey(t, 2)
	otherMember := endpointMember(t, otherPublicKey)
	if _, err := ValidateEndpointSet(
		encoded,
		endpointExpectation(otherMember),
	); !errors.Is(err, codecommcrypto.ErrSignatureVerification) {
		t.Fatalf("ValidateEndpointSet(wrong member) error = %v, want %v", err, codecommcrypto.ErrSignatureVerification)
	}

	wire := endpointSetToWire(value)
	wire.DeviceID = string(otherMember.ID)
	wrongDevice := signEndpointWire(
		t,
		wire,
		privateKey,
		codec.SignatureEndpointHints,
	)
	if _, err := ValidateEndpointSet(
		wrongDevice,
		endpointExpectation(member),
	); !errors.Is(err, ErrEndpointSetIdentity) {
		t.Fatalf("ValidateEndpointSet(wrong device ID) error = %v, want %v", err, ErrEndpointSetIdentity)
	}

	value.DeviceID = otherMember.ID
	if _, err := signEndpointSet(
		value,
		privateKey,
		endpointTestInterval,
	); !errors.Is(err, ErrEndpointSetIdentity) {
		t.Fatalf("signEndpointSet(wrong identity) error = %v, want %v", err, ErrEndpointSetIdentity)
	}
}

func TestEndpointSetUnknownFieldsAreVerifiedBeforeSchemaRejection(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 1)
	member := endpointMember(t, publicKey)
	value := validEndpointSet(member.ID)
	tests := []struct {
		name   string
		mutate func(*testing.T, map[string]json.RawMessage)
	}{
		{
			name: "top level",
			mutate: func(
				_ *testing.T,
				members map[string]json.RawMessage,
			) {
				members["future_capability"] = json.RawMessage(`{"value":1}`)
			},
		},
		{
			name: "endpoint",
			mutate: func(
				t *testing.T,
				members map[string]json.RawMessage,
			) {
				t.Helper()
				var endpoints []map[string]json.RawMessage
				if err := json.Unmarshal(members["endpoints"], &endpoints); err != nil {
					t.Fatalf("json.Unmarshal(endpoints) error = %v", err)
				}
				endpoints[0]["transport"] = json.RawMessage(`"tcp"`)
				encoded, err := json.Marshal(endpoints)
				if err != nil {
					t.Fatalf("json.Marshal(endpoints) error = %v", err)
				}
				members["endpoints"] = encoded
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			members := endpointMembers(t, value)
			test.mutate(t, members)
			encoded := signEndpointMembers(
				t,
				members,
				privateKey,
				codec.SignatureEndpointHints,
			)
			unverified, err := ParseEndpointSet(encoded)
			if err != nil {
				t.Fatalf("ParseEndpointSet() rejected unknown field early: %v", err)
			}
			if _, err := unverified.Verify(
				endpointExpectation(member),
			); !errors.Is(err, ErrUnknownField) {
				t.Fatalf("Verify() error = %v, want %v", err, ErrUnknownField)
			}

			tampered := replaceEndpointSignature(t, encoded, make([]byte, ed25519.SignatureSize))
			unverified, err = ParseEndpointSet(tampered)
			if err != nil {
				t.Fatalf("ParseEndpointSet(tampered) error = %v", err)
			}
			_, err = unverified.Verify(endpointExpectation(member))
			if !errors.Is(err, codecommcrypto.ErrSignatureVerification) {
				t.Fatalf("Verify(tampered) error = %v, want %v", err, codecommcrypto.ErrSignatureVerification)
			}
			if errors.Is(err, ErrUnknownField) {
				t.Fatal("bad signature reached closed-schema rejection")
			}
		})
	}
}

func TestEndpointSetSignatureLabelIsSeparated(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := endpointIdentityKey(t, 1)
	member := endpointMember(t, publicKey)
	value := validEndpointSet(member.ID)
	encoded := signEndpointWire(
		t,
		endpointSetToWire(value),
		privateKey,
		codec.SignatureDiscovery,
	)
	if _, err := ValidateEndpointSet(
		encoded,
		endpointExpectation(member),
	); !errors.Is(err, codecommcrypto.ErrSignatureVerification) {
		t.Fatalf("ValidateEndpointSet(wrong label) error = %v, want %v", err, codecommcrypto.ErrSignatureVerification)
	}
}

func TestNextEndpointSequence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		previous uint64
		now      time.Time
		want     uint64
		wantErr  error
	}{
		{
			name: "Unix milliseconds wins",
			now:  time.UnixMilli(1_786_123_456_789),
			want: 1_786_123_456_789,
		},
		{
			name:     "previous plus one wins",
			previous: 1_786_123_456_789,
			now:      time.UnixMilli(1),
			want:     1_786_123_456_790,
		},
		{
			name: "epoch starts at one",
			now:  time.Unix(0, 0),
			want: 1,
		},
		{
			name:     "pre-epoch clock",
			previous: 8,
			now:      time.Unix(-1, 0),
			want:     9,
		},
		{
			name:     "millisecond floor",
			previous: 1,
			now:      time.Unix(2, 999_999_999),
			want:     2_999,
		},
		{
			name:     "last sequence",
			previous: domain.MaxSafeInteger - 1,
			now:      time.Unix(0, 0),
			want:     domain.MaxSafeInteger,
		},
		{
			name:     "previous at maximum",
			previous: domain.MaxSafeInteger,
			now:      time.Unix(0, 0),
			wantErr:  ErrEndpointSequence,
		},
		{
			name:     "previous over maximum",
			previous: domain.MaxSafeInteger + 1,
			now:      time.Unix(0, 0),
			wantErr:  ErrEndpointSequence,
		},
		{
			name: "clock at maximum",
			now:  time.UnixMilli(domain.MaxSafeInteger),
			want: domain.MaxSafeInteger,
		},
		{
			name:    "clock over maximum",
			now:     time.UnixMilli(domain.MaxSafeInteger + 1),
			wantErr: ErrEndpointSequence,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := NextEndpointSequence(test.previous, test.now)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("NextEndpointSequence() error = %v, want %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("NextEndpointSequence() = %d, want %d", got, test.want)
			}
		})
	}
}

func validEndpointSet(deviceID domain.DeviceID) EndpointSet {
	return EndpointSet{
		SessionID:          endpointTestSessionID,
		WorkspaceID:        endpointTestWorkspaceID,
		RecoveryGeneration: 0,
		DeviceID:           deviceID,
		EndpointSequence:   1_786_123_456_789,
		IssuedAt:           "2026-08-13T12:00:00Z",
		ExpiresAt:          "2026-08-13T12:02:40Z",
		Endpoints: []Endpoint{
			{IP: netip.MustParseAddr("192.0.2.4"), Port: 47831},
			{IP: netip.MustParseAddr("2001:db8::1"), Port: 443},
		},
	}
}

func endpointExpectation(member device.Device) EndpointSetExpectation {
	return EndpointSetExpectation{
		SessionID:             endpointTestSessionID,
		WorkspaceID:           endpointTestWorkspaceID,
		RecoveryGeneration:    0,
		Member:                member,
		AdvertisementInterval: endpointTestInterval,
		Now:                   endpointTestNow,
	}
}

func endpointCount(count int) []Endpoint {
	endpoints := make([]Endpoint, count)
	for index := range endpoints {
		endpoints[index] = Endpoint{
			IP:   netip.MustParseAddr("192.0.2.4"),
			Port: uint16(index + 1),
		}
	}
	return endpoints
}

func endpointIdentityKey(
	t *testing.T,
	fill byte,
) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{fill}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return bytes.Clone(publicKey), bytes.Clone(privateKey)
}

func endpointMember(
	t *testing.T,
	publicKey ed25519.PublicKey,
) device.Device {
	t.Helper()
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("device.DeriveID() error = %v", err)
	}
	return device.Device{
		ID:                deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: bytes.Clone(publicKey),
		DaemonVersion:     "1.0.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
}

func endpointMemberFromPrivate(
	t *testing.T,
	privateKey ed25519.PrivateKey,
) device.Device {
	t.Helper()
	return endpointMember(t, privateKey.Public().(ed25519.PublicKey))
}

func endpointMembers(
	t *testing.T,
	value EndpointSet,
) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(endpointSetToWire(value))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	delete(members, "signature")
	return members
}

func signEndpointMembers(
	t *testing.T,
	members map[string]json.RawMessage,
	privateKey ed25519.PrivateKey,
	label codec.SignatureLabel,
) []byte {
	t.Helper()
	delete(members, "signature")
	rawUnsigned, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal(unsigned) error = %v", err)
	}
	unsigned := mustCanonicalEndpointObject(t, rawUnsigned)
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		label,
		unsigned,
	)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	members["signature"], err = json.Marshal(codec.EncodeBase64URL(signature))
	if err != nil {
		t.Fatalf("json.Marshal(signature) error = %v", err)
	}
	rawComplete, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal(complete) error = %v", err)
	}
	return mustCanonicalEndpointObject(t, rawComplete)
}

func signEndpointWire(
	t *testing.T,
	wire endpointSetWire,
	privateKey ed25519.PrivateKey,
	label codec.SignatureLabel,
) []byte {
	t.Helper()
	wire.Signature = ""
	rawUnsigned, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal(unsigned wire) error = %v", err)
	}
	unsigned := mustCanonicalEndpointObject(t, rawUnsigned)
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		label,
		unsigned,
	)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	wire.Signature = codec.EncodeBase64URL(signature)
	rawComplete, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal(complete wire) error = %v", err)
	}
	return mustCanonicalEndpointObject(t, rawComplete)
}

func replaceEndpointSignature(
	t *testing.T,
	encoded []byte,
	signature []byte,
) []byte {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	var err error
	members["signature"], err = json.Marshal(codec.EncodeBase64URL(signature))
	if err != nil {
		t.Fatalf("json.Marshal(signature) error = %v", err)
	}
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return mustCanonicalEndpointObject(t, raw)
}

func mustCanonicalEndpointObject(t *testing.T, input []byte) []byte {
	t.Helper()
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject() error = %v", err)
	}
	return canonical
}
