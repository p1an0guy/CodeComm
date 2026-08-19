package localcommand

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/event"
)

const validRequest = `{
	"operation":"cluster.set-voters",
	"request_id":"018f47de-89ab-7def-8123-0123456789ab",
	"command":{
		"kind":"membership.voter_set_changed",
		"entity_id":"018f47de-89ab-7def-8123-1123456789ab",
		"expected_entity_version":1,
		"rationale_summary":"",
		"actions":[],
		"payload":{"voter_set":["cc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},
		"redaction":{"policy":"default","fields_removed":[]}
	}
}`

func TestDecodeCanonicalizesStrictAuthorityFreeRequest(t *testing.T) {
	request, err := Decode([]byte(validRequest))
	if err != nil {
		t.Fatalf("Decode(): %v", err)
	}
	if request.Operation != "cluster.set-voters" ||
		request.Command.Kind != event.KindMembershipVoterSetChanged ||
		request.Command.ExpectedEntityVersion == nil ||
		*request.Command.ExpectedEntityVersion != 1 ||
		bytes.Contains(request.Canonical, []byte{'\n'}) {
		t.Fatalf("request = %#v; canonical = %s", request, request.Canonical)
	}
	redecoded, err := DecodeReader(bytes.NewReader(request.Canonical))
	if err != nil {
		t.Fatalf("DecodeReader(): %v", err)
	}
	if !bytes.Equal(redecoded.Canonical, request.Canonical) {
		t.Fatal("canonical request changed on exact replay")
	}
}

func TestDecodeRejectsOuterSchemaAndCommandAuthority(t *testing.T) {
	tests := [][]byte{
		[]byte(`{"command":{},"operation":"cluster.set-voters","request_id":"018f47de-89ab-7def-8123-0123456789ab","extra":true}`),
		[]byte(`{"command":{},"operation":"cluster.set-voters","request_id":null}`),
		bytes.Replace(
			[]byte(validRequest),
			[]byte(`"kind":"membership.voter_set_changed"`),
			[]byte(`"origin":null,"kind":"membership.voter_set_changed"`),
			1,
		),
	}
	for _, input := range tests {
		if _, err := Decode(input); err == nil {
			t.Fatalf("Decode(%s) succeeded", input)
		}
	}
	if _, err := Decode(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Decode(nil) error = %v", err)
	}
}
