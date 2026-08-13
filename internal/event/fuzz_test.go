package event

import (
	"testing"
)

func FuzzDecodeLocalCommand(f *testing.F) {
	f.Add([]byte(`{
		"kind":"task.created",
		"entity_id":"01890f47-3e72-7000-8000-000000000006",
		"rationale_summary":"",
		"actions":[],
		"payload":{},
		"redaction":{"policy":"default","fields_removed":[]}
	}`))
	f.Add([]byte(`{"origin":{"actor_type":"human"}}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeLocalCommand(input)
	})
}

func FuzzParseAndVerify(f *testing.F) {
	deviceID, publicKey, privateKey := testIdentity(f)
	binding := mustMCPBinding(f, deviceID, testAgentSessionID, nil)
	proposal, err := BuildProposal(validCommand(KindTaskCreated), binding, validBuildContext())
	if err != nil {
		f.Fatalf("BuildProposal() error = %v", err)
	}
	signed, err := Sign(proposal, privateKey)
	if err != nil {
		f.Fatalf("Sign() error = %v", err)
	}
	f.Add(signed.CanonicalBytes())
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))

	context := verificationContext(publicKey)
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseAndVerify(input, context)
	})
}
