package agent

import (
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
)

func canonicalObject(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return codec.CanonicalizeSignedObject(encoded)
}

func canonicalLaunchBindRequest(
	request ipc.BindRequest,
	selector []byte,
) ([]byte, error) {
	return canonicalObject(map[string]any{
		"client_instance_id": request.ClientInstanceID,
		"launch_selector":    codec.EncodeBase64URL(selector),
		"session_id":         request.SessionID,
		"workspace_id":       request.WorkspaceID,
	})
}

func defaultRedaction() event.Redaction {
	return event.Redaction{
		Policy:        event.RedactionDefault,
		FieldsRemoved: []event.RedactionField{},
	}
}
