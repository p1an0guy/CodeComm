package pairing

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestPairingConfirmationMessagesRoundTrip(t *testing.T) {
	t.Parallel()

	verified := verifiedRequestFixture(t)
	acknowledgment, err := NewRequestAcknowledgment(verified)
	if err != nil {
		t.Fatalf("NewRequestAcknowledgment() error = %v", err)
	}
	parsedAcknowledgment, err := ParseRequestAcknowledgment(acknowledgment.CanonicalBytes())
	if err != nil {
		t.Fatalf("ParseRequestAcknowledgment() error = %v", err)
	}
	if parsedAcknowledgment.AttemptID != acknowledgment.AttemptID ||
		parsedAcknowledgment.RequestDigest != acknowledgment.RequestDigest ||
		parsedAcknowledgment.InviteDigest != acknowledgment.InviteDigest ||
		parsedAcknowledgment.Status != StatusAwaitingSAS {
		t.Fatalf("parsed acknowledgment = %+v, want %+v", parsedAcknowledgment, acknowledgment)
	}

	for _, confirmed := range []bool{false, true} {
		message, err := NewConfirmation(
			acknowledgment.AttemptID, acknowledgment.RequestDigest, confirmed,
		)
		if err != nil {
			t.Fatalf("NewConfirmation(%t) error = %v", confirmed, err)
		}
		parsed, err := ParseConfirmation(message.CanonicalBytes())
		if err != nil || parsed.AttemptID != message.AttemptID ||
			parsed.RequestDigest != message.RequestDigest || parsed.Confirmed != confirmed {
			t.Errorf("ParseConfirmation(%t) = (%+v, %v)", confirmed, parsed, err)
		}
	}

	for _, status := range []ConfirmationStatus{
		StatusAwaitingInviter, StatusFinalizing, StatusConfirmed,
		StatusDeclined, StatusExpired, StatusRevoked,
	} {
		message, err := NewConfirmationResult(
			acknowledgment.AttemptID, acknowledgment.RequestDigest, status,
		)
		if err != nil {
			t.Fatalf("NewConfirmationResult(%q) error = %v", status, err)
		}
		parsed, err := ParseConfirmationResult(message.CanonicalBytes())
		if err != nil || parsed.AttemptID != message.AttemptID ||
			parsed.RequestDigest != message.RequestDigest || parsed.Status != status {
			t.Errorf("ParseConfirmationResult(%q) = (%+v, %v)", status, parsed, err)
		}
	}

	mutated := acknowledgment.CanonicalBytes()
	mutated[0] ^= 1
	if bytes.Equal(mutated, acknowledgment.CanonicalBytes()) {
		t.Fatal("acknowledgment exposes mutable canonical storage")
	}
}

func TestPairingConfirmationGoldenVectors(t *testing.T) {
	t.Parallel()

	verified := verifiedRequestFixture(t)
	acknowledgment, err := NewRequestAcknowledgment(verified)
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := NewConfirmation(
		acknowledgment.AttemptID, acknowledgment.RequestDigest, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewConfirmationResult(
		acknowledgment.AttemptID, acknowledgment.RequestDigest, StatusAwaitingInviter,
	)
	if err != nil {
		t.Fatal(err)
	}
	finalizing, err := NewConfirmationResult(
		acknowledgment.AttemptID, acknowledgment.RequestDigest, StatusFinalizing,
	)
	if err != nil {
		t.Fatal(err)
	}

	const wantAcknowledgment = `{"attempt_id":"01890f47-3e72-7000-8000-000000000301","invite_digest":"Iwa8gQWPBKn29AVAJobw4hj1cEha_KYzTWE0olL1g9g","request_digest":"_DtNWDSuuE_VMA03Bd3LN2j5D21XMFapwxknYbBBVjw","schema_version":1,"status":"awaiting_sas"}`
	const wantConfirmation = `{"attempt_id":"01890f47-3e72-7000-8000-000000000301","confirmed":true,"request_digest":"_DtNWDSuuE_VMA03Bd3LN2j5D21XMFapwxknYbBBVjw","schema_version":1}`
	const wantResult = `{"attempt_id":"01890f47-3e72-7000-8000-000000000301","request_digest":"_DtNWDSuuE_VMA03Bd3LN2j5D21XMFapwxknYbBBVjw","schema_version":1,"status":"awaiting_inviter"}`
	const wantFinalizing = `{"attempt_id":"01890f47-3e72-7000-8000-000000000301","request_digest":"_DtNWDSuuE_VMA03Bd3LN2j5D21XMFapwxknYbBBVjw","schema_version":1,"status":"finalizing"}`
	if string(acknowledgment.CanonicalBytes()) != wantAcknowledgment ||
		string(confirmation.CanonicalBytes()) != wantConfirmation ||
		string(result.CanonicalBytes()) != wantResult ||
		string(finalizing.CanonicalBytes()) != wantFinalizing {
		t.Fatalf(
			"golden messages: ack=%s confirmation=%s result=%s finalizing=%s",
			acknowledgment.CanonicalBytes(),
			confirmation.CanonicalBytes(),
			result.CanonicalBytes(),
			finalizing.CanonicalBytes(),
		)
	}
}

func TestPairingConfirmationMessagesRejectClosedSchemaViolations(t *testing.T) {
	t.Parallel()

	verified := verifiedRequestFixture(t)
	acknowledgment, err := NewRequestAcknowledgment(verified)
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := NewConfirmation(
		acknowledgment.AttemptID, acknowledgment.RequestDigest, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewConfirmationResult(
		acknowledgment.AttemptID, acknowledgment.RequestDigest, StatusConfirmed,
	)
	if err != nil {
		t.Fatal(err)
	}

	for name, test := range map[string]struct {
		input []byte
		parse func([]byte) error
	}{
		"acknowledgment": {acknowledgment.CanonicalBytes(), func(input []byte) error {
			_, err := ParseRequestAcknowledgment(input)
			return err
		}},
		"confirmation": {confirmation.CanonicalBytes(), func(input []byte) error {
			_, err := ParseConfirmation(input)
			return err
		}},
		"result": {result.CanonicalBytes(), func(input []byte) error {
			_, err := ParseConfirmationResult(input)
			return err
		}},
	} {
		t.Run(name, func(t *testing.T) {
			var members map[string]json.RawMessage
			if err := json.Unmarshal(test.input, &members); err != nil {
				t.Fatal(err)
			}
			members["future"] = json.RawMessage(`1`)
			if err := test.parse(canonicalObject(t, members)); !errors.Is(err, ErrPairingMessageUnknownField) {
				t.Errorf("unknown field error = %v, want %v", err, ErrPairingMessageUnknownField)
			}
			delete(members, "future")
			delete(members, "schema_version")
			if err := test.parse(canonicalObject(t, members)); !errors.Is(err, ErrInvalidPairingMessage) {
				t.Errorf("missing field error = %v, want %v", err, ErrInvalidPairingMessage)
			}
			if err := test.parse(append(bytes.Clone(test.input), 0x0a)); !errors.Is(err, ErrInvalidPairingMessage) {
				t.Errorf("noncanonical error = %v, want %v", err, ErrInvalidPairingMessage)
			}
		})
	}

	oversized := make([]byte, MaxPairingMessageBytes+1)
	if _, err := ParseConfirmation(oversized); !errors.Is(err, ErrPairingMessageTooLarge) {
		t.Fatalf("oversized confirmation error = %v, want %v", err, ErrPairingMessageTooLarge)
	}
	if _, err := NewConfirmationResult(
		acknowledgment.AttemptID, acknowledgment.RequestDigest, StatusAwaitingSAS,
	); !errors.Is(err, ErrInvalidPairingMessage) {
		t.Fatalf("invalid result status error = %v, want %v", err, ErrInvalidPairingMessage)
	}
}

func FuzzParsePairingConfirmationMessages(f *testing.F) {
	verified := verifiedRequestFixture(f)
	acknowledgment, err := NewRequestAcknowledgment(verified)
	if err != nil {
		f.Fatal(err)
	}
	confirmation, err := NewConfirmation(
		acknowledgment.AttemptID, acknowledgment.RequestDigest, true,
	)
	if err != nil {
		f.Fatal(err)
	}
	result, err := NewConfirmationResult(
		acknowledgment.AttemptID, acknowledgment.RequestDigest, StatusConfirmed,
	)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		acknowledgment.CanonicalBytes(), confirmation.CanonicalBytes(), result.CanonicalBytes(), {},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if value, err := ParseRequestAcknowledgment(input); err == nil &&
			!bytes.Equal(value.CanonicalBytes(), input) {
			t.Fatal("acknowledgment parse changed canonical bytes")
		}
		if value, err := ParseConfirmation(input); err == nil &&
			!bytes.Equal(value.CanonicalBytes(), input) {
			t.Fatal("confirmation parse changed canonical bytes")
		}
		if value, err := ParseConfirmationResult(input); err == nil &&
			!bytes.Equal(value.CanonicalBytes(), input) {
			t.Fatal("confirmation result parse changed canonical bytes")
		}
	})
}

func verifiedRequestFixture(t testing.TB) VerifiedRequest {
	t.Helper()
	invite, core, exporter := validRequestFixture(t)
	request, err := BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}
	verified, err := request.Verify(invite, exporter)
	if err != nil {
		t.Fatalf("Request.Verify() error = %v", err)
	}
	return verified
}
