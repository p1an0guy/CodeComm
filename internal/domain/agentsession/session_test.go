package agentsession

import (
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	validSessionID     = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abc")
	validWorkingRootID = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abd")
	validDeviceID      = domain.DeviceID("cc10000000000000000000000000000000000000000000000000000000000000000")
)

func TestSessionValidateAcceptsDocumentedValues(t *testing.T) {
	t.Parallel()

	for _, clientKind := range ClientKinds() {
		clientKind := clientKind
		t.Run("client_"+string(clientKind), func(t *testing.T) {
			t.Parallel()
			session := validSession()
			session.ClientKind = clientKind
			if err := session.Validate(); err != nil {
				t.Fatalf("Session.Validate() error = %v", err)
			}
		})
	}

	for _, state := range ConnectedStates() {
		state := state
		t.Run("connected_"+string(state), func(t *testing.T) {
			t.Parallel()
			session := validSession()
			session.State = state
			if err := session.Validate(); err != nil {
				t.Fatalf("Session.Validate() error = %v", err)
			}
		})

		t.Run("disconnected_from_"+string(state), func(t *testing.T) {
			t.Parallel()
			session := validSession()
			session.State = StateDisconnected
			session.ResumeState = state
			if err := session.Validate(); err != nil {
				t.Fatalf("Session.Validate() error = %v", err)
			}
		})
	}

	for _, reason := range EndReasons() {
		reason := reason
		t.Run("ended_"+string(reason), func(t *testing.T) {
			t.Parallel()
			session := validSession()
			session.State = StateEnded
			session.EndReason = reason
			if err := session.Validate(); err != nil {
				t.Fatalf("Session.Validate() error = %v", err)
			}
		})
	}
}

func TestSessionValidateEnforcesProfileByteBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		profile *string
		want    error
	}{
		{name: "unset", profile: nil},
		{name: "one byte", profile: stringPointer("x")},
		{name: "maximum bytes", profile: stringPointer(strings.Repeat("x", MaxAgentProfileIDBytes))},
		{name: "multibyte maximum", profile: stringPointer(strings.Repeat("é", MaxAgentProfileIDBytes/2))},
		{name: "set empty", profile: stringPointer(""), want: ErrInvalidAgentProfileID},
		{name: "one byte over", profile: stringPointer(strings.Repeat("x", MaxAgentProfileIDBytes+1)), want: ErrInvalidAgentProfileID},
		{name: "multibyte over", profile: stringPointer(strings.Repeat("é", MaxAgentProfileIDBytes/2+1)), want: ErrInvalidAgentProfileID},
		{name: "invalid UTF-8", profile: stringPointer(string([]byte{0xff})), want: ErrInvalidAgentProfileID},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			session := validSession()
			session.AgentProfileID = test.profile
			err := session.Validate()
			if !errors.Is(err, test.want) {
				t.Fatalf("Session.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSessionValidateRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Session)
		want   error
	}{
		{
			name: "session ID",
			mutate: func(session *Session) {
				session.ID = domain.UUIDv7("not-a-uuid")
			},
			want: ErrInvalidID,
		},
		{
			name: "device ID",
			mutate: func(session *Session) {
				session.DeviceID = domain.DeviceID("not-a-device")
			},
			want: ErrInvalidDeviceID,
		},
		{
			name: "client kind",
			mutate: func(session *Session) {
				session.ClientKind = ClientKind("unknown")
			},
			want: ErrInvalidClientKind,
		},
		{
			name: "state",
			mutate: func(session *Session) {
				session.State = State("unknown")
			},
			want: ErrInvalidState,
		},
		{
			name: "absent state",
			mutate: func(session *Session) {
				session.State = StateAbsent
			},
			want: ErrInvalidState,
		},
		{
			name: "working root ID",
			mutate: func(session *Session) {
				session.WorkingRootID = domain.UUIDv7("not-a-uuid")
			},
			want: ErrInvalidWorkingRootID,
		},
		{
			name: "entity version",
			mutate: func(session *Session) {
				session.EntityVersion = 0
			},
			want: ErrInvalidEntityVersion,
		},
		{
			name: "entity version over signed JSON limit",
			mutate: func(session *Session) {
				session.EntityVersion = domain.MaxSafeInteger + 1
			},
			want: ErrInvalidEntityVersion,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			session := validSession()
			test.mutate(&session)
			if err := session.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Session.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSessionValidateAcceptsEntityVersionBounds(t *testing.T) {
	t.Parallel()

	for _, version := range []uint64{1, domain.MaxSafeInteger} {
		session := validSession()
		session.EntityVersion = version
		if err := session.Validate(); err != nil {
			t.Errorf("Session.Validate() at entity version %d error = %v", version, err)
		}
	}
}

func TestSessionValidateEnforcesResumeStateConsistency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		state  State
		resume State
	}{
		{name: "connected carries resume", state: StateWorking, resume: StateIdle},
		{name: "ended carries resume", state: StateEnded, resume: StateBlocked},
		{name: "disconnected missing resume", state: StateDisconnected, resume: StateAbsent},
		{name: "disconnected resumes disconnected", state: StateDisconnected, resume: StateDisconnected},
		{name: "disconnected resumes ended", state: StateDisconnected, resume: StateEnded},
		{name: "disconnected resumes unknown", state: StateDisconnected, resume: State("unknown")},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			session := validSession()
			session.State = test.state
			session.ResumeState = test.resume
			if test.state == StateEnded {
				session.EndReason = EndReasonClean
			}
			if err := session.Validate(); !errors.Is(err, ErrInvalidResumeState) {
				t.Fatalf("Session.Validate() error = %v, want %v", err, ErrInvalidResumeState)
			}
		})
	}
}

func TestSessionValidateEnforcesEndReasonConsistency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		state  State
		reason EndReason
	}{
		{name: "connected carries reason", state: StateWorking, reason: EndReasonClean},
		{name: "disconnected carries reason", state: StateDisconnected, reason: EndReasonCrashReap},
		{name: "ended missing reason", state: StateEnded, reason: EndReasonAbsent},
		{name: "ended unknown reason", state: StateEnded, reason: EndReason("unknown")},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			session := validSession()
			session.State = test.state
			session.EndReason = test.reason
			if test.state == StateDisconnected {
				session.ResumeState = StateWorking
			}
			if err := session.Validate(); !errors.Is(err, ErrInvalidEndReason) {
				t.Fatalf("Session.Validate() error = %v, want %v", err, ErrInvalidEndReason)
			}
		})
	}
}

func TestClosedEnumsRejectUnknownAndZeroValues(t *testing.T) {
	t.Parallel()

	if ClientKind("").Valid() || ClientKind("unknown").Valid() {
		t.Error("ClientKind.Valid accepted a value outside the closed enum")
	}
	if StateAbsent.Valid() || State("unknown").Valid() {
		t.Error("State.Valid accepted a value outside the committed-state enum")
	}
	if EndReasonAbsent.Valid() || EndReason("unknown").Valid() {
		t.Error("EndReason.Valid accepted a value outside the closed enum")
	}
	if Operation("").Valid() || Operation("unknown").Valid() {
		t.Error("Operation.Valid accepted a value outside the closed enum")
	}
}

func TestEnumListsReturnDefensiveCopies(t *testing.T) {
	t.Parallel()

	clientKinds := ClientKinds()
	clientKinds[0] = ClientKind("corrupt")
	if got := ClientKinds()[0]; got != ClientKindCodex {
		t.Fatalf("ClientKinds()[0] = %q after caller mutation, want %q", got, ClientKindCodex)
	}

	states := States()
	states[0] = State("corrupt")
	if got := States()[0]; got != StateStarting {
		t.Fatalf("States()[0] = %q after caller mutation, want %q", got, StateStarting)
	}

	connected := ConnectedStates()
	connected[0] = State("corrupt")
	if got := ConnectedStates()[0]; got != StateStarting {
		t.Fatalf("ConnectedStates()[0] = %q after caller mutation, want %q", got, StateStarting)
	}

	reasons := EndReasons()
	reasons[0] = EndReason("corrupt")
	if got := EndReasons()[0]; got != EndReasonClean {
		t.Fatalf("EndReasons()[0] = %q after caller mutation, want %q", got, EndReasonClean)
	}

	operations := Operations()
	operations[0] = Operation("corrupt")
	if got := Operations()[0]; got != OperationCreate {
		t.Fatalf("Operations()[0] = %q after caller mutation, want %q", got, OperationCreate)
	}
}

func validSession() Session {
	return Session{
		ID:            validSessionID,
		DeviceID:      validDeviceID,
		ClientKind:    ClientKindCodex,
		State:         StateStarting,
		WorkingRootID: validWorkingRootID,
		EntityVersion: 1,
	}
}

func stringPointer(value string) *string {
	return &value
}
