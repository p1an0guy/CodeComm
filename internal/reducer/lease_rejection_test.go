package reducer

import (
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestLeasePayloadContractsRejectInvalidInputs(t *testing.T) {
	t.Parallel()

	tooManyPatterns := make([]string, lease.MaxPathPatterns+1)
	for index := range tooManyPatterns {
		tooManyPatterns[index] = "src"
	}
	tests := []struct {
		name    string
		kind    event.Kind
		payload string
		want    Code
		prepare func(*reducerFixture)
	}{
		{
			name:    "acquire unknown field takes precedence",
			kind:    event.KindLeaseAcquired,
			payload: `{"path_globs":null,"task_id":null,"unknown":true}`,
			want:    CodeUnknownPayloadField,
		},
		{
			name:    "acquire missing scope",
			kind:    event.KindLeaseAcquired,
			payload: `{"ttl_seconds":900}`,
			want:    CodeMissingPayloadField,
		},
		{
			name:    "acquire missing TTL",
			kind:    event.KindLeaseAcquired,
			payload: `{"path_globs":["src"],"scope":"path"}`,
			want:    CodeMissingPayloadField,
		},
		{
			name:    "acquire null optional",
			kind:    event.KindLeaseAcquired,
			payload: `{"path_globs":null,"scope":"path","ttl_seconds":900}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "acquire unknown scope",
			kind:    event.KindLeaseAcquired,
			payload: `{"scope":"repository","ttl_seconds":900}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "task scope missing task",
			kind:    event.KindLeaseAcquired,
			payload: `{"scope":"task","ttl_seconds":900}`,
			want:    CodeMissingPayloadField,
		},
		{
			name: "task scope prohibits paths",
			kind: event.KindLeaseAcquired,
			payload: `{"path_globs":["src"],"scope":"task","task_id":"` +
				string(testTaskID) + `","ttl_seconds":900}`,
			want: CodeInvalidPayload,
		},
		{
			name:    "path scope missing paths",
			kind:    event.KindLeaseAcquired,
			payload: `{"scope":"path","ttl_seconds":900}`,
			want:    CodeMissingPayloadField,
		},
		{
			name:    "path scope empty paths",
			kind:    event.KindLeaseAcquired,
			payload: `{"path_globs":[],"scope":"path","ttl_seconds":900}`,
			want:    CodeInvalidPayload,
		},
		{
			name: "path scope too many raw duplicate paths",
			kind: event.KindLeaseAcquired,
			payload: `{"path_globs":["` +
				strings.Join(tooManyPatterns, `","`) +
				`"],"scope":"path","ttl_seconds":900}`,
			want: CodeInvalidPayload,
		},
		{
			name:    "path scope malformed glob",
			kind:    event.KindLeaseAcquired,
			payload: `{"path_globs":["src/*.go"],"scope":"path","ttl_seconds":900}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "malformed optional task association",
			kind:    event.KindLeaseAcquired,
			payload: `{"path_globs":["src"],"scope":"path","task_id":"bad","ttl_seconds":900}`,
			want:    CodeInvalidPayload,
		},
		{
			name: "missing optional task association target",
			kind: event.KindLeaseAcquired,
			payload: `{"path_globs":["src"],"scope":"path","task_id":"` +
				string(testOtherTaskID) + `","ttl_seconds":900}`,
			want: CodeLeaseTaskNotFound,
		},
		{
			name: "task scope requires actor ownership",
			kind: event.KindLeaseAcquired,
			payload: `{"scope":"task","task_id":"` +
				string(testTaskID) + `","ttl_seconds":900}`,
			want: CodeTaskHolderRequired,
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
			},
		},
		{
			name:    "acquire below committed TTL",
			kind:    event.KindLeaseAcquired,
			payload: `{"path_globs":["src"],"scope":"path","ttl_seconds":29}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "acquire above committed TTL",
			kind:    event.KindLeaseAcquired,
			payload: `{"path_globs":["src"],"scope":"path","ttl_seconds":3601}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "renew unknown field",
			kind:    event.KindLeaseRenewed,
			payload: `{"scope":"path","ttl_seconds":900}`,
			want:    CodeUnknownPayloadField,
		},
		{
			name:    "renew missing TTL",
			kind:    event.KindLeaseRenewed,
			payload: `{}`,
			want:    CodeMissingPayloadField,
		},
		{
			name:    "renew null TTL",
			kind:    event.KindLeaseRenewed,
			payload: `{"ttl_seconds":null}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "renew above committed TTL",
			kind:    event.KindLeaseRenewed,
			payload: `{"ttl_seconds":3601}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "release unknown field",
			kind:    event.KindLeaseReleased,
			payload: `{"note":"no","release_reason":"voluntary"}`,
			want:    CodeUnknownPayloadField,
		},
		{
			name:    "release missing reason",
			kind:    event.KindLeaseReleased,
			payload: `{}`,
			want:    CodeMissingPayloadField,
		},
		{
			name:    "release null reason",
			kind:    event.KindLeaseReleased,
			payload: `{"release_reason":null}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "release session ended is cascade only",
			kind:    event.KindLeaseReleased,
			payload: `{"release_reason":"session_ended"}`,
			want:    CodeInvalidReleaseReason,
		},
		{
			name:    "release recovery is transform only",
			kind:    event.KindLeaseReleased,
			payload: `{"release_reason":"recovery"}`,
			want:    CodeInvalidReleaseReason,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			version := uint64(0)
			if test.kind != event.KindLeaseAcquired {
				version = 4
				addReducerLease(
					&fixture.state,
					mustReducerLease(
						t,
						testLeaseID,
						fixture.editorDevice,
						testAgentSessionID,
						lease.ScopePath,
						"",
						version,
						"src/**",
					),
				)
			}
			if test.prepare != nil {
				test.prepare(&fixture)
			}
			proposal := buildLeaseProposal(
				t,
				fixture,
				event.ActorAgent,
				test.kind,
				testLeaseID,
				version,
				test.payload,
			)
			assertRejectedCode(t, fixture.state, proposal, test.want)
		})
	}
}

func TestLeaseEntityCASAndLifecycleRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kind    event.Kind
		version uint64
		prepare func(*testing.T, *reducerFixture)
		want    Code
	}{
		{
			name: "acquisition collision",
			kind: event.KindLeaseAcquired,
			prepare: func(t *testing.T, fixture *reducerFixture) {
				addReducerLease(
					&fixture.state,
					mustReducerLease(
						t,
						testLeaseID,
						fixture.editorDevice,
						testAgentSessionID,
						lease.ScopePath,
						"",
						1,
						"other/**",
					),
				)
			},
			want: CodeEntityAlreadyExists,
		},
		{
			name:    "renew missing lease",
			kind:    event.KindLeaseRenewed,
			version: 1,
			want:    CodeEntityNotFound,
		},
		{
			name:    "release stale version",
			kind:    event.KindLeaseReleased,
			version: 3,
			prepare: addCurrentTestLease,
			want:    CodeEntityVersionMismatch,
		},
		{
			name:    "renew exhausted version",
			kind:    event.KindLeaseRenewed,
			version: domain.MaxSafeInteger,
			prepare: func(t *testing.T, fixture *reducerFixture) {
				value := mustReducerLease(
					t,
					testLeaseID,
					fixture.editorDevice,
					testAgentSessionID,
					lease.ScopePath,
					"",
					domain.MaxSafeInteger,
					"src/**",
				)
				addReducerLease(&fixture.state, value)
			},
			want: CodeEntityVersionExhausted,
		},
		{
			name:    "released lease is terminal",
			kind:    event.KindLeaseRenewed,
			version: 5,
			prepare: func(t *testing.T, fixture *reducerFixture) {
				value := mustReducerLease(
					t,
					testLeaseID,
					fixture.editorDevice,
					testAgentSessionID,
					lease.ScopePath,
					"",
					4,
					"src/**",
				)
				value.Status = lease.StatusReleased
				value.ReleaseReason = lease.ReleaseVoluntary
				value.EntityVersion = 5
				fixture.state.leases[value.ID] = value
			},
			want: CodeInvalidLeaseTransition,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			if test.prepare != nil {
				test.prepare(t, &fixture)
			}
			payload := `{"ttl_seconds":900}`
			if test.kind == event.KindLeaseAcquired {
				payload = `{"path_globs":["src"],"scope":"path","ttl_seconds":900}`
			}
			if test.kind == event.KindLeaseReleased {
				payload = `{"release_reason":"voluntary"}`
			}
			proposal := buildLeaseProposal(
				t,
				fixture,
				event.ActorAgent,
				test.kind,
				testLeaseID,
				test.version,
				payload,
			)
			assertRejectedCode(t, fixture.state, proposal, test.want)
		})
	}
}

func TestLeaseAcquisitionFailurePrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		payload   string
		collision bool
		want      Code
	}{
		{
			name: "collision precedes TTL and task reference",
			payload: `{"path_globs":["src/**"],"scope":"path","task_id":"` +
				string(testOtherTaskID) + `","ttl_seconds":29}`,
			collision: true,
			want:      CodeEntityAlreadyExists,
		},
		{
			name: "TTL precedes task reference",
			payload: `{"path_globs":["src/**"],"scope":"path","task_id":"` +
				string(testOtherTaskID) + `","ttl_seconds":29}`,
			want: CodeInvalidPayload,
		},
		{
			name: "task reference precedes path grammar",
			payload: `{"path_globs":["src/*.go"],"scope":"path","task_id":"` +
				string(testOtherTaskID) + `","ttl_seconds":900}`,
			want: CodeLeaseTaskNotFound,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			if test.collision {
				addReducerLease(
					&fixture.state,
					mustReducerLease(
						t,
						testLeaseID,
						fixture.editorDevice,
						testAgentSessionID,
						lease.ScopePath,
						"",
						1,
						"other/**",
					),
				)
			}
			proposal := buildLeaseProposal(
				t,
				fixture,
				event.ActorAgent,
				event.KindLeaseAcquired,
				testLeaseID,
				0,
				test.payload,
			)
			assertRejectedCode(t, fixture.state, proposal, test.want)
		})
	}
}

func addCurrentTestLease(t *testing.T, fixture *reducerFixture) {
	t.Helper()
	addReducerLease(
		&fixture.state,
		mustReducerLease(
			t,
			testLeaseID,
			fixture.editorDevice,
			testAgentSessionID,
			lease.ScopePath,
			"",
			4,
			"src/**",
		),
	)
}
