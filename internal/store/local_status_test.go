package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

func TestStatusSnapshotReturnsOneBoundedTransactionalView(t *testing.T) {
	value, member, live, tasks := openStatusSnapshotTestStore(t)

	snapshot, err := value.LocalState().StatusSnapshot(
		context.Background(),
		member.ID,
		1,
	)
	if err != nil {
		t.Fatalf("StatusSnapshot(): %v", err)
	}
	if snapshot.SessionID != domain.UUIDv7(testSessionID) ||
		snapshot.WorkspaceID != testWorkspaceID ||
		snapshot.RecoveryGeneration != 0 ||
		snapshot.Member.ID != member.ID ||
		snapshot.MemberTotal != 1 ||
		len(snapshot.Members) != 1 ||
		snapshot.Members[0].ID != member.ID ||
		snapshot.Members[0].EntityVersion != member.EntityVersion ||
		snapshot.Heads.DigestVersion != 1 ||
		snapshot.Heads.ProjectionSchemaVersion != 1 ||
		snapshot.TaskTotal != uint64(len(tasks)) ||
		!snapshot.TasksTruncated {
		t.Fatalf("StatusSnapshot() = %#v", snapshot)
	}
	if !reflect.DeepEqual(snapshot.VoterSet.VoterDeviceIDs(), []domain.DeviceID{
		member.ID,
	}) {
		t.Fatalf("voter target = %#v", snapshot.VoterSet.VoterDeviceIDs())
	}
	if !reflect.DeepEqual(
		snapshot.CredentialAuthority.VoterDeviceIDs(),
		[]domain.DeviceID{member.ID},
	) {
		t.Fatalf(
			"credential authority = %#v",
			snapshot.CredentialAuthority.VoterDeviceIDs(),
		)
	}
	assertLocalQueryValues(t, snapshot.AgentSessions, []agentsession.Session{live})
	assertLocalQueryValues(t, snapshot.Tasks, tasks[:1])
}

func TestStatusSnapshotRejectsInvalidInputAndCorruptRows(t *testing.T) {
	value, member, _, _ := openStatusSnapshotTestStore(t)
	state := value.LocalState()
	for _, test := range []struct {
		name     string
		ctx      context.Context
		deviceID domain.DeviceID
		limit    int
	}{
		{
			name:     "nil context",
			deviceID: member.ID,
			limit:    1,
		},
		{
			name:     "invalid device",
			ctx:      context.Background(),
			deviceID: "invalid",
			limit:    1,
		},
		{
			name:     "zero limit",
			ctx:      context.Background(),
			deviceID: member.ID,
		},
		{
			name:     "excess limit",
			ctx:      context.Background(),
			deviceID: member.ID,
			limit:    MaxLocalTaskQuery + 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := state.StatusSnapshot(
				test.ctx,
				test.deviceID,
				test.limit,
			); !errors.Is(err, ErrInvalidLocalState) {
				t.Fatalf(
					"StatusSnapshot() error = %v, want %v",
					err,
					ErrInvalidLocalState,
				)
			}
		})
	}

	if _, err := state.StatusSnapshot(
		context.Background(),
		localQueryDeviceID,
		1,
	); !errors.Is(err, ErrLocalStateIntegrity) {
		t.Fatalf(
			"StatusSnapshot(missing member) error = %v, want %v",
			err,
			ErrLocalStateIntegrity,
		)
	}

	updateLocalQueryRow(
		t,
		state,
		"UPDATE voter_set SET voter_device_ids_json = '[ ]';",
	)
	if _, err := state.StatusSnapshot(
		context.Background(),
		member.ID,
		1,
	); !errors.Is(err, ErrLocalStateIntegrity) {
		t.Fatalf(
			"StatusSnapshot(corrupt voter target) error = %v, want %v",
			err,
			ErrLocalStateIntegrity,
		)
	}
}

func openStatusSnapshotTestStore(
	t *testing.T,
) (*Store, device.Device, agentsession.Session, []task.Task) {
	t.Helper()
	member := projectionDevices(t, 1)[0]
	member.Role = device.RoleOwner
	voterSet, err := voterset.New(
		domain.UUIDv7(testSessionID),
		[]domain.DeviceID{member.ID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	live := newLocalQueryAgentSession(0)
	live.DeviceID = member.ID
	ended := newLocalQueryAgentSession(1)
	ended.DeviceID = member.ID
	ended.State = agentsession.StateEnded
	ended.ResumeState = agentsession.StateAbsent
	ended.EndReason = agentsession.EndReasonClean
	tasks := []task.Task{
		newLocalQueryTask(1, task.PriorityHighest, "first"),
		newLocalQueryTask(2, task.PriorityNormal, "second"),
	}
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	if _, err := value.Initialize(
		context.Background(),
		commitmentInitialState(
			t,
			domain.UUIDv7(testSessionID),
			0,
			ProjectionWrites{
				Devices:  []device.Device{member},
				VoterSet: []voterset.Set{voterSet},
				CredentialAuthority: []CredentialAuthorityRow{{
					SessionID:        domain.UUIDv7(testSessionID),
					VoterDeviceIDs:   []domain.DeviceID{member.ID},
					VoterSetVersion:  1,
					ActivationSource: credentialauthority.ActivationGenesis,
				}},
				AgentSessions: []agentsession.Session{ended, live},
				Tasks:         tasks,
			},
		),
	); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	return value, member, live, tasks
}
