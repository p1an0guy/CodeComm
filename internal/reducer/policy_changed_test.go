package reducer

import (
	"encoding/json"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestPolicyChangedReplacesCompletePolicyAndAppliesAtomically(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	for id, member := range fixture.state.devices {
		member.MaxApplyLevel = 2
		fixture.state.devices[id] = member
	}
	values := policy.Values{
		CheckpointEvents:             501,
		CheckpointIntervalSeconds:    301,
		LeaseMinTTLSeconds:           31,
		LeaseDefaultTTLSeconds:       901,
		LeaseMaxTTLSeconds:           3_601,
		AgentClaimLimit:              9,
		AgentLeaseLimit:              33,
		DeviceClaimLimit:             65,
		DeviceLeaseLimit:             258,
		AdvertisementIntervalSeconds: 21,
		AuditDepthPerDevicePerEpoch:  259,
		MaxMemberDevices:             7,
		MaxActiveAgentSessions:       30,
		ClusterMinApplyLevel:         2,
	}
	proposal := buildPolicyProposal(
		t,
		fixture,
		fixture.ownerDevice,
		testSessionID,
		1,
		policyPayload(t, values),
	)

	outcome := assertAccepted(t, fixture.state, proposal)
	if len(outcome.Changes.SessionPolicy) != 1 ||
		len(outcome.Changes.Tasks) != 0 ||
		len(outcome.Changes.Leases) != 0 ||
		len(outcome.Changes.AgentSessions) != 0 {
		t.Fatalf("policy changes = %#v", outcome.Changes)
	}
	got := outcome.Changes.SessionPolicy[0]
	if got.SessionID != testSessionID ||
		got.EntityVersion != 2 ||
		got.Values != values {
		t.Fatalf("policy = %#v, want values %#v", got, values)
	}
	if outcome.Audit == nil ||
		outcome.Audit.Class != AuditOperatorOverride ||
		outcome.Audit.Subject != "session_policy:"+string(testSessionID) {
		t.Fatalf("policy audit = %#v", outcome.Audit)
	}

	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if fixture.state.sessionPolicy != got {
		t.Fatalf("stored policy = %#v, want %#v", fixture.state.sessionPolicy, got)
	}
	key := OriginScopeKey{
		DeviceID: fixture.ownerDevice,
		Kind:     ScopeBoot,
		ScopeID:  testBootID,
	}
	if fixture.state.originScopes[key].LastSequence != 2 {
		t.Fatalf("stored origin scope = %#v", fixture.state.originScopes[key])
	}
}

func TestPolicyChangedRejectsMalformedOrNonAllowlistedPayloads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   Code
	}{
		{
			name: "missing key",
			mutate: func(object map[string]any) {
				delete(object, "checkpoint_events")
			},
			want: CodeMissingPayloadField,
		},
		{
			name: "immutable key",
			mutate: func(object map[string]any) {
				object["credential_epoch_seconds"] = 1_800
			},
			want: CodeUnknownPayloadField,
		},
		{
			name: "null value",
			mutate: func(object map[string]any) {
				object["checkpoint_events"] = nil
			},
			want: CodeInvalidPayload,
		},
		{
			name: "string value",
			mutate: func(object map[string]any) {
				object["checkpoint_events"] = "500"
			},
			want: CodeInvalidPayload,
		},
		{
			name: "hard range",
			mutate: func(object map[string]any) {
				object["checkpoint_events"] = 99
			},
			want: CodeInvalidPayload,
		},
		{
			name: "TTL relation",
			mutate: func(object map[string]any) {
				object["lease_min_ttl_seconds"] = 1_000
			},
			want: CodeInvalidPayload,
		},
		{
			name: "claim relation",
			mutate: func(object map[string]any) {
				object["agent_claim_limit"] = 64
				object["device_claim_limit"] = 63
			},
			want: CodeInvalidPayload,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			object := policyPayloadMap(policy.DefaultValues())
			test.mutate(object)
			proposal := buildPolicyProposal(
				t,
				fixture,
				fixture.ownerDevice,
				testSessionID,
				1,
				marshalPolicyPayload(t, object),
			)
			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Status != StatusRejected ||
				outcome.Code != test.want ||
				len(outcome.Changes.OriginScopes) != 1 ||
				outcome.Changes.OriginScopes[0].LastSequence != 2 ||
				len(outcome.Changes.SessionPolicy) != 0 {
				t.Fatalf("outcome = %#v, want rejected/%s", outcome, test.want)
			}
		})
	}
}

func TestPolicyChangedRejectsEveryNamedImmutableV1Key(t *testing.T) {
	t.Parallel()

	keys := []string{
		"credential_epoch_seconds",
		"credential_overlap_seconds",
		"credential_renewal_lead_seconds",
		"primitive_suite_version",
		"protocol_policy_version",
		"digest_version",
		"projection_schema_version",
		"event_chain_version",
		"result_chain_version",
		"max_signed_json_nesting_depth",
		"max_event_bytes",
		"event_path_array_max_bytes",
		"activity_duration_max_ms",
		"task_dependency_walk_max",
		"control_file_max_bytes",
		"control_file_diff_max_bytes",
		"control_path_policy_version",
		"publication_receipt_window_results",
		"publication_introduced_commit_max",
		"publication_changed_edge_max",
		"publication_parent_max",
		"multicast_ipv4_group",
		"multicast_ipv6_group",
		"multicast_port",
		"merge_inputs_version",
	}

	for _, key := range keys {
		key := key
		t.Run(key, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			object := policyPayloadMap(policy.DefaultValues())
			object[key] = true
			proposal := buildPolicyProposal(
				t,
				fixture,
				fixture.ownerDevice,
				testSessionID,
				1,
				marshalPolicyPayload(t, object),
			)
			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Status != StatusRejected ||
				outcome.Code != CodeUnknownPayloadField ||
				len(outcome.Changes.OriginScopes) != 1 ||
				len(outcome.Changes.SessionPolicy) != 0 {
				t.Fatalf("outcome = %#v", outcome)
			}
		})
	}
}

func TestPolicyChangedEnforcesSessionCASRoleAndVersionBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		device   func(reducerFixture) domain.DeviceID
		entityID domain.UUIDv7
		expected uint64
		prepare  func(*reducerFixture)
		want     Code
	}{
		{
			name: "editor is not owner",
			device: func(fixture reducerFixture) domain.DeviceID {
				return fixture.editorDevice
			},
			entityID: testSessionID,
			expected: 1,
			want:     CodeInsufficientRole,
		},
		{
			name: "wrong session entity",
			device: func(fixture reducerFixture) domain.DeviceID {
				return fixture.ownerDevice
			},
			entityID: domain.UUIDv7(
				"01890f47-3e72-7000-8000-000000000099",
			),
			expected: 1,
			want:     CodeSessionBindingMismatch,
		},
		{
			name: "stale CAS",
			device: func(fixture reducerFixture) domain.DeviceID {
				return fixture.ownerDevice
			},
			entityID: testSessionID,
			expected: 2,
			want:     CodeEntityVersionMismatch,
		},
		{
			name: "entity version exhausted",
			device: func(fixture reducerFixture) domain.DeviceID {
				return fixture.ownerDevice
			},
			entityID: testSessionID,
			expected: domain.MaxSafeInteger,
			prepare: func(fixture *reducerFixture) {
				fixture.state.sessionPolicy.EntityVersion = domain.MaxSafeInteger
			},
			want: CodeEntityVersionExhausted,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			if test.prepare != nil {
				test.prepare(&fixture)
			}
			proposal := buildPolicyProposal(
				t,
				fixture,
				test.device(fixture),
				test.entityID,
				test.expected,
				policyPayload(t, policy.DefaultValues()),
			)
			assertRejectedCode(t, fixture.state, proposal, test.want)
		})
	}
}

func TestPolicyChangedRejectsCapsBelowCurrentReplicatedUse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*testing.T, *reducerFixture)
		mutate  func(*policy.Values)
	}{
		{
			name: "active members",
			mutate: func(values *policy.Values) {
				values.MaxMemberDevices = 2
			},
		},
		{
			name: "active agent sessions",
			prepare: func(_ *testing.T, fixture *reducerFixture) {
				addReducerAgent(
					&fixture.state,
					testOtherAgentID,
					fixture.editorDevice,
				)
			},
			mutate: func(values *policy.Values) {
				values.MaxActiveAgentSessions = 1
			},
		},
		{
			name: "audit depth",
			prepare: func(_ *testing.T, fixture *reducerFixture) {
				counter := fixture.state.auditCounters[fixture.ownerDevice]
				counter.AcceptedCount =
					uint64(policy.MinAuditDepthPerDevicePerEpoch + 1)
				fixture.state.auditCounters[fixture.ownerDevice] = counter
			},
			mutate: func(values *policy.Values) {
				values.AuditDepthPerDevicePerEpoch =
					policy.MinAuditDepthPerDevicePerEpoch
			},
		},
		{
			name: "claims per agent",
			prepare: func(_ *testing.T, fixture *reducerFixture) {
				addPolicyTestClaim(
					&fixture.state,
					testTaskID,
					fixture.editorDevice,
					testAgentSessionID,
				)
				addPolicyTestClaim(
					&fixture.state,
					testOtherTaskID,
					fixture.editorDevice,
					testAgentSessionID,
				)
			},
			mutate: func(values *policy.Values) {
				values.AgentClaimLimit = 1
			},
		},
		{
			name: "claims per device",
			prepare: func(_ *testing.T, fixture *reducerFixture) {
				addReducerAgent(
					&fixture.state,
					testOtherAgentID,
					fixture.editorDevice,
				)
				addPolicyTestClaim(
					&fixture.state,
					testTaskID,
					fixture.editorDevice,
					testAgentSessionID,
				)
				addPolicyTestClaim(
					&fixture.state,
					testOtherTaskID,
					fixture.editorDevice,
					testOtherAgentID,
				)
			},
			mutate: func(values *policy.Values) {
				values.AgentClaimLimit = 1
				values.DeviceClaimLimit = 1
			},
		},
		{
			name: "leases per agent",
			prepare: func(t *testing.T, fixture *reducerFixture) {
				addReducerLease(
					&fixture.state,
					mustReducerLease(
						t,
						reducerLeaseID(1),
						fixture.editorDevice,
						testAgentSessionID,
						lease.ScopePath,
						"",
						1,
						"docs/**",
					),
				)
				addReducerLease(
					&fixture.state,
					mustReducerLease(
						t,
						reducerLeaseID(2),
						fixture.editorDevice,
						testAgentSessionID,
						lease.ScopePath,
						"",
						1,
						"src/**",
					),
				)
			},
			mutate: func(values *policy.Values) {
				values.AgentLeaseLimit = 1
			},
		},
		{
			name: "leases per device",
			prepare: func(t *testing.T, fixture *reducerFixture) {
				addReducerAgent(
					&fixture.state,
					testOtherAgentID,
					fixture.editorDevice,
				)
				addReducerLease(
					&fixture.state,
					mustReducerLease(
						t,
						reducerLeaseID(1),
						fixture.editorDevice,
						testAgentSessionID,
						lease.ScopePath,
						"",
						1,
						"docs/**",
					),
				)
				addReducerLease(
					&fixture.state,
					mustReducerLease(
						t,
						reducerLeaseID(2),
						fixture.editorDevice,
						testOtherAgentID,
						lease.ScopePath,
						"",
						1,
						"src/**",
					),
				)
			},
			mutate: func(values *policy.Values) {
				values.AgentLeaseLimit = 1
				values.DeviceLeaseLimit = 1
			},
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
			values := policy.DefaultValues()
			test.mutate(&values)
			proposal := buildPolicyProposal(
				t,
				fixture,
				fixture.ownerDevice,
				testSessionID,
				1,
				policyPayload(t, values),
			)
			assertRejectedCode(
				t,
				fixture.state,
				proposal,
				CodePolicyLimitBelowCurrentUse,
			)
		})
	}
}

func TestPolicyChangedAcceptsCapsEqualToCurrentReplicatedUse(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	addReducerAgent(
		&fixture.state,
		testOtherAgentID,
		fixture.editorDevice,
	)
	addPolicyTestClaim(
		&fixture.state,
		testTaskID,
		fixture.editorDevice,
		testAgentSessionID,
	)
	addPolicyTestClaim(
		&fixture.state,
		testOtherTaskID,
		fixture.editorDevice,
		testOtherAgentID,
	)
	addReducerLease(
		&fixture.state,
		mustReducerLease(
			t,
			reducerLeaseID(1),
			fixture.editorDevice,
			testAgentSessionID,
			lease.ScopePath,
			"",
			1,
			"docs/**",
		),
	)
	addReducerLease(
		&fixture.state,
		mustReducerLease(
			t,
			reducerLeaseID(2),
			fixture.editorDevice,
			testOtherAgentID,
			lease.ScopePath,
			"",
			1,
			"src/**",
		),
	)
	values := policy.DefaultValues()
	values.AgentClaimLimit = 1
	values.AgentLeaseLimit = 1
	values.DeviceClaimLimit = 2
	values.DeviceLeaseLimit = 2
	values.MaxMemberDevices = 3
	values.MaxActiveAgentSessions = 2
	proposal := buildPolicyProposal(
		t,
		fixture,
		fixture.ownerDevice,
		testSessionID,
		1,
		policyPayload(t, values),
	)

	outcome := assertAccepted(t, fixture.state, proposal)
	if got := outcome.Changes.SessionPolicy[0].Values; got != values {
		t.Fatalf("policy values = %#v, want %#v", got, values)
	}
}

func TestPolicyChangedEnforcesApplyLevelMonotonicityAndCapability(t *testing.T) {
	t.Parallel()

	t.Run("decrease rejected", func(t *testing.T) {
		t.Parallel()

		fixture := newReducerFixture(t)
		fixture.state.sessionPolicy.Values.ClusterMinApplyLevel = 2
		for id, member := range fixture.state.devices {
			member.MaxApplyLevel = 2
			fixture.state.devices[id] = member
		}
		values := policy.DefaultValues()
		values.ClusterMinApplyLevel = 1
		proposal := buildPolicyProposal(
			t,
			fixture,
			fixture.ownerDevice,
			testSessionID,
			1,
			policyPayload(t, values),
		)
		context, outcome, done, err := beginReduction(
			fixture.state,
			proposal,
		)
		if err != nil || done {
			t.Fatalf(
				"beginReduction() = (%#v, %t, %v), want active context",
				outcome,
				done,
				err,
			)
		}
		outcome, err = reducePolicyChanged(context)
		if err != nil ||
			outcome.Status != StatusRejected ||
			outcome.Code != CodeClusterApplyLevelDecrease {
			t.Fatalf(
				"reducePolicyChanged() = (%#v, %v), want %s",
				outcome,
				err,
				CodeClusterApplyLevelDecrease,
			)
		}
	})

	t.Run("unsupported active device rejects", func(t *testing.T) {
		t.Parallel()

		fixture := newReducerFixture(t)
		values := policy.DefaultValues()
		values.ClusterMinApplyLevel = 2
		proposal := buildPolicyProposal(
			t,
			fixture,
			fixture.ownerDevice,
			testSessionID,
			1,
			policyPayload(t, values),
		)
		assertRejectedCode(
			t,
			fixture.state,
			proposal,
			CodeClusterApplyLevelUnsupported,
		)
	})

	t.Run("inactive device is ignored", func(t *testing.T) {
		t.Parallel()

		fixture := newReducerFixture(t)
		for id, member := range fixture.state.devices {
			member.MaxApplyLevel = 2
			fixture.state.devices[id] = member
		}
		inactive := fixture.state.devices[fixture.targetDevice]
		inactive.MaxApplyLevel = 1
		inactive.Status = device.StatusRequiresReadmission
		fixture.state.devices[fixture.targetDevice] = inactive
		values := policy.DefaultValues()
		values.ClusterMinApplyLevel = 2
		proposal := buildPolicyProposal(
			t,
			fixture,
			fixture.ownerDevice,
			testSessionID,
			1,
			policyPayload(t, values),
		)
		assertAccepted(t, fixture.state, proposal)
	})
}

func TestPolicyChangedPinsCurrentUseBeforeApplyCapabilityPrecedence(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	values := policy.DefaultValues()
	values.MaxMemberDevices = 2
	values.ClusterMinApplyLevel = 2
	proposal := buildPolicyProposal(
		t,
		fixture,
		fixture.ownerDevice,
		testSessionID,
		1,
		policyPayload(t, values),
	)

	assertRejectedCode(
		t,
		fixture.state,
		proposal,
		CodePolicyLimitBelowCurrentUse,
	)
}

func addPolicyTestClaim(
	state *State,
	id domain.UUIDv7,
	deviceID domain.DeviceID,
	agentSessionID domain.UUIDv7,
) {
	value := testTask(task.StateClaimed, 1)
	value.ID = id
	value.OwnerDeviceID = deviceID
	value.OwnerAgentSessionID = agentSessionID
	state.tasks[id] = value
	state.addClaim(value)
}

func buildPolicyProposal(
	t *testing.T,
	fixture reducerFixture,
	deviceID domain.DeviceID,
	entityID domain.UUIDv7,
	expected uint64,
	payload string,
) event.SignedEvent {
	t.Helper()
	return buildCoordinationProposal(
		t,
		fixture,
		event.ActorHuman,
		deviceID,
		event.KindPolicyChanged,
		string(entityID),
		expected,
		payload,
		2,
	)
}

func policyPayload(t *testing.T, values policy.Values) string {
	t.Helper()
	return marshalPolicyPayload(t, policyPayloadMap(values))
}

func marshalPolicyPayload(t *testing.T, object map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("json.Marshal(policy payload) error = %v", err)
	}
	return string(encoded)
}

func policyPayloadMap(values policy.Values) map[string]any {
	return map[string]any{
		"checkpoint_events":                values.CheckpointEvents,
		"checkpoint_interval_seconds":      values.CheckpointIntervalSeconds,
		"lease_min_ttl_seconds":            values.LeaseMinTTLSeconds,
		"lease_default_ttl_seconds":        values.LeaseDefaultTTLSeconds,
		"lease_max_ttl_seconds":            values.LeaseMaxTTLSeconds,
		"agent_claim_limit":                values.AgentClaimLimit,
		"agent_lease_limit":                values.AgentLeaseLimit,
		"device_claim_limit":               values.DeviceClaimLimit,
		"device_lease_limit":               values.DeviceLeaseLimit,
		"advertisement_interval_seconds":   values.AdvertisementIntervalSeconds,
		"audit_depth_per_device_per_epoch": values.AuditDepthPerDevicePerEpoch,
		"max_member_devices":               values.MaxMemberDevices,
		"max_active_agent_sessions":        values.MaxActiveAgentSessions,
		"cluster_min_apply_level":          values.ClusterMinApplyLevel,
	}
}
