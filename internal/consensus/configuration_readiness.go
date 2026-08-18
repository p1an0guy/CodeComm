package consensus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

const MaxConfigurationReadinessTokenBytes = 4 << 10

var (
	ErrConfigurationReadinessUnavailable = errors.New(
		"consensus: configuration readiness provider unavailable",
	)
	ErrInvalidConfigurationReadiness = errors.New(
		"consensus: invalid configuration readiness evidence",
	)
	ErrConfigurationReadinessChanged = errors.New(
		"consensus: configuration readiness evidence is stale",
	)
	ErrConfigurationQuorumUnavailable = errors.New(
		"consensus: reachable active credentialed quorum unavailable",
	)
)

// ConfigurationOperation is the closed set of topology mutations whose
// post-change quorum must be checked immediately before Raft enqueue.
type ConfigurationOperation string

const (
	ConfigurationAddVoter    ConfigurationOperation = "add_voter"
	ConfigurationAddNonvoter ConfigurationOperation = "add_nonvoter"
	ConfigurationDemoteVoter ConfigurationOperation = "demote_voter"
	ConfigurationRemove      ConfigurationOperation = "remove_server"
	ConfigurationTransfer    ConfigurationOperation = "transfer_leadership"
	ConfigurationObserve     ConfigurationOperation = "observe_reconciliation"
)

func (operation ConfigurationOperation) valid() bool {
	switch operation {
	case ConfigurationAddVoter,
		ConfigurationAddNonvoter,
		ConfigurationDemoteVoter,
		ConfigurationRemove,
		ConfigurationTransfer,
		ConfigurationObserve:
		return true
	default:
		return false
	}
}

// ConfigurationReadinessRequirement is one immutable applied-state and live
// topology cut. Device-ID slices are canonical, sorted, and independent.
type ConfigurationReadinessRequirement struct {
	SessionID                domain.UUIDv7
	RecoveryGeneration       uint64
	TargetVoterSetVersion    uint64
	TargetVoterDeviceIDs     []domain.DeviceID
	ConfigurationIndex       uint64
	LiveVoterDeviceIDs       []domain.DeviceID
	LiveNonvoterDeviceIDs    []domain.DeviceID
	ActiveDeviceIDs          []domain.DeviceID
	PostChangeVoterDeviceIDs []domain.DeviceID
	RequiredPostChangeQuorum uint64
	Operation                ConfigurationOperation
	SubjectDeviceID          domain.DeviceID
}

func (requirement ConfigurationReadinessRequirement) validate() error {
	if !requirement.SessionID.Valid() ||
		!domain.ValidUnsignedInteger(requirement.RecoveryGeneration) ||
		requirement.TargetVoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(requirement.TargetVoterSetVersion) ||
		requirement.ConfigurationIndex < 1 ||
		!domain.ValidUnsignedInteger(requirement.ConfigurationIndex) ||
		!requirement.Operation.valid() ||
		!requirement.SubjectDeviceID.Valid() {
		return ErrInvalidConfigurationReadiness
	}
	if _, err := voterset.New(
		requirement.SessionID,
		requirement.TargetVoterDeviceIDs,
		requirement.TargetVoterSetVersion,
	); err != nil {
		return fmt.Errorf(
			"%w: target voter set: %v",
			ErrInvalidConfigurationReadiness,
			err,
		)
	}
	if !sortedUniqueDeviceIDs(requirement.LiveVoterDeviceIDs) ||
		!sortedUniqueDeviceIDs(requirement.LiveNonvoterDeviceIDs) ||
		!sortedUniqueDeviceIDs(requirement.ActiveDeviceIDs) ||
		!sortedUniqueDeviceIDs(requirement.PostChangeVoterDeviceIDs) ||
		len(requirement.LiveVoterDeviceIDs) < 1 ||
		len(requirement.PostChangeVoterDeviceIDs) < 1 ||
		len(requirement.LiveVoterDeviceIDs)+
			len(requirement.LiveNonvoterDeviceIDs) >
			int(policy.MaxMemberDevices) ||
		overlapDeviceIDs(
			requirement.LiveVoterDeviceIDs,
			requirement.LiveNonvoterDeviceIDs,
		) ||
		!subsetDeviceIDs(
			requirement.ActiveDeviceIDs,
			mergeSortedDeviceIDs(
				requirement.LiveVoterDeviceIDs,
				requirement.LiveNonvoterDeviceIDs,
			),
		) {
		return ErrInvalidConfigurationReadiness
	}
	required := len(requirement.PostChangeVoterDeviceIDs)/2 + 1
	if requirement.RequiredPostChangeQuorum != uint64(required) {
		return ErrInvalidConfigurationReadiness
	}
	return nil
}

func (requirement ConfigurationReadinessRequirement) same(
	other ConfigurationReadinessRequirement,
) bool {
	return requirement.SessionID == other.SessionID &&
		requirement.RecoveryGeneration == other.RecoveryGeneration &&
		requirement.TargetVoterSetVersion ==
			other.TargetVoterSetVersion &&
		requirement.ConfigurationIndex == other.ConfigurationIndex &&
		requirement.RequiredPostChangeQuorum ==
			other.RequiredPostChangeQuorum &&
		requirement.Operation == other.Operation &&
		requirement.SubjectDeviceID == other.SubjectDeviceID &&
		sameDeviceIDs(
			requirement.TargetVoterDeviceIDs,
			other.TargetVoterDeviceIDs,
		) &&
		sameDeviceIDs(
			requirement.LiveVoterDeviceIDs,
			other.LiveVoterDeviceIDs,
		) &&
		sameDeviceIDs(
			requirement.LiveNonvoterDeviceIDs,
			other.LiveNonvoterDeviceIDs,
		) &&
		sameDeviceIDs(
			requirement.ActiveDeviceIDs,
			other.ActiveDeviceIDs,
		) &&
		sameDeviceIDs(
			requirement.PostChangeVoterDeviceIDs,
			other.PostChangeVoterDeviceIDs,
		)
}

func (requirement ConfigurationReadinessRequirement) clone() ConfigurationReadinessRequirement {
	result := requirement
	result.TargetVoterDeviceIDs = append(
		[]domain.DeviceID(nil),
		requirement.TargetVoterDeviceIDs...,
	)
	result.LiveVoterDeviceIDs = append(
		[]domain.DeviceID(nil),
		requirement.LiveVoterDeviceIDs...,
	)
	result.LiveNonvoterDeviceIDs = append(
		[]domain.DeviceID(nil),
		requirement.LiveNonvoterDeviceIDs...,
	)
	result.ActiveDeviceIDs = append(
		[]domain.DeviceID(nil),
		requirement.ActiveDeviceIDs...,
	)
	result.PostChangeVoterDeviceIDs = append(
		[]domain.DeviceID(nil),
		requirement.PostChangeVoterDeviceIDs...,
	)
	return result
}

// ConfigurationReadinessCandidate is provider-issued, bounded evidence for
// one requirement. Consensus validates the canonical device sets; Token is an
// opaque provider freshness binding and must contain no private key material.
type ConfigurationReadinessCandidate struct {
	ReachableDeviceIDs         []domain.DeviceID
	CurrentCredentialDeviceIDs []domain.DeviceID
	Token                      []byte
}

func (candidate ConfigurationReadinessCandidate) clone() ConfigurationReadinessCandidate {
	return ConfigurationReadinessCandidate{
		ReachableDeviceIDs: append(
			[]domain.DeviceID(nil),
			candidate.ReachableDeviceIDs...,
		),
		CurrentCredentialDeviceIDs: append(
			[]domain.DeviceID(nil),
			candidate.CurrentCredentialDeviceIDs...,
		),
		Token: bytes.Clone(candidate.Token),
	}
}

// ConfigurationReadinessProvider probes reachability and current content
// credentials outside the enqueue lock, then performs a non-blocking,
// non-I/O freshness check inside it. VerifyCurrentConfigurationReadiness MUST
// NOT dial, wait, or call back into consensus.
type ConfigurationReadinessProvider interface {
	CollectConfigurationReadiness(
		context.Context,
		ConfigurationReadinessRequirement,
	) (ConfigurationReadinessCandidate, error)
	VerifyCurrentConfigurationReadiness(
		ConfigurationReadinessRequirement,
		ConfigurationReadinessCandidate,
	) error
}

type configurationReadinessGate struct {
	provider ConfigurationReadinessProvider
}

type verifiedConfigurationReadiness struct {
	requirement ConfigurationReadinessRequirement
	candidate   ConfigurationReadinessCandidate
}

func newConfigurationReadinessGate(
	provider ConfigurationReadinessProvider,
) *configurationReadinessGate {
	if nilConfigurationReadinessProvider(provider) {
		return nil
	}
	return &configurationReadinessGate{provider: provider}
}

func (gate *configurationReadinessGate) collect(
	ctx context.Context,
	requirement ConfigurationReadinessRequirement,
) (verifiedConfigurationReadiness, error) {
	if ctx == nil || requirement.validate() != nil {
		return verifiedConfigurationReadiness{},
			ErrInvalidConfigurationReadiness
	}
	if err := ctx.Err(); err != nil {
		return verifiedConfigurationReadiness{}, err
	}
	if gate == nil ||
		nilConfigurationReadinessProvider(gate.provider) {
		return verifiedConfigurationReadiness{},
			ErrConfigurationReadinessUnavailable
	}
	candidate, err := gate.provider.CollectConfigurationReadiness(
		ctx,
		requirement.clone(),
	)
	if err != nil {
		return verifiedConfigurationReadiness{}, err
	}
	if err := validateConfigurationReadinessCandidate(
		requirement,
		candidate,
	); err != nil {
		return verifiedConfigurationReadiness{}, err
	}
	return verifiedConfigurationReadiness{
		requirement: requirement.clone(),
		candidate:   candidate.clone(),
	}, nil
}

func (gate *configurationReadinessGate) verifyCurrent(
	current ConfigurationReadinessRequirement,
	verified verifiedConfigurationReadiness,
) error {
	if gate == nil ||
		nilConfigurationReadinessProvider(gate.provider) {
		return ErrConfigurationReadinessUnavailable
	}
	if current.validate() != nil ||
		verified.requirement.validate() != nil ||
		!current.same(verified.requirement) {
		return ErrConfigurationReadinessChanged
	}
	if err := validateConfigurationReadinessCandidate(
		current,
		verified.candidate,
	); err != nil {
		return err
	}
	if err := gate.provider.VerifyCurrentConfigurationReadiness(
		current.clone(),
		verified.candidate.clone(),
	); err != nil {
		return err
	}
	return validateConfigurationReadinessCandidate(
		current,
		verified.candidate,
	)
}

func validateConfigurationReadinessCandidate(
	requirement ConfigurationReadinessRequirement,
	candidate ConfigurationReadinessCandidate,
) error {
	if requirement.validate() != nil ||
		!sortedUniqueDeviceIDs(candidate.ReachableDeviceIDs) ||
		!sortedUniqueDeviceIDs(candidate.CurrentCredentialDeviceIDs) ||
		len(candidate.ReachableDeviceIDs) > int(policy.MaxMemberDevices) ||
		len(candidate.CurrentCredentialDeviceIDs) >
			int(policy.MaxMemberDevices) ||
		len(candidate.Token) > MaxConfigurationReadinessTokenBytes {
		return ErrInvalidConfigurationReadiness
	}
	live := deviceIDSet(requirement.LiveVoterDeviceIDs)
	for _, id := range requirement.LiveNonvoterDeviceIDs {
		live[id] = struct{}{}
	}
	reachable := deviceIDSet(candidate.ReachableDeviceIDs)
	credentialed := deviceIDSet(candidate.CurrentCredentialDeviceIDs)
	active := deviceIDSet(requirement.ActiveDeviceIDs)
	for id := range reachable {
		if _, exists := live[id]; !exists {
			return ErrInvalidConfigurationReadiness
		}
		if _, exists := active[id]; !exists {
			return ErrInvalidConfigurationReadiness
		}
	}
	for id := range credentialed {
		if _, exists := live[id]; !exists {
			return ErrInvalidConfigurationReadiness
		}
		if _, exists := active[id]; !exists {
			return ErrInvalidConfigurationReadiness
		}
	}
	ready := 0
	for _, id := range requirement.PostChangeVoterDeviceIDs {
		if _, ok := reachable[id]; !ok {
			continue
		}
		if _, ok := credentialed[id]; ok {
			ready++
		}
	}
	if uint64(ready) < requirement.RequiredPostChangeQuorum {
		return ErrConfigurationQuorumUnavailable
	}
	if requirement.Operation == ConfigurationAddVoter ||
		requirement.Operation == ConfigurationTransfer ||
		requirement.Operation == ConfigurationObserve {
		if _, exists := reachable[requirement.SubjectDeviceID]; !exists {
			return ErrConfigurationQuorumUnavailable
		}
		if _, exists := credentialed[requirement.SubjectDeviceID]; !exists {
			return ErrConfigurationQuorumUnavailable
		}
	}
	return nil
}

func configurationReadinessRequirement(
	state decodedState,
	configuration *committedRaftConfiguration,
	change raftConfigurationChange,
) (ConfigurationReadinessRequirement, error) {
	if state.VoterSet.Validate() != nil ||
		configuration == nil ||
		configuration.Index < 1 ||
		!domain.ValidUnsignedInteger(configuration.Index) ||
		validateDeviceAddressedSnapshotConfiguration(
			configuration.Configuration,
		) != nil ||
		change.validate() != nil {
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	liveVoters := make([]domain.DeviceID, 0, len(configuration.Configuration.Servers))
	liveNonvoters := make(
		[]domain.DeviceID,
		0,
		len(configuration.Configuration.Servers),
	)
	for _, server := range configuration.Configuration.Servers {
		id := domain.DeviceID(server.ID)
		switch server.Suffrage {
		case raft.Voter:
			liveVoters = append(liveVoters, id)
		case raft.Nonvoter:
			liveNonvoters = append(liveNonvoters, id)
		default:
			return ConfigurationReadinessRequirement{},
				ErrInvalidConfigurationReadiness
		}
	}
	sortDeviceIDs(liveVoters)
	sortDeviceIDs(liveNonvoters)
	activeDeviceIDs, err := activeConfiguredDeviceIDs(
		state,
		liveVoters,
		liveNonvoters,
	)
	if err != nil {
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	postChange := append([]domain.DeviceID(nil), liveVoters...)
	switch change.kind {
	case raftChangeAddVoter:
		postChange = addSortedDeviceID(postChange, change.deviceID)
	case raftChangeDemoteVoter, raftChangeRemoveServer:
		postChange = removeSortedDeviceID(postChange, change.deviceID)
	case raftChangeAddNonvoter:
	default:
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	if len(postChange) == 0 {
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	requirement := ConfigurationReadinessRequirement{
		SessionID:                state.VoterSet.SessionID,
		RecoveryGeneration:       state.recoveryGeneration,
		TargetVoterSetVersion:    state.VoterSet.VoterSetVersion,
		TargetVoterDeviceIDs:     state.VoterSet.VoterDeviceIDs(),
		ConfigurationIndex:       configuration.Index,
		LiveVoterDeviceIDs:       liveVoters,
		LiveNonvoterDeviceIDs:    liveNonvoters,
		ActiveDeviceIDs:          activeDeviceIDs,
		PostChangeVoterDeviceIDs: postChange,
		RequiredPostChangeQuorum: uint64(len(postChange)/2 + 1),
		Operation:                configurationOperation(change.kind),
		SubjectDeviceID:          change.deviceID,
	}
	if requirement.validate() != nil {
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	return requirement, nil
}

func leadershipTransferReadinessRequirement(
	state decodedState,
	configuration *committedRaftConfiguration,
	target domain.DeviceID,
) (ConfigurationReadinessRequirement, error) {
	if !target.Valid() ||
		state.VoterSet.Validate() != nil ||
		configuration == nil ||
		configuration.Index < 1 ||
		!domain.ValidUnsignedInteger(configuration.Index) ||
		validateDeviceAddressedSnapshotConfiguration(
			configuration.Configuration,
		) != nil {
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	var liveVoters, liveNonvoters []domain.DeviceID
	for _, server := range configuration.Configuration.Servers {
		id := domain.DeviceID(server.ID)
		switch server.Suffrage {
		case raft.Voter:
			liveVoters = append(liveVoters, id)
		case raft.Nonvoter:
			liveNonvoters = append(liveNonvoters, id)
		default:
			return ConfigurationReadinessRequirement{},
				ErrInvalidConfigurationReadiness
		}
	}
	sortDeviceIDs(liveVoters)
	sortDeviceIDs(liveNonvoters)
	activeDeviceIDs, err := activeConfiguredDeviceIDs(
		state,
		liveVoters,
		liveNonvoters,
	)
	if err != nil {
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	requirement := ConfigurationReadinessRequirement{
		SessionID:                state.VoterSet.SessionID,
		RecoveryGeneration:       state.recoveryGeneration,
		TargetVoterSetVersion:    state.VoterSet.VoterSetVersion,
		TargetVoterDeviceIDs:     state.VoterSet.VoterDeviceIDs(),
		ConfigurationIndex:       configuration.Index,
		LiveVoterDeviceIDs:       liveVoters,
		LiveNonvoterDeviceIDs:    liveNonvoters,
		ActiveDeviceIDs:          activeDeviceIDs,
		PostChangeVoterDeviceIDs: append([]domain.DeviceID(nil), liveVoters...),
		RequiredPostChangeQuorum: uint64(len(liveVoters)/2 + 1),
		Operation:                ConfigurationTransfer,
		SubjectDeviceID:          target,
	}
	if requirement.validate() != nil ||
		!containsSortedDeviceID(liveVoters, target) ||
		!state.VoterSet.Contains(target) {
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	return requirement, nil
}

func reconciliationReadinessRequirement(
	state decodedState,
	configuration *committedRaftConfiguration,
	localLeader domain.DeviceID,
) (ConfigurationReadinessRequirement, error) {
	if !localLeader.Valid() ||
		state.VoterSet.Validate() != nil ||
		configuration == nil ||
		configuration.Index < 1 ||
		!domain.ValidUnsignedInteger(configuration.Index) ||
		validateDeviceAddressedSnapshotConfiguration(
			configuration.Configuration,
		) != nil {
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	var liveVoters, liveNonvoters []domain.DeviceID
	localIsVoter := false
	for _, server := range configuration.Configuration.Servers {
		id := domain.DeviceID(server.ID)
		switch server.Suffrage {
		case raft.Voter:
			liveVoters = append(liveVoters, id)
			localIsVoter = localIsVoter || id == localLeader
		case raft.Nonvoter:
			liveNonvoters = append(liveNonvoters, id)
		default:
			return ConfigurationReadinessRequirement{},
				ErrInvalidConfigurationReadiness
		}
	}
	sortDeviceIDs(liveVoters)
	sortDeviceIDs(liveNonvoters)
	activeDeviceIDs, err := activeConfiguredDeviceIDs(
		state,
		liveVoters,
		liveNonvoters,
	)
	if err != nil {
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	requirement := ConfigurationReadinessRequirement{
		SessionID:                state.VoterSet.SessionID,
		RecoveryGeneration:       state.recoveryGeneration,
		TargetVoterSetVersion:    state.VoterSet.VoterSetVersion,
		TargetVoterDeviceIDs:     state.VoterSet.VoterDeviceIDs(),
		ConfigurationIndex:       configuration.Index,
		LiveVoterDeviceIDs:       liveVoters,
		LiveNonvoterDeviceIDs:    liveNonvoters,
		ActiveDeviceIDs:          activeDeviceIDs,
		PostChangeVoterDeviceIDs: append([]domain.DeviceID(nil), liveVoters...),
		RequiredPostChangeQuorum: uint64(len(liveVoters)/2 + 1),
		Operation:                ConfigurationObserve,
		SubjectDeviceID:          localLeader,
	}
	if !localIsVoter ||
		requirement.validate() != nil ||
		!containsSortedDeviceID(activeDeviceIDs, localLeader) {
		return ConfigurationReadinessRequirement{},
			ErrInvalidConfigurationReadiness
	}
	return requirement, nil
}

func configurationOperation(
	kind raftConfigurationChangeKind,
) ConfigurationOperation {
	switch kind {
	case raftChangeAddVoter:
		return ConfigurationAddVoter
	case raftChangeAddNonvoter:
		return ConfigurationAddNonvoter
	case raftChangeDemoteVoter:
		return ConfigurationDemoteVoter
	case raftChangeRemoveServer:
		return ConfigurationRemove
	default:
		return ""
	}
}

func nilConfigurationReadinessProvider(
	provider ConfigurationReadinessProvider,
) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func sortedUniqueDeviceIDs(values []domain.DeviceID) bool {
	var previous domain.DeviceID
	for index, value := range values {
		if !value.Valid() || index > 0 && previous >= value {
			return false
		}
		previous = value
	}
	return true
}

func overlapDeviceIDs(left, right []domain.DeviceID) bool {
	leftSet := deviceIDSet(left)
	for _, id := range right {
		if _, exists := leftSet[id]; exists {
			return true
		}
	}
	return false
}

func subsetDeviceIDs(
	subset []domain.DeviceID,
	superset []domain.DeviceID,
) bool {
	available := deviceIDSet(superset)
	for _, id := range subset {
		if _, exists := available[id]; !exists {
			return false
		}
	}
	return true
}

func mergeSortedDeviceIDs(
	left []domain.DeviceID,
	right []domain.DeviceID,
) []domain.DeviceID {
	result := append([]domain.DeviceID(nil), left...)
	result = append(result, right...)
	sortDeviceIDs(result)
	return result
}

func activeConfiguredDeviceIDs(
	state decodedState,
	liveVoters []domain.DeviceID,
	liveNonvoters []domain.DeviceID,
) ([]domain.DeviceID, error) {
	configured := mergeSortedDeviceIDs(liveVoters, liveNonvoters)
	result := make([]domain.DeviceID, 0, len(configured))
	for _, id := range configured {
		member, exists := state.Admission.Member(id)
		if !exists {
			return nil, ErrInvalidConfigurationReadiness
		}
		if member.Status == device.StatusActive {
			result = append(result, id)
		}
	}
	return result, nil
}

func deviceIDSet(values []domain.DeviceID) map[domain.DeviceID]struct{} {
	result := make(map[domain.DeviceID]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sortDeviceIDs(values []domain.DeviceID) {
	sort.Slice(values, func(left, right int) bool {
		return values[left] < values[right]
	})
}

func addSortedDeviceID(
	values []domain.DeviceID,
	deviceID domain.DeviceID,
) []domain.DeviceID {
	index := sort.Search(len(values), func(index int) bool {
		return values[index] >= deviceID
	})
	if index < len(values) && values[index] == deviceID {
		return values
	}
	values = append(values, "")
	copy(values[index+1:], values[index:])
	values[index] = deviceID
	return values
}

func removeSortedDeviceID(
	values []domain.DeviceID,
	deviceID domain.DeviceID,
) []domain.DeviceID {
	index := sort.Search(len(values), func(index int) bool {
		return values[index] >= deviceID
	})
	if index >= len(values) || values[index] != deviceID {
		return values
	}
	copy(values[index:], values[index+1:])
	return values[:len(values)-1]
}

func containsSortedDeviceID(
	values []domain.DeviceID,
	deviceID domain.DeviceID,
) bool {
	index := sort.Search(len(values), func(index int) bool {
		return values[index] >= deviceID
	})
	return index < len(values) && values[index] == deviceID
}
