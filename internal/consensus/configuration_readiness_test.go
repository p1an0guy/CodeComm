package consensus

import (
	"context"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

type readinessGateTestProvider struct {
	candidate ConfigurationReadinessCandidate
	collect   error
	verify    error
}

func (provider *readinessGateTestProvider) CollectConfigurationReadiness(
	ctx context.Context,
	_ ConfigurationReadinessRequirement,
) (ConfigurationReadinessCandidate, error) {
	if err := ctx.Err(); err != nil {
		return ConfigurationReadinessCandidate{}, err
	}
	return provider.candidate.clone(), provider.collect
}

func (provider *readinessGateTestProvider) VerifyCurrentConfigurationReadiness(
	_ ConfigurationReadinessRequirement,
	_ ConfigurationReadinessCandidate,
) error {
	return provider.verify
}

func TestConfigurationReadinessGateRequiresFreshCredentialedQuorum(
	t *testing.T,
) {
	requirement := readinessGateTestRequirement()
	provider := &readinessGateTestProvider{
		candidate: ConfigurationReadinessCandidate{
			ReachableDeviceIDs: append(
				[]domain.DeviceID(nil),
				requirement.PostChangeVoterDeviceIDs...,
			),
			CurrentCredentialDeviceIDs: append(
				[]domain.DeviceID(nil),
				requirement.PostChangeVoterDeviceIDs...,
			),
			Token: []byte("fresh"),
		},
	}
	gate := newConfigurationReadinessGate(provider)
	verified, err := gate.collect(testContext(t), requirement)
	if err != nil {
		t.Fatalf("collect(): %v", err)
	}
	if err := gate.verifyCurrent(requirement, verified); err != nil {
		t.Fatalf("verifyCurrent(): %v", err)
	}

	stale := requirement.clone()
	stale.ConfigurationIndex++
	if err := gate.verifyCurrent(stale, verified); !errors.Is(
		err,
		ErrConfigurationReadinessChanged,
	) {
		t.Fatalf("verifyCurrent(stale) error = %v", err)
	}

	provider.candidate.CurrentCredentialDeviceIDs =
		provider.candidate.CurrentCredentialDeviceIDs[:1]
	if _, err := gate.collect(
		testContext(t),
		requirement,
	); !errors.Is(err, ErrConfigurationQuorumUnavailable) {
		t.Fatalf("collect(missing credential) error = %v", err)
	}
}

func TestConfigurationReadinessGateRejectsUnboundEvidence(t *testing.T) {
	requirement := readinessGateTestRequirement()
	outsider := meshTestDeviceID('9')
	provider := &readinessGateTestProvider{
		candidate: ConfigurationReadinessCandidate{
			ReachableDeviceIDs: []domain.DeviceID{
				requirement.PostChangeVoterDeviceIDs[0],
				outsider,
			},
			CurrentCredentialDeviceIDs: append(
				[]domain.DeviceID(nil),
				requirement.PostChangeVoterDeviceIDs...,
			),
		},
	}
	gate := newConfigurationReadinessGate(provider)
	if _, err := gate.collect(
		testContext(t),
		requirement,
	); !errors.Is(err, ErrInvalidConfigurationReadiness) {
		t.Fatalf("collect(outsider) error = %v", err)
	}

	provider.candidate = ConfigurationReadinessCandidate{
		ReachableDeviceIDs: append(
			[]domain.DeviceID(nil),
			requirement.PostChangeVoterDeviceIDs...,
		),
		CurrentCredentialDeviceIDs: append(
			[]domain.DeviceID(nil),
			requirement.PostChangeVoterDeviceIDs...,
		),
		Token: make([]byte, MaxConfigurationReadinessTokenBytes+1),
	}
	if _, err := gate.collect(
		testContext(t),
		requirement,
	); !errors.Is(err, ErrInvalidConfigurationReadiness) {
		t.Fatalf("collect(oversize token) error = %v", err)
	}

	provider.candidate.Token = nil
	requirement.ActiveDeviceIDs = []domain.DeviceID{
		requirement.PostChangeVoterDeviceIDs[0],
		requirement.LiveNonvoterDeviceIDs[1],
	}
	if _, err := gate.collect(
		testContext(t),
		requirement,
	); !errors.Is(err, ErrInvalidConfigurationReadiness) {
		t.Fatalf("collect(revoked quorum member) error = %v", err)
	}
}

func TestConfigurationReadinessRequiresPromotedSubject(t *testing.T) {
	first := meshTestDeviceID('1')
	second := meshTestDeviceID('2')
	third := meshTestDeviceID('3')
	fourth := meshTestDeviceID('4')
	requirement := ConfigurationReadinessRequirement{
		SessionID:             nodeTestSessionID,
		RecoveryGeneration:    0,
		TargetVoterSetVersion: 2,
		TargetVoterDeviceIDs: []domain.DeviceID{
			second,
			third,
			fourth,
		},
		ConfigurationIndex:       9,
		LiveVoterDeviceIDs:       []domain.DeviceID{first, third, fourth},
		LiveNonvoterDeviceIDs:    []domain.DeviceID{second},
		ActiveDeviceIDs:          []domain.DeviceID{first, second, third, fourth},
		PostChangeVoterDeviceIDs: []domain.DeviceID{first, second, third, fourth},
		RequiredPostChangeQuorum: 3,
		Operation:                ConfigurationAddVoter,
		SubjectDeviceID:          second,
	}
	provider := &readinessGateTestProvider{
		candidate: ConfigurationReadinessCandidate{
			ReachableDeviceIDs: []domain.DeviceID{
				first,
				third,
				fourth,
			},
			CurrentCredentialDeviceIDs: []domain.DeviceID{
				first,
				third,
				fourth,
			},
		},
	}
	if _, err := newConfigurationReadinessGate(provider).collect(
		testContext(t),
		requirement,
	); !errors.Is(err, ErrConfigurationQuorumUnavailable) {
		t.Fatalf("collect(missing promoted subject) error = %v", err)
	}
}

func TestConfigurationReadinessObserveOmitsRevokedOutgoingLeader(
	t *testing.T,
) {
	first := meshTestDeviceID('1')
	second := meshTestDeviceID('2')
	third := meshTestDeviceID('3')
	fourth := meshTestDeviceID('4')
	fifth := meshTestDeviceID('5')
	requirement := ConfigurationReadinessRequirement{
		SessionID:             nodeTestSessionID,
		RecoveryGeneration:    0,
		TargetVoterSetVersion: 2,
		TargetVoterDeviceIDs: []domain.DeviceID{
			second,
			third,
			fourth,
		},
		ConfigurationIndex: 11,
		LiveVoterDeviceIDs: []domain.DeviceID{
			first,
			second,
			third,
			fourth,
			fifth,
		},
		LiveNonvoterDeviceIDs: []domain.DeviceID{},
		ActiveDeviceIDs: []domain.DeviceID{
			second,
			third,
			fourth,
			fifth,
		},
		PostChangeVoterDeviceIDs: []domain.DeviceID{
			first,
			second,
			third,
			fourth,
			fifth,
		},
		RequiredPostChangeQuorum: 3,
		Operation:                ConfigurationObserve,
		SubjectDeviceID:          first,
	}
	provider := &readinessGateTestProvider{
		candidate: ConfigurationReadinessCandidate{
			ReachableDeviceIDs: []domain.DeviceID{
				second,
				third,
				fourth,
			},
			CurrentCredentialDeviceIDs: []domain.DeviceID{
				second,
				third,
				fourth,
			},
		},
	}
	gate := newConfigurationReadinessGate(provider)
	verified, err := gate.collect(testContext(t), requirement)
	if err != nil {
		t.Fatalf("collect(without outgoing leader): %v", err)
	}
	if err := gate.verifyCurrent(requirement, verified); err != nil {
		t.Fatalf("verifyCurrent(without outgoing leader): %v", err)
	}

	provider.candidate.ReachableDeviceIDs =
		provider.candidate.ReachableDeviceIDs[:2]
	provider.candidate.CurrentCredentialDeviceIDs =
		provider.candidate.CurrentCredentialDeviceIDs[:2]
	if _, err := gate.collect(
		testContext(t),
		requirement,
	); !errors.Is(err, ErrConfigurationQuorumUnavailable) {
		t.Fatalf("collect(without active quorum) error = %v", err)
	}
}

func TestConfigurationReadinessProviderFreshnessFailurePropagates(
	t *testing.T,
) {
	requirement := readinessGateTestRequirement()
	providerErr := errors.New("peer generation changed")
	provider := &readinessGateTestProvider{
		candidate: ConfigurationReadinessCandidate{
			ReachableDeviceIDs: append(
				[]domain.DeviceID(nil),
				requirement.PostChangeVoterDeviceIDs...,
			),
			CurrentCredentialDeviceIDs: append(
				[]domain.DeviceID(nil),
				requirement.PostChangeVoterDeviceIDs...,
			),
		},
		verify: providerErr,
	}
	gate := newConfigurationReadinessGate(provider)
	verified, err := gate.collect(testContext(t), requirement)
	if err != nil {
		t.Fatalf("collect(): %v", err)
	}
	if err := gate.verifyCurrent(requirement, verified); !errors.Is(
		err,
		providerErr,
	) {
		t.Fatalf("verifyCurrent() error = %v", err)
	}
}

func readinessGateTestRequirement() ConfigurationReadinessRequirement {
	first := meshTestDeviceID('1')
	second := meshTestDeviceID('2')
	third := meshTestDeviceID('3')
	return ConfigurationReadinessRequirement{
		SessionID:             nodeTestSessionID,
		RecoveryGeneration:    0,
		TargetVoterSetVersion: 2,
		TargetVoterDeviceIDs: []domain.DeviceID{
			first,
			second,
			third,
		},
		ConfigurationIndex:       7,
		LiveVoterDeviceIDs:       []domain.DeviceID{first},
		LiveNonvoterDeviceIDs:    []domain.DeviceID{second, third},
		ActiveDeviceIDs:          []domain.DeviceID{first, second, third},
		PostChangeVoterDeviceIDs: []domain.DeviceID{first, second},
		RequiredPostChangeQuorum: 2,
		Operation:                ConfigurationAddVoter,
		SubjectDeviceID:          second,
	}
}

var _ ConfigurationReadinessProvider = (*readinessGateTestProvider)(nil)
