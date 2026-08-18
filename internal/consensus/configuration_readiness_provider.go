package consensus

import (
	"bytes"
	"context"
	"encoding/binary"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	configurationReadinessTokenVersion = 1
	configurationReadinessProbeTimeout = 10 * time.Second
	deviceIDBytes                      = 67
	credentialTokenBytes               = deviceIDBytes + 8 + 8 + 32
	reachabilityTokenBytes             = deviceIDBytes + 8
)

type consensusPeerReachability interface {
	ProbeConsensusPeer(
		context.Context,
		domain.DeviceID,
	) (transport.ConsensusPeerReachabilityToken, error)
	VerifyConsensusPeerReachability(
		transport.ConsensusPeerReachabilityToken,
	) error
}

type nodeConfigurationReadinessProvider struct {
	admissionSnapshot func() (*peerauth.Snapshot, error)
	localDeviceID     domain.DeviceID
	localReachable    func() bool
	reachability      consensusPeerReachability
	now               func() time.Time
}

type configurationCredentialToken struct {
	deviceID                domain.DeviceID
	epoch                   uint64
	authorizationChainIndex uint64
	keyDigest               [32]byte
}

type configurationReadinessToken struct {
	reachability []transport.ConsensusPeerReachabilityToken
	credentials  []configurationCredentialToken
}

func newNodeConfigurationReadinessProvider(
	node *SingleNode,
	raftTransport RaftTransport,
	now func() time.Time,
) ConfigurationReadinessProvider {
	reachability, ok := raftTransport.(consensusPeerReachability)
	if node == nil || !ok || reachability == nil || now == nil {
		return nil
	}
	return &nodeConfigurationReadinessProvider{
		admissionSnapshot: func() (*peerauth.Snapshot, error) {
			return currentNodeAdmissionSnapshot(node)
		},
		localDeviceID: domain.DeviceID(node.serverID),
		localReachable: func() bool {
			return node.raft != nil &&
				node.raft.State() != raft.Shutdown &&
				node.FatalError() == nil
		},
		reachability: reachability,
		now:          now,
	}
}

func (provider *nodeConfigurationReadinessProvider) CollectConfigurationReadiness(
	ctx context.Context,
	requirement ConfigurationReadinessRequirement,
) (ConfigurationReadinessCandidate, error) {
	if provider == nil ||
		provider.admissionSnapshot == nil ||
		!provider.localDeviceID.Valid() ||
		provider.localReachable == nil ||
		provider.reachability == nil ||
		provider.now == nil ||
		ctx == nil ||
		requirement.validate() != nil {
		return ConfigurationReadinessCandidate{},
			ErrConfigurationReadinessUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ConfigurationReadinessCandidate{}, err
	}
	admission, err := provider.admissionSnapshot()
	if err != nil {
		return ConfigurationReadinessCandidate{}, err
	}
	if !configurationReadinessLineageMatches(admission, requirement) {
		return ConfigurationReadinessCandidate{},
			ErrConfigurationReadinessChanged
	}
	at := provider.now()
	if at.IsZero() {
		return ConfigurationReadinessCandidate{},
			ErrConfigurationReadinessUnavailable
	}

	credentialTokens := make([]configurationCredentialToken, 0, len(requirement.ActiveDeviceIDs))
	credentialed := make([]domain.DeviceID, 0, len(requirement.ActiveDeviceIDs))
	for _, id := range requirement.ActiveDeviceIDs {
		authorization, found := admission.ActiveCredentialAuthorizationAt(id, at)
		if !found {
			continue
		}
		credentialTokens = append(credentialTokens, configurationCredentialToken{
			deviceID:                id,
			epoch:                   authorization.Epoch,
			authorizationChainIndex: authorization.AuthorizationChainIndex,
			keyDigest:               authorization.KeyDigest,
		})
		credentialed = append(credentialed, id)
	}

	reachabilityTokens, err := provider.collectReachability(
		ctx,
		requirement.ActiveDeviceIDs,
	)
	if err != nil {
		return ConfigurationReadinessCandidate{}, err
	}
	reachable := make([]domain.DeviceID, len(reachabilityTokens))
	for index, token := range reachabilityTokens {
		reachable[index] = token.DeviceID
	}
	encoded, err := encodeConfigurationReadinessToken(
		configurationReadinessToken{
			reachability: reachabilityTokens,
			credentials:  credentialTokens,
		},
	)
	if err != nil {
		return ConfigurationReadinessCandidate{},
			ErrInvalidConfigurationReadiness
	}
	return ConfigurationReadinessCandidate{
		ReachableDeviceIDs:         reachable,
		CurrentCredentialDeviceIDs: credentialed,
		Token:                      encoded,
	}, nil
}

func (provider *nodeConfigurationReadinessProvider) VerifyCurrentConfigurationReadiness(
	requirement ConfigurationReadinessRequirement,
	candidate ConfigurationReadinessCandidate,
) error {
	if provider == nil ||
		provider.admissionSnapshot == nil ||
		!provider.localDeviceID.Valid() ||
		provider.localReachable == nil ||
		provider.reachability == nil ||
		provider.now == nil ||
		requirement.validate() != nil {
		return ErrConfigurationReadinessUnavailable
	}
	token, err := decodeConfigurationReadinessToken(candidate.Token)
	if err != nil ||
		!sameDeviceIDs(
			candidate.ReachableDeviceIDs,
			reachabilityTokenDeviceIDs(token.reachability),
		) ||
		!sameDeviceIDs(
			candidate.CurrentCredentialDeviceIDs,
			credentialTokenDeviceIDs(token.credentials),
		) {
		return ErrInvalidConfigurationReadiness
	}
	admission, err := provider.admissionSnapshot()
	if err != nil {
		return err
	}
	if !configurationReadinessLineageMatches(admission, requirement) {
		return ErrConfigurationReadinessChanged
	}
	at := provider.now()
	if at.IsZero() {
		return ErrConfigurationReadinessUnavailable
	}
	currentCredentials := make([]configurationCredentialToken, 0, len(requirement.ActiveDeviceIDs))
	for _, id := range requirement.ActiveDeviceIDs {
		authorization, found := admission.ActiveCredentialAuthorizationAt(id, at)
		if !found {
			continue
		}
		currentCredentials = append(currentCredentials, configurationCredentialToken{
			deviceID:                id,
			epoch:                   authorization.Epoch,
			authorizationChainIndex: authorization.AuthorizationChainIndex,
			keyDigest:               authorization.KeyDigest,
		})
	}
	if !sameConfigurationCredentialTokens(
		token.credentials,
		currentCredentials,
	) {
		return ErrConfigurationReadinessChanged
	}
	for _, reachability := range token.reachability {
		if reachability.DeviceID == provider.localDeviceID {
			if reachability.Generation != 0 ||
				!provider.localReachable() {
				return ErrConfigurationReadinessChanged
			}
			continue
		}
		if reachability.Generation == 0 {
			return ErrInvalidConfigurationReadiness
		}
		if err := provider.reachability.VerifyConsensusPeerReachability(
			reachability,
		); err != nil {
			return ErrConfigurationReadinessChanged
		}
	}
	return nil
}

func (provider *nodeConfigurationReadinessProvider) collectReachability(
	ctx context.Context,
	active []domain.DeviceID,
) ([]transport.ConsensusPeerReachabilityToken, error) {
	localID := provider.localDeviceID
	result := make([]transport.ConsensusPeerReachabilityToken, 0, len(active))
	if containsSortedDeviceID(active, localID) &&
		provider.localReachable() {
		result = append(result, transport.ConsensusPeerReachabilityToken{
			DeviceID: localID,
		})
	}

	type probeResult struct {
		token transport.ConsensusPeerReachabilityToken
		err   error
	}
	probes := make(chan probeResult, len(active))
	var wait sync.WaitGroup
	for _, id := range active {
		if id == localID {
			continue
		}
		wait.Add(1)
		go func(deviceID domain.DeviceID) {
			defer wait.Done()
			probeContext, cancel := context.WithTimeout(
				ctx,
				configurationReadinessProbeTimeout,
			)
			defer cancel()
			token, err := provider.reachability.ProbeConsensusPeer(
				probeContext,
				deviceID,
			)
			probes <- probeResult{token: token, err: err}
		}(id)
	}
	wait.Wait()
	close(probes)
	for probe := range probes {
		if probe.err != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			continue
		}
		if !probe.token.DeviceID.Valid() ||
			probe.token.DeviceID == localID ||
			probe.token.Generation == 0 ||
			!containsSortedDeviceID(active, probe.token.DeviceID) {
			return nil, ErrInvalidConfigurationReadiness
		}
		result = append(result, probe.token)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].DeviceID < result[right].DeviceID
	})
	for index := 1; index < len(result); index++ {
		if result[index-1].DeviceID >= result[index].DeviceID {
			return nil, ErrInvalidConfigurationReadiness
		}
	}
	return result, nil
}

func currentNodeAdmissionSnapshot(node *SingleNode) (
	*peerauth.Snapshot,
	error,
) {
	if node == nil ||
		node.fsm == nil ||
		node.state == nil {
		return nil, ErrConfigurationReadinessUnavailable
	}
	if err := node.FatalError(); err != nil {
		return nil, err
	}
	publication := node.fsm.admission.Load()
	if publication == nil ||
		publication.snapshot == nil ||
		publication.revision == 0 ||
		publication.revision != node.state.AdmissionRevision() {
		return nil, ErrConfigurationReadinessChanged
	}
	return publication.snapshot, nil
}

func configurationReadinessLineageMatches(
	admission interface {
		Lineage() (domain.UUIDv7, uint64, bool)
	},
	requirement ConfigurationReadinessRequirement,
) bool {
	if admission == nil {
		return false
	}
	sessionID, generation, valid := admission.Lineage()
	return valid &&
		sessionID == requirement.SessionID &&
		generation == requirement.RecoveryGeneration
}

func encodeConfigurationReadinessToken(
	token configurationReadinessToken,
) ([]byte, error) {
	if len(token.reachability) > 255 ||
		len(token.credentials) > 255 ||
		!sortedReachabilityTokens(token.reachability) ||
		!sortedCredentialTokens(token.credentials) {
		return nil, ErrInvalidConfigurationReadiness
	}
	size := 3 +
		len(token.reachability)*reachabilityTokenBytes +
		len(token.credentials)*credentialTokenBytes
	if size > MaxConfigurationReadinessTokenBytes {
		return nil, ErrInvalidConfigurationReadiness
	}
	encoded := make([]byte, size)
	encoded[0] = configurationReadinessTokenVersion
	encoded[1] = byte(len(token.reachability))
	encoded[2] = byte(len(token.credentials))
	offset := 3
	for _, value := range token.reachability {
		copy(encoded[offset:offset+deviceIDBytes], value.DeviceID)
		offset += deviceIDBytes
		binary.BigEndian.PutUint64(encoded[offset:offset+8], value.Generation)
		offset += 8
	}
	for _, value := range token.credentials {
		copy(encoded[offset:offset+deviceIDBytes], value.deviceID)
		offset += deviceIDBytes
		binary.BigEndian.PutUint64(encoded[offset:offset+8], value.epoch)
		offset += 8
		binary.BigEndian.PutUint64(
			encoded[offset:offset+8],
			value.authorizationChainIndex,
		)
		offset += 8
		copy(encoded[offset:offset+32], value.keyDigest[:])
		offset += 32
	}
	return encoded, nil
}

func decodeConfigurationReadinessToken(
	encoded []byte,
) (configurationReadinessToken, error) {
	if len(encoded) < 3 ||
		len(encoded) > MaxConfigurationReadinessTokenBytes ||
		encoded[0] != configurationReadinessTokenVersion {
		return configurationReadinessToken{},
			ErrInvalidConfigurationReadiness
	}
	reachabilityCount := int(encoded[1])
	credentialCount := int(encoded[2])
	expected := 3 +
		reachabilityCount*reachabilityTokenBytes +
		credentialCount*credentialTokenBytes
	if len(encoded) != expected {
		return configurationReadinessToken{},
			ErrInvalidConfigurationReadiness
	}
	token := configurationReadinessToken{
		reachability: make(
			[]transport.ConsensusPeerReachabilityToken,
			reachabilityCount,
		),
		credentials: make(
			[]configurationCredentialToken,
			credentialCount,
		),
	}
	offset := 3
	for index := range token.reachability {
		token.reachability[index].DeviceID = domain.DeviceID(
			string(encoded[offset : offset+deviceIDBytes]),
		)
		offset += deviceIDBytes
		token.reachability[index].Generation = binary.BigEndian.Uint64(
			encoded[offset : offset+8],
		)
		offset += 8
	}
	for index := range token.credentials {
		value := &token.credentials[index]
		value.deviceID = domain.DeviceID(
			string(encoded[offset : offset+deviceIDBytes]),
		)
		offset += deviceIDBytes
		value.epoch = binary.BigEndian.Uint64(encoded[offset : offset+8])
		offset += 8
		value.authorizationChainIndex = binary.BigEndian.Uint64(
			encoded[offset : offset+8],
		)
		offset += 8
		copy(value.keyDigest[:], encoded[offset:offset+32])
		offset += 32
	}
	if !sortedReachabilityTokens(token.reachability) ||
		!sortedCredentialTokens(token.credentials) {
		return configurationReadinessToken{},
			ErrInvalidConfigurationReadiness
	}
	return token, nil
}

func sortedReachabilityTokens(
	values []transport.ConsensusPeerReachabilityToken,
) bool {
	var previous domain.DeviceID
	for index, value := range values {
		if !value.DeviceID.Valid() ||
			index > 0 && previous >= value.DeviceID {
			return false
		}
		previous = value.DeviceID
	}
	return true
}

func sortedCredentialTokens(values []configurationCredentialToken) bool {
	var previous domain.DeviceID
	for index, value := range values {
		if !value.deviceID.Valid() ||
			value.epoch < 1 ||
			!domain.ValidUnsignedInteger(value.epoch) ||
			value.authorizationChainIndex < 1 ||
			!domain.ValidUnsignedInteger(value.authorizationChainIndex) ||
			index > 0 && previous >= value.deviceID {
			return false
		}
		previous = value.deviceID
	}
	return true
}

func sameConfigurationCredentialTokens(
	left []configurationCredentialToken,
	right []configurationCredentialToken,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].deviceID != right[index].deviceID ||
			left[index].epoch != right[index].epoch ||
			left[index].authorizationChainIndex !=
				right[index].authorizationChainIndex ||
			!bytes.Equal(
				left[index].keyDigest[:],
				right[index].keyDigest[:],
			) {
			return false
		}
	}
	return true
}

func reachabilityTokenDeviceIDs(
	values []transport.ConsensusPeerReachabilityToken,
) []domain.DeviceID {
	result := make([]domain.DeviceID, len(values))
	for index, value := range values {
		result[index] = value.DeviceID
	}
	return result
}

func credentialTokenDeviceIDs(
	values []configurationCredentialToken,
) []domain.DeviceID {
	result := make([]domain.DeviceID, len(values))
	for index, value := range values {
		result[index] = value.deviceID
	}
	return result
}

var _ ConfigurationReadinessProvider = (*nodeConfigurationReadinessProvider)(nil)
