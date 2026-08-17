package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

type raftConfigurationWire struct {
	Servers []raftServerWire `json:"servers"`
}

type raftServerWire struct {
	Address  string `json:"address"`
	ID       string `json:"id"`
	Suffrage string `json:"suffrage"`
}

type committedRaftConfiguration struct {
	Index         uint64
	Configuration raft.Configuration
}

func (configuration committedRaftConfiguration) contains(
	deviceID domain.DeviceID,
) bool {
	if !deviceID.Valid() {
		return false
	}
	for _, server := range configuration.Configuration.Servers {
		if server.ID == raft.ServerID(deviceID) &&
			server.Address == raft.ServerAddress(deviceID) {
			return true
		}
	}
	return false
}

func encodeRaftConfiguration(
	configuration raft.Configuration,
) ([]byte, error) {
	wire := raftConfigurationWire{
		Servers: make([]raftServerWire, len(configuration.Servers)),
	}
	for index, server := range configuration.Servers {
		var suffrage string
		switch server.Suffrage {
		case raft.Voter:
			suffrage = "voter"
		case raft.Nonvoter:
			suffrage = "nonvoter"
		default:
			return nil, ErrInvalidRaftTopology
		}
		wire.Servers[index] = raftServerWire{
			Address:  string(server.Address),
			ID:       string(server.ID),
			Suffrage: suffrage,
		}
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("consensus: encode Raft configuration: %w", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil || len(canonical) > store.MaxRaftConfigurationBytes {
		return nil, ErrInvalidRaftTopology
	}
	return canonical, nil
}

func decodeRaftConfigurationJSON(
	encoded []byte,
) (raft.Configuration, error) {
	if len(encoded) == 0 ||
		len(encoded) > store.MaxRaftConfigurationBytes {
		return raft.Configuration{}, ErrInvalidRaftTopology
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return raft.Configuration{}, ErrInvalidRaftTopology
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire raftConfigurationWire
	if err := decoder.Decode(&wire); err != nil {
		return raft.Configuration{}, ErrInvalidRaftTopology
	}
	if err := requireJSONEOF(decoder); err != nil {
		return raft.Configuration{}, ErrInvalidRaftTopology
	}
	configuration := raft.Configuration{
		Servers: make([]raft.Server, len(wire.Servers)),
	}
	for index, server := range wire.Servers {
		var suffrage raft.ServerSuffrage
		switch server.Suffrage {
		case "voter":
			suffrage = raft.Voter
		case "nonvoter":
			suffrage = raft.Nonvoter
		default:
			return raft.Configuration{}, ErrInvalidRaftTopology
		}
		configuration.Servers[index] = raft.Server{
			Suffrage: suffrage,
			ID:       raft.ServerID(server.ID),
			Address:  raft.ServerAddress(server.Address),
		}
	}
	return configuration, nil
}

func cloneCommittedRaftConfiguration(
	value *committedRaftConfiguration,
) *committedRaftConfiguration {
	if value == nil {
		return nil
	}
	clone := *value
	clone.Configuration = value.Configuration.Clone()
	return &clone
}

func verifyCommittedConfigurationEvidence(
	ctx context.Context,
	logs raft.LogStore,
	snapshots raft.SnapshotStore,
	state *store.Store,
) error {
	if ctx == nil || logs == nil || snapshots == nil || state == nil {
		return ErrRaftLogCoverage
	}
	record, found, err := state.CommittedRaftConfiguration(ctx)
	if err != nil {
		return fmt.Errorf(
			"%w: load committed configuration evidence: %v",
			ErrRaftLogCoverage,
			err,
		)
	}
	if !found {
		return nil
	}
	var entry raft.Log
	err = logs.GetLog(record.LogIndex, &entry)
	if err == nil {
		if entry.Type != raft.LogConfiguration {
			return fmt.Errorf(
				"%w: configuration evidence index %d has log type %d",
				ErrRaftLogCoverage,
				record.LogIndex,
				entry.Type,
			)
		}
		configuration, decodeErr := decodeRaftConfiguration(entry.Data)
		if decodeErr != nil {
			return fmt.Errorf(
				"%w: decode configuration evidence at %d: %v",
				ErrRaftLogCoverage,
				record.LogIndex,
				decodeErr,
			)
		}
		return compareCommittedConfigurationEvidence(record, configuration)
	}
	if !errors.Is(err, raft.ErrLogNotFound) {
		return fmt.Errorf(
			"%w: read configuration evidence at %d: %v",
			ErrRaftLogCoverage,
			record.LogIndex,
			err,
		)
	}
	metas, err := snapshots.List()
	if err != nil {
		return fmt.Errorf(
			"%w: list configuration snapshot evidence: %v",
			ErrRaftLogCoverage,
			err,
		)
	}
	for _, meta := range metas {
		if meta != nil && meta.ConfigurationIndex == record.LogIndex {
			return compareCommittedConfigurationEvidence(
				record,
				meta.Configuration,
			)
		}
	}
	return fmt.Errorf(
		"%w: configuration evidence index %d is absent from log and snapshots",
		ErrRaftLogCoverage,
		record.LogIndex,
	)
}

func compareCommittedConfigurationEvidence(
	record store.RaftConfigurationRecord,
	configuration raft.Configuration,
) error {
	encoded, err := encodeRaftConfiguration(configuration)
	if err != nil || !bytes.Equal(encoded, record.ConfigurationJSON) {
		return fmt.Errorf(
			"%w: committed configuration evidence mismatch at %d",
			ErrRaftLogCoverage,
			record.LogIndex,
		)
	}
	return nil
}
