package phase3bench

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestCoordinationGrowthWorkloadContract(t *testing.T) {
	contract, err := CoordinationGrowthContractValue()
	if err != nil {
		t.Fatalf("CoordinationGrowthContractValue(): %v", err)
	}
	wantKinds := map[string]int{
		"activity.recorded": 2_500,
		"lease.acquired":    1_000,
		"lease.released":    1_000,
		"lease.renewed":     1_000,
		"task.created":      1_000,
		"task.updated":      3_500,
	}
	wantOutcomes := map[string]int{
		"accepted/accepted":                9_500,
		"rejected/entity_version_mismatch": 500,
	}
	if contract.WorkloadVersion != CoordinationGrowthWorkloadVersion ||
		contract.EventCount != CoordinationGrowthEventCount ||
		contract.AcceptedCount !=
			CoordinationGrowthEventCount/growthBlockSize*growthAcceptedPerBlock ||
		contract.RejectedCount !=
			CoordinationGrowthEventCount/growthBlockSize*growthRejectedPerBlock ||
		contract.TraceSHA256 != CoordinationGrowthTraceSHA256 ||
		contract.LocalRequestBytes != 3_642_500 ||
		contract.SignedEventBytes != 8_882_778 ||
		!reflect.DeepEqual(contract.KindHistogram, wantKinds) ||
		!reflect.DeepEqual(contract.OutcomeHistogram, wantOutcomes) {
		t.Fatalf("coordination growth contract = %#v", contract)
	}
}

func TestMeasureStorageCountsStateSidecarsAndConsensusFiles(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "state.db")
	consensusDir := filepath.Join(root, "consensus")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(consensusDir, "snapshots"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		statePath:          "state",
		statePath + "-wal": "wal-data",
		filepath.Join(filepath.Dir(statePath), "x"):   "ignored",
		filepath.Join(consensusDir, "raft.db"):        "raft-data",
		filepath.Join(consensusDir, "snapshots", "1"): "snapshot",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	measured, err := measureStorage(statePath, consensusDir)
	if err != nil {
		t.Fatalf("measureStorage(): %v", err)
	}
	if measured.StateWAL != int64(len("wal-data")) ||
		measured.StateDB != int64(len("state")) ||
		measured.StateSHM != 0 ||
		measured.Consensus != int64(len("raft-data")+len("snapshot")) ||
		measured.ConsensusFiles != 2 ||
		measured.Total !=
			measured.StateDB+
				measured.StateWAL+
				measured.StateSHM+
				measured.Consensus {
		t.Fatalf("measureStorage() = %#v", measured)
	}
}

func TestGrowthRaftConfigDisablesAutomaticSnapshots(t *testing.T) {
	config := growthRaftConfig()
	if config.SnapshotThreshold != math.MaxUint64 ||
		config.SnapshotInterval < 100*365*24*time.Hour {
		t.Fatalf(
			"automatic snapshots are not disabled: threshold=%d interval=%s",
			config.SnapshotThreshold,
			config.SnapshotInterval,
		)
	}
}

func TestCoordinationGrowthBudget(t *testing.T) {
	if os.Getenv("CODECOMM_PHASE3_PERFORMANCE") != "1" {
		t.Skip("set CODECOMM_PHASE3_PERFORMANCE=1 to run the 10k-event gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	report, err := runCoordinationGrowth(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("runCoordinationGrowth(): %v", err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CODECOMM_PHASE3_COORDINATION_GROWTH=%s", encoded)
	if !report.WithinBudget {
		t.Fatalf(
			"coordination growth = %d bytes, budget %d",
			report.GrowthBytes,
			report.BudgetBytes,
		)
	}
}
