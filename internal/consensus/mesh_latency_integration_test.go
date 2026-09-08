package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	secureMeshLeaderReplacementChild = "leader-replacement-latency"
	phase3PerformanceEnvironment     = "CODECOMM_PHASE3_PERFORMANCE"
	leaderReplacementSampleCount     = 20
	leaderReplacementTarget          = 5 * time.Second
)

type leaderReplacementReport struct {
	SampleMillis []int64 `json:"sample_millis"`
	P95Millis    int64   `json:"p95_millis"`
	MaxMillis    int64   `json:"max_millis"`
}

func TestSecureMeshLeaderReplacementLatency(t *testing.T) {
	if os.Getenv(phase3PerformanceEnvironment) != "1" {
		t.Skip("set CODECOMM_PHASE3_PERFORMANCE=1 to run the leader-replacement gate")
	}
	if secureMeshRunsInProcess() ||
		os.Getenv(secureMeshChild) == secureMeshLeaderReplacementChild {
		runSecureMeshLeaderReplacementLatency(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestSecureMeshLeaderReplacementLatency$",
		"-test.count=1",
		"-test.v",
	)
	command.Env = secureMeshChildEnvironmentWithMode(
		os.Environ(),
		secureMeshLeaderReplacementChild,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf(
			"leader-replacement mesh child timed out: %v\n%s",
			ctx.Err(),
			output,
		)
	}
	if err != nil {
		t.Fatalf(
			"leader-replacement mesh child failed: %v\n%s",
			err,
			output,
		)
	}
	t.Logf("%s", output)
}

func runSecureMeshLeaderReplacementLatency(t *testing.T) {
	harness := newSecureMeshHarness(t)
	defer harness.close(t)

	nodes := harness.runningNodes()
	harness.waitForCommittedConfiguration(t, nodes)
	harness.waitForLeader(t, nodes)

	samples := make([]time.Duration, 0, leaderReplacementSampleCount)
	for index := 0; index < leaderReplacementSampleCount; index++ {
		leader := harness.waitForLeader(t, harness.runningNodes())
		majority := secureMeshNodesExcept(harness.runningNodes(), leader)
		if len(majority) != 2 {
			t.Fatalf("replacement majority = %d, want 2", len(majority))
		}

		started := time.Now()
		// Cut every established link before shutdown so the old leader cannot
		// transfer leadership; the surviving voters observe an abrupt loss.
		if closed := harness.topology.setPartition(
			leader.identity.deviceID,
			true,
		); closed == 0 {
			t.Fatalf("sample %d severed no established leader link", index+1)
		}
		harness.stopNode(t, leader)
		replacement := harness.waitForLeader(t, majority)
		eventID := leaderReplacementUUID(0x100 + uint64(index))
		taskID := leaderReplacementUUID(0x200 + uint64(index))
		signed := harness.taskEvent(
			t,
			replacement,
			eventID,
			taskID,
			domain.Timestamp(
				time.Date(
					2026,
					time.September,
					8,
					12,
					0,
					index,
					0,
					time.UTC,
				).Format(time.RFC3339),
			),
			fmt.Sprintf("leader replacement sample %02d", index+1),
		)
		result, err := replacement.node.Apply(meshTestContext(t), signed)
		if err != nil {
			t.Fatalf("sample %d replacement Apply(): %v", index+1, err)
		}
		if result.Duplicate ||
			result.Outcome.Status != store.OutcomeAccepted {
			t.Fatalf(
				"sample %d replacement result = %#v",
				index+1,
				result,
			)
		}
		samples = append(samples, time.Since(started))

		harness.startNode(t, leader, false)
		harness.topology.setPartition(leader.identity.deviceID, false)
		harness.waitForTask(t, harness.runningNodes(), taskID)
		harness.waitForLeader(t, harness.runningNodes())
		assertMeshViewsConverged(t, harness.runningNodes())
	}

	report := summarizeLeaderReplacement(samples)
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode leader-replacement report: %v", err)
	}
	t.Logf("CODECOMM_PHASE3_LEADER_REPLACEMENT=%s", encoded)
	if time.Duration(report.P95Millis)*time.Millisecond >=
		leaderReplacementTarget {
		t.Fatalf(
			"leader replacement p95 = %dms, target <%s",
			report.P95Millis,
			leaderReplacementTarget,
		)
	}
}

func TestSummarizeLeaderReplacementUsesNearestRank(t *testing.T) {
	samples := make([]time.Duration, leaderReplacementSampleCount)
	for index := range samples {
		samples[index] = time.Duration(index+1) * time.Millisecond
	}
	report := summarizeLeaderReplacement(samples)
	if len(report.SampleMillis) != leaderReplacementSampleCount ||
		report.P95Millis != 19 ||
		report.MaxMillis != 20 {
		t.Fatalf("leader replacement report = %#v", report)
	}
}

func secureMeshNodesExcept(
	nodes []*secureMeshNode,
	excluded *secureMeshNode,
) []*secureMeshNode {
	result := make([]*secureMeshNode, 0, len(nodes)-1)
	for _, candidate := range nodes {
		if candidate != excluded {
			result = append(result, candidate)
		}
	}
	return result
}

func summarizeLeaderReplacement(
	samples []time.Duration,
) leaderReplacementReport {
	millis := make([]int64, len(samples))
	for index, sample := range samples {
		millis[index] = sample.Milliseconds()
	}
	sort.Slice(millis, func(left, right int) bool {
		return millis[left] < millis[right]
	})
	if len(millis) == 0 {
		return leaderReplacementReport{}
	}
	p95Index := (95*len(millis)+99)/100 - 1
	return leaderReplacementReport{
		SampleMillis: millis,
		P95Millis:    millis[p95Index],
		MaxMillis:    millis[len(millis)-1],
	}
}

func leaderReplacementUUID(sequence uint64) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf(
		"019b17cc-0008-7def-b456-%012x",
		sequence,
	))
}
