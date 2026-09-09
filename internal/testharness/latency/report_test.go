package latency

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestSummarizeUsesNearestRankAndPreservesRawOrder(t *testing.T) {
	samples := make([]time.Duration, 20)
	for index := range samples {
		samples[index] = time.Duration(20-index) * time.Millisecond
	}
	report, err := Summarize(samples)
	if err != nil {
		t.Fatalf("Summarize(): %v", err)
	}
	wantRaw := make([]int64, len(samples))
	for index, sample := range samples {
		wantRaw[index] = sample.Nanoseconds()
	}
	if !slices.Equal(report.SampleNanos, wantRaw) ||
		report.P95() != 19*time.Millisecond ||
		report.Max() != 20*time.Millisecond {
		t.Fatalf("report = %#v", report)
	}
}

func TestSummarizeRejectsMissingOrNegativeSamples(t *testing.T) {
	for name, samples := range map[string][]time.Duration{
		"missing":  nil,
		"negative": {time.Millisecond, -time.Nanosecond},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Summarize(samples); !errors.Is(
				err,
				ErrInvalidSamples,
			) {
				t.Fatalf("Summarize() error = %v", err)
			}
		})
	}
}
