package latency

import (
	"errors"
	"sort"
	"time"
)

var ErrInvalidSamples = errors.New("latency: invalid samples")

// Report preserves raw measurements while exposing the nearest-rank p95.
type Report struct {
	SampleNanos []int64 `json:"sample_nanos"`
	P95Nanos    int64   `json:"p95_nanos"`
	MaxNanos    int64   `json:"max_nanos"`
}

func Summarize(samples []time.Duration) (Report, error) {
	if len(samples) == 0 {
		return Report{}, ErrInvalidSamples
	}
	ordered := make([]time.Duration, len(samples))
	report := Report{SampleNanos: make([]int64, len(samples))}
	for index, sample := range samples {
		if sample < 0 {
			return Report{}, ErrInvalidSamples
		}
		ordered[index] = sample
		report.SampleNanos[index] = sample.Nanoseconds()
	}
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left] < ordered[right]
	})
	p95Index := (95*len(ordered)+99)/100 - 1
	report.P95Nanos = ordered[p95Index].Nanoseconds()
	report.MaxNanos = ordered[len(ordered)-1].Nanoseconds()
	return report, nil
}

func (report Report) P95() time.Duration {
	return time.Duration(report.P95Nanos)
}

func (report Report) Max() time.Duration {
	return time.Duration(report.MaxNanos)
}
