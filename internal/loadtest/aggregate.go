// Agrega las repeticiones del load test en medianas y rangos.
package loadtest

import "time"

type RepetitionSummary struct {
	Requests      int
	Errors        int
	ErrorRate     float64
	ThroughputRPS float64
	P50, P95, P99 time.Duration
}

func summarizeRepetition(r RunResult) RepetitionSummary {
	return RepetitionSummary{
		Requests: r.Requests, Errors: r.Errors, ErrorRate: r.ErrorRate(),
		ThroughputRPS: r.Throughput(),
		P50:           r.P50(), P95: r.P95(), P99: r.P99(),
	}
}

type AggregatedResult struct {
	Repetitions int

	Requests  int
	Errors    int
	ErrorRate float64

	ThroughputMedian float64
	ThroughputMin    float64
	ThroughputMax    float64

	P50 time.Duration
	P95 time.Duration
	P99 time.Duration

	PerRepetition []RepetitionSummary
}

func Aggregate(reps []RunResult) AggregatedResult {
	if len(reps) == 0 {
		return AggregatedResult{}
	}

	agg := AggregatedResult{Repetitions: len(reps)}

	throughputs := make([]float64, len(reps))
	p50s := make([]time.Duration, len(reps))
	p95s := make([]time.Duration, len(reps))
	p99s := make([]time.Duration, len(reps))
	agg.PerRepetition = make([]RepetitionSummary, len(reps))

	for i, r := range reps {
		throughputs[i] = r.Throughput()
		p50s[i] = r.P50()
		p95s[i] = r.P95()
		p99s[i] = r.P99()

		agg.Requests += r.Requests
		agg.Errors += r.Errors
		agg.PerRepetition[i] = summarizeRepetition(r)
	}

	agg.ThroughputMedian = medianFloat(throughputs)
	agg.ThroughputMin, agg.ThroughputMax = minMaxFloat(throughputs)

	if agg.Requests > 0 {
		agg.ErrorRate = float64(agg.Errors) / float64(agg.Requests)
	}

	agg.P50 = medianDuration(p50s)
	agg.P95 = medianDuration(p95s)
	agg.P99 = medianDuration(p99s)

	return agg
}

func medianFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func medianDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(values))
	copy(sorted, values)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func minMaxFloat(values []float64) (min, max float64) {
	if len(values) == 0 {
		return 0, 0
	}
	min, max = values[0], values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max
}
