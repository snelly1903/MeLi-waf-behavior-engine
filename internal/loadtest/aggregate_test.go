// Prueba la agregación de repeticiones y el cálculo de percentiles.
package loadtest

import (
	"testing"
	"time"
)

func TestPercentile_NearestRank(t *testing.T) {
	values := []time.Duration{
		10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond,
		40 * time.Millisecond, 50 * time.Millisecond, 60 * time.Millisecond,
		70 * time.Millisecond, 80 * time.Millisecond, 90 * time.Millisecond, 100 * time.Millisecond,
	}
	if got := percentile(values, 50); got != 50*time.Millisecond {
		t.Errorf("p50 = %v, want 50ms", got)
	}
	if got := percentile(values, 95); got != 90*time.Millisecond {
		t.Errorf("p95 = %v, want 90ms (nearest-rank truncado con N=10: index int(0.95*10)-1=8)", got)
	}
	if got := percentile(nil, 50); got != 0 {
		t.Errorf("percentile(nil) = %v, want 0", got)
	}
}

func TestAggregate_ThroughputIsMedianAndRange_NeverMean(t *testing.T) {
	reps := []RunResult{
		{Requests: 100, ActualDuration: 10 * time.Second},
		{Requests: 100, ActualDuration: 10 * time.Second},
		{Requests: 1000, ActualDuration: 10 * time.Second},
	}
	agg := Aggregate(reps)

	if agg.ThroughputMedian != 10 {
		t.Errorf("ThroughputMedian = %v, want 10 (mediana de {10,10,100}, nunca el promedio 40)", agg.ThroughputMedian)
	}
	if agg.ThroughputMin != 10 || agg.ThroughputMax != 100 {
		t.Errorf("Min/Max = %v/%v, want 10/100", agg.ThroughputMin, agg.ThroughputMax)
	}
}

func TestAggregate_PercentilesAreMedianOfPerRunPercentiles_NeverPooled(t *testing.T) {
	reps := []RunResult{
		{Requests: 2, Latencies: []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}, ActualDuration: time.Second},
		{Requests: 2, Latencies: []time.Duration{20 * time.Millisecond, 20 * time.Millisecond}, ActualDuration: time.Second},
	}
	agg := Aggregate(reps)
	if agg.Requests != 4 {
		t.Errorf("Requests = %d, want 4 (suma cruda entre las 2 repeticiones)", agg.Requests)
	}

	if agg.P50 != 15*time.Millisecond {
		t.Errorf("P50 = %v, want 15ms (mediana de los P50 por repetición [10ms,20ms], nunca 10ms pooled)", agg.P50)
	}
}

func TestAggregate_PreservesRawPerRepetitionResults(t *testing.T) {
	reps := []RunResult{
		{Requests: 5, Errors: 1, Latencies: []time.Duration{10 * time.Millisecond}, ActualDuration: time.Second},
		{Requests: 7, Errors: 0, Latencies: []time.Duration{20 * time.Millisecond}, ActualDuration: time.Second},
	}
	agg := Aggregate(reps)
	if len(agg.PerRepetition) != 2 {
		t.Fatalf("len(PerRepetition) = %d, want 2 (una entrada cruda por repetición)", len(agg.PerRepetition))
	}
	if agg.PerRepetition[0].Requests != 5 || agg.PerRepetition[0].Errors != 1 {
		t.Errorf("PerRepetition[0] = %+v, want Requests=5 Errors=1", agg.PerRepetition[0])
	}
	if agg.PerRepetition[1].Requests != 7 || agg.PerRepetition[1].Errors != 0 {
		t.Errorf("PerRepetition[1] = %+v, want Requests=7 Errors=0", agg.PerRepetition[1])
	}
}

func TestAggregate_Empty_ReturnsZeroValue(t *testing.T) {
	agg := Aggregate(nil)
	if agg.Repetitions != 0 || agg.Requests != 0 || len(agg.PerRepetition) != 0 {
		t.Errorf("Aggregate(nil) = %+v, want zero value", agg)
	}
}
