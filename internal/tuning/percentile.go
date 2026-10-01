// Calcula resúmenes de percentiles sobre valores numéricos.
package tuning

import (
	"math"
	"sort"
)

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)

	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

type PercentileSummary struct {
	N   int
	Min float64
	P50 float64
	P75 float64
	P90 float64
	P95 float64
	Max float64
}

func Summarize(values []float64) PercentileSummary {
	if len(values) == 0 {
		return PercentileSummary{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	return PercentileSummary{
		N:   len(sorted),
		Min: sorted[0],
		P50: percentile(sorted, 0.50),
		P75: percentile(sorted, 0.75),
		P90: percentile(sorted, 0.90),
		P95: percentile(sorted, 0.95),
		Max: sorted[len(sorted)-1],
	}
}
