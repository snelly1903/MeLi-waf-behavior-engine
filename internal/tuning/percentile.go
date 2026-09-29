package tuning

import (
	"math"
	"sort"
)

// percentile devuelve el percentil p (0..1) de values, usando el
// método "nearest rank" (el más simple y menos sorprendente para
// reportar percentiles a mano: siempre devuelve un valor REALMENTE
// presente en la muestra, nunca una interpolación entre dos). values
// no se modifica — se ordena una copia. Devuelve 0 si values está
// vacío (el llamador es responsable de no reportar un percentil sin
// muestras como si fuera un dato real — ver PercentileSummary).
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

// PercentileSummary son min/p50/p75/p90/p95/max de un conjunto de
// valores — el resumen mínimo usado para las distribuciones de score.
// N es cuántas muestras tiene la
// distribución: 0 significa que este resumen no tiene ningún dato
// real detrás (nunca se confunde con "todos los valores son cero").
type PercentileSummary struct {
	N   int
	Min float64
	P50 float64
	P75 float64
	P90 float64
	P95 float64
	Max float64
}

// Summarize calcula un PercentileSummary de values. Con values vacío,
// devuelve N=0 y el resto en su cero — quien reporte esto tiene que
// comprobar N antes de mostrar los demás campos como si fueran datos.
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
