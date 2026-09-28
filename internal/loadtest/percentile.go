package loadtest

import (
	"sort"
	"time"
)

// percentile calcula el percentil p (0-100) de values por el método
// "nearest rank" — mismo criterio simple ya usado en
// internal/tuning.percentile, reimplementado acá en vez de importado
// para no acoplar este paquete de performance a internal/tuning
// (paquetes con propósitos distintos, sin ninguna razón para
// compartir dependencia). Devuelve 0 si values está vacío.
func percentile(values []time.Duration, p float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	rank := int(p/100*float64(len(sorted))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}
