package loadtest

import "time"

// RepetitionSummary es el resultado crudo de UNA repetición,
// resumido para reportarlo: se conservan también los resultados
// crudos por repetición, nunca solo el agregado. Requests/Errors/
// Throughput/percentiles se calculan SOLO sobre las muestras de ESA
// repetición, nunca mezclados con las otras.
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

// AggregatedResult resume 3 repeticiones independientes de la MISMA
// combinación (perfil x concurrencia x modo OTel): cada repetición
// corre con decider/servidor frescos, nunca comparten estado. El
// throughput se reporta como mediana + rango (min/max) entre las 3
// repeticiones — nunca un promedio simple, que escondería cuánto
// varió una corrida de otra.
//
// P50/P95/P99 son la MEDIANA de los percentiles calculados POR
// REPETICIÓN: nunca se mezclan las muestras crudas de las 3
// repeticiones en un pool único antes de calcular el percentil,
// porque eso podría ocultar que una repetición concreta tuvo una
// cola mucho peor que las otras dos. PerRepetition conserva el
// resultado crudo de cada una, sin perder esa granularidad.
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

// Aggregate combina reps (una por repetición) en un AggregatedResult.
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
	// Inserción simple: los conjuntos acá son de 3 elementos (una
	// repetición por combinación), sort.Float64s sería overkill pero
	// tampoco incorrecto — se usa igual por claridad, el tamaño es
	// siempre chico.
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

// medianDuration es el equivalente de medianFloat para
// time.Duration — usado para combinar los percentiles YA
// calculados por repetición (ver Aggregate), nunca las muestras
// crudas.
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
