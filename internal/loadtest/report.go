package loadtest

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// CombinationResult es UNA fila del reporte final: una combinación
// (perfil x concurrencia x modo OTel) ya agregada entre sus 3
// repeticiones, más el delta de memoria del proceso COMBINADO
// cliente+servidor (nunca "RAM exclusiva del servidor" — cliente y
// servidor comparten el mismo proceso Go en este harness, ver
// docs/decisiones.md, tarea 1.10).
type CombinationResult struct {
	Profile     string
	Concurrency int
	OTelEnabled bool

	// PairedOTelComparison marca las combinaciones que pertenecen al
	// bloque comparativo OTel ON/OFF pareado (mixed@25 y mixed@100,
	// cada par OFF->ON corrido uno inmediatamente después del otro,
	// cerca en el tiempo — tarea 1.10) — nunca las mismas
	// combinaciones (perfil/concurrencia) que ya corrió la matriz
	// principal, aunque coincidan en Profile/Concurrency/OTelEnabled=false.
	PairedOTelComparison bool

	Aggregated AggregatedResult

	// CombinedProcessAllocDeltaBytes es runtime.MemStats().Alloc
	// después menos antes de esta combinación — SIEMPRE del proceso
	// combinado cliente+servidor (httptest.Server corre en el mismo
	// proceso), nunca memoria exclusiva del servidor.
	CombinedProcessAllocDeltaBytes int64
}

// WriteCSV escribe results en path, una fila por CombinationResult
// (agregado — ver WriteJSON para el detalle crudo por repetición).
func WriteCSV(path string, results []CombinationResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"profile", "concurrency", "otel_enabled", "paired_otel_comparison", "repetitions",
		"requests", "errors", "error_rate",
		"throughput_median_rps", "throughput_min_rps", "throughput_max_rps",
		"p50_ms", "p95_ms", "p99_ms",
		"combined_process_alloc_delta_bytes",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		a := r.Aggregated
		row := []string{
			r.Profile,
			strconv.Itoa(r.Concurrency),
			strconv.FormatBool(r.OTelEnabled),
			strconv.FormatBool(r.PairedOTelComparison),
			strconv.Itoa(a.Repetitions),
			strconv.Itoa(a.Requests),
			strconv.Itoa(a.Errors),
			fmt.Sprintf("%.4f", a.ErrorRate),
			fmt.Sprintf("%.2f", a.ThroughputMedian),
			fmt.Sprintf("%.2f", a.ThroughputMin),
			fmt.Sprintf("%.2f", a.ThroughputMax),
			fmt.Sprintf("%.3f", msOf(a.P50)),
			fmt.Sprintf("%.3f", msOf(a.P95)),
			fmt.Sprintf("%.3f", msOf(a.P99)),
			strconv.FormatInt(r.CombinedProcessAllocDeltaBytes, 10),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func msOf(d interface{ Seconds() float64 }) float64 {
	return d.Seconds() * 1000
}

// WriteJSON escribe results en path como JSON indentado — los mismos
// datos agregados que WriteCSV (latencias ya en milisegundos), MÁS
// el detalle crudo de cada repetición individual
// (`repetitions`, tarea 1.10: "conserva también los resultados
// crudos por repetición") — el CSV, al ser tabular, se queda solo
// con el agregado.
func WriteJSON(path string, results []CombinationResult) error {
	type repetitionJSON struct {
		Requests      int     `json:"requests"`
		Errors        int     `json:"errors"`
		ErrorRate     float64 `json:"error_rate"`
		ThroughputRPS float64 `json:"throughput_rps"`
		P50Ms         float64 `json:"p50_ms"`
		P95Ms         float64 `json:"p95_ms"`
		P99Ms         float64 `json:"p99_ms"`
	}

	type jsonRow struct {
		Profile              string `json:"profile"`
		Concurrency          int    `json:"concurrency"`
		OTelEnabled          bool   `json:"otel_enabled"`
		PairedOTelComparison bool   `json:"paired_otel_comparison"`
		Repetitions          int    `json:"repetitions"`

		Requests  int     `json:"requests"`
		Errors    int     `json:"errors"`
		ErrorRate float64 `json:"error_rate"`

		ThroughputMedianRPS float64 `json:"throughput_median_rps"`
		ThroughputMinRPS    float64 `json:"throughput_min_rps"`
		ThroughputMaxRPS    float64 `json:"throughput_max_rps"`

		// P50Ms/P95Ms/P99Ms son la MEDIANA de los percentiles
		// calculados por repetición (ver AggregatedResult) — nunca
		// pooled sobre todas las muestras juntas.
		P50Ms float64 `json:"p50_ms"`
		P95Ms float64 `json:"p95_ms"`
		P99Ms float64 `json:"p99_ms"`

		CombinedProcessAllocDeltaBytes int64 `json:"combined_process_alloc_delta_bytes"`

		RepetitionDetails []repetitionJSON `json:"repetitions_detail"`
	}

	rows := make([]jsonRow, len(results))
	for i, r := range results {
		a := r.Aggregated
		reps := make([]repetitionJSON, len(a.PerRepetition))
		for j, rep := range a.PerRepetition {
			reps[j] = repetitionJSON{
				Requests: rep.Requests, Errors: rep.Errors, ErrorRate: rep.ErrorRate,
				ThroughputRPS: rep.ThroughputRPS,
				P50Ms:         msOf(rep.P50), P95Ms: msOf(rep.P95), P99Ms: msOf(rep.P99),
			}
		}

		rows[i] = jsonRow{
			Profile: r.Profile, Concurrency: r.Concurrency, OTelEnabled: r.OTelEnabled,
			PairedOTelComparison: r.PairedOTelComparison,
			Repetitions:          a.Repetitions,
			Requests:             a.Requests, Errors: a.Errors, ErrorRate: a.ErrorRate,
			ThroughputMedianRPS: a.ThroughputMedian, ThroughputMinRPS: a.ThroughputMin, ThroughputMaxRPS: a.ThroughputMax,
			P50Ms: msOf(a.P50), P95Ms: msOf(a.P95), P99Ms: msOf(a.P99),
			CombinedProcessAllocDeltaBytes: r.CombinedProcessAllocDeltaBytes,
			RepetitionDetails:              reps,
		}
	}

	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
