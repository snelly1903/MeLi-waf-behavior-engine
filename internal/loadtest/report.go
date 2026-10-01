// Exporta los resultados del load test a CSV y JSON.
package loadtest

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

type CombinationResult struct {
	Profile     string
	Concurrency int
	OTelEnabled bool

	PairedOTelComparison bool

	Aggregated AggregatedResult

	CombinedProcessAllocDeltaBytes int64
}

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
