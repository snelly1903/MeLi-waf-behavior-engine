package loadtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleResults() []CombinationResult {
	return []CombinationResult{
		{
			Profile: "mixed", Concurrency: 25, OTelEnabled: false, PairedOTelComparison: true,
			Aggregated: AggregatedResult{
				Repetitions: 2, Requests: 300, Errors: 0, ErrorRate: 0,
				ThroughputMedian: 120.5, ThroughputMin: 110, ThroughputMax: 130,
				P50: 5 * time.Millisecond, P95: 12 * time.Millisecond, P99: 20 * time.Millisecond,
				PerRepetition: []RepetitionSummary{
					{Requests: 150, Errors: 0, ThroughputRPS: 110, P50: 4 * time.Millisecond, P95: 11 * time.Millisecond, P99: 19 * time.Millisecond},
					{Requests: 150, Errors: 0, ThroughputRPS: 130, P50: 6 * time.Millisecond, P95: 13 * time.Millisecond, P99: 21 * time.Millisecond},
				},
			},
			CombinedProcessAllocDeltaBytes: 1024,
		},
	}
}

func TestWriteCSV_RoundTripsHeaderAndData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loadtest.csv")

	if err := WriteCSV(path, sampleResults()); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "profile,concurrency,otel_enabled,paired_otel_comparison") {
		t.Errorf("CSV header inesperado: %q", content)
	}
	if !strings.Contains(content, "mixed,25,false,true,2,300") {
		t.Errorf("CSV no contiene la fila esperada: %q", content)
	}
}

func TestWriteJSON_ValidAndLatenciesInMilliseconds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loadtest.json")

	if err := WriteJSON(path, sampleResults()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if p50, ok := rows[0]["p50_ms"].(float64); !ok || p50 != 5 {
		t.Errorf("p50_ms = %v, want 5 (5ms convertido a milisegundos)", rows[0]["p50_ms"])
	}
	if paired, ok := rows[0]["paired_otel_comparison"].(bool); !ok || !paired {
		t.Errorf("paired_otel_comparison = %v, want true", rows[0]["paired_otel_comparison"])
	}
	detail, ok := rows[0]["repetitions_detail"].([]any)
	if !ok || len(detail) != 2 {
		t.Fatalf("repetitions_detail = %v, want un array de 2 repeticiones crudas", rows[0]["repetitions_detail"])
	}
	first, ok := detail[0].(map[string]any)
	if !ok || first["requests"].(float64) != 150 {
		t.Errorf("repetitions_detail[0] = %v, want requests=150", detail[0])
	}
}
