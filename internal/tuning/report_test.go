package tuning

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
)

// TestToRows_UndefinedRatiosRenderAsNA cubre la división por cero
// pedida explícitamente en Tests: un run sin ningún positivo real
// (0% malicious) tiene que exportar "N/A" en Recall — nunca "0" ni
// una celda vacía.
func TestToRows_UndefinedRatiosRenderAsNA(t *testing.T) {
	matrix := eval.ConfusionMatrix{TP: 0, FP: 1, FN: 0, TN: 9}
	result := eval.Result{
		Strict: eval.PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()},
		Broad:  eval.PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()},
	}
	rows := ToRows([]RunResult{{Candidate: "baseline", Seed: 1, Ratio: 0, Eval: result}})

	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.StrictRecall != "N/A" {
		t.Errorf("StrictRecall = %q, want %q", r.StrictRecall, "N/A")
	}
	if r.StrictF1 != "N/A" {
		t.Errorf("StrictF1 = %q, want %q (Recall N/A se propaga a F1)", r.StrictF1, "N/A")
	}
	if r.CSEventualDetectionRate != "N/A" {
		t.Errorf("CSEventualDetectionRate = %q, want %q (0 campañas de credential_stuffing)", r.CSEventualDetectionRate, "N/A")
	}
	if r.CSMeanRequestsToDetect != "N/A" {
		t.Errorf("CSMeanRequestsToDetect = %q, want %q", r.CSMeanRequestsToDetect, "N/A")
	}
}

// TestToRows_DefinedValuesRenderAsNumbers es el espejo del anterior:
// cuando SÍ hay datos, las celdas tienen que ser números, no "N/A".
func TestToRows_DefinedValuesRenderAsNumbers(t *testing.T) {
	matrix := eval.ConfusionMatrix{TP: 3, FP: 1, FN: 2, TN: 4}
	result := eval.Result{
		Strict: eval.PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()},
		Broad:  eval.PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()},
	}
	rows := ToRows([]RunResult{{Candidate: "baseline", Seed: 1, Ratio: 30, Eval: result}})
	r := rows[0]
	if r.StrictPrecision == "N/A" {
		t.Error("StrictPrecision = N/A, want un número (hay TP y FP)")
	}
	if r.StrictF1 == "N/A" {
		t.Error("StrictF1 = N/A, want un número")
	}
}

func TestWriteCSV_RoundTrips(t *testing.T) {
	matrix := eval.ConfusionMatrix{TP: 1, FP: 0, FN: 0, TN: 1}
	rows := ToRows([]RunResult{
		{Candidate: "baseline", Seed: 101, Ratio: 10, Eval: eval.Result{
			Strict: eval.PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()},
			Broad:  eval.PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()},
		}},
	})

	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, rows); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("reading csv: %v", err)
	}
	if len(records) != 2 { // header + 1 fila
		t.Fatalf("records = %d, want 2 (header + 1 fila)", len(records))
	}
	if records[0][0] != "candidate" {
		t.Errorf("primer encabezado = %q, want %q", records[0][0], "candidate")
	}
	if records[1][0] != "baseline" {
		t.Errorf("primera celda de datos = %q, want %q", records[1][0], "baseline")
	}
}

func TestWriteJSON_RoundTrips(t *testing.T) {
	matrix := eval.ConfusionMatrix{TP: 1, FP: 0, FN: 0, TN: 1}
	rows := ToRows([]RunResult{
		{Candidate: "baseline", Seed: 101, Ratio: 10, Eval: eval.Result{
			Strict: eval.PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()},
			Broad:  eval.PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()},
		}},
	})

	path := filepath.Join(t.TempDir(), "out.json")
	if err := WriteJSON(path, rows); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var decoded []Row
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if len(decoded) != 1 || decoded[0].Candidate != "baseline" || decoded[0].Seed != 101 {
		t.Errorf("decoded = %+v, want un Row con Candidate=baseline Seed=101", decoded)
	}
}

// TestRenderMarkdown_GroupsByCandidateAndRatio confirma que el
// resumen agrupa correctamente varios seeds de la misma ratio bajo un
// solo encabezado — la base de la sección de "estabilidad entre
// seeds".
func TestRenderMarkdown_GroupsByCandidateAndRatio(t *testing.T) {
	matrix := eval.ConfusionMatrix{TP: 1, FP: 0, FN: 0, TN: 1}
	er := eval.Result{
		Strict: eval.PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()},
		Broad:  eval.PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()},
	}
	results := []RunResult{
		{Candidate: "baseline", Seed: 101, Ratio: 10, Eval: er},
		{Candidate: "baseline", Seed: 102, Ratio: 10, Eval: er},
		{Candidate: "baseline", Seed: 101, Ratio: 30, Eval: er},
	}

	md := RenderMarkdown(results)
	if !strings.Contains(md, "baseline — 10% malicious") {
		t.Error("el reporte no agrupó los dos seeds de 10% bajo un encabezado común")
	}
	if !strings.Contains(md, "baseline — 30% malicious") {
		t.Error("el reporte no incluyó la sección de 30%")
	}
}
