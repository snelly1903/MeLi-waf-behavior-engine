package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLines escribe cada elemento de lines como una línea de path,
// creando el archivo (y su carpeta, si hiciera falta).
func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

// TestRun_EndToEnd_CleanScenario arma a mano un escenario chico (3
// etiquetas, 3 decisiones ficticias que las aciertan todas) y confirma
// que el comando genera un reporte limpio, sin advertencias de
// integridad, con código de salida 0.
func TestRun_EndToEnd_CleanScenario(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "labels.jsonl"), []string{
		`{"request_id":"r-1","label":"legit"}`,
		`{"request_id":"r-2","label":"credential_stuffing"}`,
		`{"request_id":"r-3","label":"slow_scan"}`,
	})
	writeLines(t, filepath.Join(dir, "decisions.jsonl"), []string{
		`{"request_id":"r-1","timestamp":"2026-09-24T10:00:00Z","entity_id":"ip:203.0.113.1","action":"ALLOW","confidence_score":0.05,"attack_vector":"unknown"}`,
		`{"request_id":"r-2","timestamp":"2026-09-24T10:00:05Z","entity_id":"ip:203.0.113.2","action":"BLOCK","confidence_score":0.9,"attack_vector":"credential_stuffing","contributing_signals":[{"name":"fail_ratio","value":0.8,"weight":1}],"explanation":"fail ratio alto"}`,
		`{"request_id":"r-3","timestamp":"2026-09-24T10:00:10Z","entity_id":"ip:203.0.113.3","action":"BLOCK","confidence_score":0.9,"attack_vector":"slow_scan","contributing_signals":[{"name":"path_entropy","value":0.7,"weight":1}],"explanation":"paths muy dispersos"}`,
	})

	outPath := filepath.Join(dir, "report.md")
	code := run(dir, outPath)

	if code != exitClean {
		t.Fatalf("run() exit code = %d, want %d (exitClean)", code, exitClean)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("os.ReadFile(report.md): %v", err)
	}
	report := string(data)
	if strings.Contains(report, "problemas de integridad") {
		t.Error("clean scenario must not produce a report with the integrity warning")
	}
	if !strings.Contains(report, "Registros cruzados: 3 de 3 esperados.") {
		t.Errorf("report does not show 3 of 3 joined records:\n%s", report)
	}
}

// TestRun_EndToEnd_DirtyScenario deja una etiqueta sin decisión (r-4) y
// confirma que el comando igual escribe el reporte, pero con la
// advertencia de integridad y código de salida exitIntegrityIssues —
// nunca un error operativo, porque el comando sí pudo hacer su trabajo.
func TestRun_EndToEnd_DirtyScenario(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "labels.jsonl"), []string{
		`{"request_id":"r-1","label":"legit"}`,
		`{"request_id":"r-4","label":"slow_scan"}`,
	})
	writeLines(t, filepath.Join(dir, "decisions.jsonl"), []string{
		`{"request_id":"r-1","timestamp":"2026-09-24T10:00:00Z","entity_id":"ip:203.0.113.1","action":"ALLOW","confidence_score":0.05,"attack_vector":"unknown"}`,
	})

	outPath := filepath.Join(dir, "report.md")
	code := run(dir, outPath)

	if code != exitIntegrityIssues {
		t.Fatalf("run() exit code = %d, want %d (exitIntegrityIssues)", code, exitIntegrityIssues)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("os.ReadFile(report.md): %v", err)
	}
	report := string(data)
	if !strings.Contains(report, "Decisiones faltantes: r-4") {
		t.Errorf("report does not mention the missing decision for r-4:\n%s", report)
	}
}

// TestRun_MissingScenarioFile confirma que un archivo inexistente es un
// error operativo (exitOperationalError), distinto de un problema de
// integridad del dato.
func TestRun_MissingScenarioFile(t *testing.T) {
	dir := t.TempDir() // vacío: no tiene labels.jsonl ni decisions.jsonl

	code := run(dir, filepath.Join(dir, "report.md"))

	if code != exitOperationalError {
		t.Fatalf("run() exit code = %d, want %d (exitOperationalError)", code, exitOperationalError)
	}
}

// TestRun_StdoutWhenNoOut confirma que omitir --out no falla: el
// reporte simplemente no se escribe a disco (se imprime a stdout desde
// main(), que este test no captura, pero sí puede confirmar el código
// de salida).
func TestRun_StdoutWhenNoOut(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "labels.jsonl"), []string{
		`{"request_id":"r-1","label":"legit"}`,
	})
	writeLines(t, filepath.Join(dir, "decisions.jsonl"), []string{
		`{"request_id":"r-1","timestamp":"2026-09-24T10:00:00Z","entity_id":"ip:203.0.113.1","action":"ALLOW","confidence_score":0.05,"attack_vector":"unknown"}`,
	})

	code := run(dir, "")
	if code != exitClean {
		t.Fatalf("run() exit code = %d, want %d (exitClean)", code, exitClean)
	}
}
