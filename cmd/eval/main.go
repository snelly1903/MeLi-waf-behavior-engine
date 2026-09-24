// Command eval compara las decisiones de un motor (hoy, siempre
// ficticias — todavía no existe el motor WAF real) contra el ground
// truth de un escenario generado por cmd/datagen, y arma un reporte
// Markdown legible con las métricas del challenge (ver
// docs/decisiones.md, tarea 0.8).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
)

// Códigos de salida: 0 es éxito sin problemas de integridad, 1 es
// "el reporte se generó pero tiene problemas de integridad" (no es un
// error operativo: el comando hizo su trabajo, pero el dato de entrada
// no está completo), y 2 es un error operativo (archivo inexistente,
// fallo al escribir) que impidió generar el reporte.
const (
	exitClean            = 0
	exitIntegrityIssues  = 1
	exitOperationalError = 2
)

func main() {
	scenario := flag.String("scenario", "", "carpeta del escenario con events.jsonl, labels.jsonl y decisions.jsonl")
	out := flag.String("out", "", "ruta del archivo Markdown de salida (si se omite, imprime a stdout)")
	flag.Parse()

	if *scenario == "" {
		log.Fatal("eval: --scenario es obligatorio")
	}

	os.Exit(run(*scenario, *out))
}

func run(scenarioDir, out string) int {
	labelsResult, err := eval.LoadLabels(filepath.Join(scenarioDir, "labels.jsonl"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval: no se pudo cargar labels.jsonl: %v\n", err)
		return exitOperationalError
	}

	decisionsResult, err := eval.LoadDecisions(filepath.Join(scenarioDir, "decisions.jsonl"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval: no se pudo cargar decisions.jsonl: %v\n", err)
		return exitOperationalError
	}

	result := eval.EvaluateDecisions(labelsResult, decisionsResult)

	meta := eval.ReportMeta{
		ScenarioName:    filepath.Base(scenarioDir),
		ExpectedRecords: len(labelsResult.Labels),
	}
	report := eval.RenderMarkdown(result, meta)

	if out == "" {
		fmt.Println(report)
	} else {
		if err := os.WriteFile(out, []byte(report), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "eval: no se pudo escribir el reporte en %s: %v\n", out, err)
			return exitOperationalError
		}
		fmt.Printf("eval: reporte escrito en %s\n", out)
	}

	if !result.Issues.Clean() {
		fmt.Fprintln(os.Stderr, "eval: el reporte tiene problemas de integridad de datos — no es un resultado definitivo")
		return exitIntegrityIssues
	}
	return exitClean
}
