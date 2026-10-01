// Ejecuta la calibración offline del motor sobre los escenarios de tuning y exporta los reportes.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/baseline"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/tuning"
)

func main() {
	seedsFlag := flag.String("seeds", "101,102,103", "semillas separadas por coma — réplicas del mismo diseño de escenario, para medir estabilidad")
	ratiosFlag := flag.String("ratios", "0,10,30", "porcentajes de tráfico malicioso separados por coma")
	dataDir := flag.String("data-dir", "data/tuning", "carpeta base donde generar/reutilizar los escenarios (dentro de data/, ya en .gitignore)")
	out := flag.String("out", "reports/tuning/baseline", "prefijo de salida — se escriben <out>.md, <out>.csv y <out>.json")
	flag.Parse()

	seeds, err := parseUint64List(*seedsFlag)
	if err != nil {
		log.Fatalf("tune: --seeds inválido: %v", err)
	}
	ratios, err := parseIntList(*ratiosFlag)
	if err != nil {
		log.Fatalf("tune: --ratios inválido: %v", err)
	}

	candidate := tuning.BaselineCandidate()
	resolver := datagen.NewSimulatedASNResolver()

	var results []tuning.RunResult
	for _, seed := range seeds {
		for _, ratio := range ratios {
			cfg := datagen.DefaultScenarioConfig(seed, float64(ratio)/100)
			scenario := datagen.BuildScenario(cfg)

			scenarioDir := filepath.Join(*dataDir, fmt.Sprintf("seed-%d", seed), fmt.Sprintf("scenario-%d", ratio))
			if err := datagen.WriteScenario(scenarioDir, scenario); err != nil {
				log.Fatalf("tune: escribiendo %s: %v", scenarioDir, err)
			}

			result, err := tuning.RunScenario(scenario, candidate, resolver)
			if err != nil {
				log.Fatalf("tune: corriendo %q sobre %s: %v", candidate.Name, scenarioDir, err)
			}
			results = append(results, result)

			decisionsPath := filepath.Join(scenarioDir, fmt.Sprintf("decisions-%s.jsonl", candidate.Name))
			if err := baseline.WriteDecisions(decisionsPath, result.Decisions); err != nil {
				log.Fatalf("tune: escribiendo %s: %v", decisionsPath, err)
			}

			if !result.Eval.Issues.Clean() {
				log.Printf("tune: ADVERTENCIA — %s tiene problemas de integridad de datos: %+v", scenarioDir, result.Eval.Issues)
			}
			log.Printf("tune: %s seed=%d ratio=%d%% — %d eventos, %d cruzados, strict TP/FP/FN/TN=%d/%d/%d/%d broad=%d/%d/%d/%d",
				candidate.Name, seed, ratio, scenario.Stats.TotalEvents, result.Eval.TotalJoined,
				result.Eval.Strict.Matrix.TP, result.Eval.Strict.Matrix.FP, result.Eval.Strict.Matrix.FN, result.Eval.Strict.Matrix.TN,
				result.Eval.Broad.Matrix.TP, result.Eval.Broad.Matrix.FP, result.Eval.Broad.Matrix.FN, result.Eval.Broad.Matrix.TN,
			)
		}
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		log.Fatalf("tune: creando carpeta de salida: %v", err)
	}

	rows := tuning.ToRows(results)
	if err := tuning.WriteCSV(*out+".csv", rows); err != nil {
		log.Fatalf("tune: %v", err)
	}
	if err := tuning.WriteJSON(*out+".json", rows); err != nil {
		log.Fatalf("tune: %v", err)
	}
	if err := os.WriteFile(*out+".md", []byte(tuning.RenderMarkdown(results)), 0o644); err != nil {
		log.Fatalf("tune: %v", err)
	}

	log.Printf("tune: reporte escrito en %s.{md,csv,json} (%d filas: %d seeds x %d ratios)", *out, len(rows), len(seeds), len(ratios))
}

func parseUint64List(s string) ([]uint64, error) {
	var result []uint64
	for _, part := range strings.Split(s, ",") {
		v, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, nil
}

func parseIntList(s string) ([]int, error) {
	var result []int
	for _, part := range strings.Split(s, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		if v != 0 && v != 10 && v != 30 {
			return nil, fmt.Errorf("ratio %d inválido (debe ser 0, 10 o 30)", v)
		}
		result = append(result, v)
	}
	return result, nil
}
