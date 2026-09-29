// Command sweepcombined corre los 4 candidatos combinados (slow_scan
// + statistical_anomaly a la vez) aprobados: C0 baseline, C1
// slow-scan-only, C2 slow-scan+account-weight, C3
// slow-scan+trigger020 — solo sobre tuning (seeds 101/102/103, ratios
// 0/10/30%), nunca holdout. No toca credential_stuffing, ScoreFloor,
// ChallengeThreshold ni BlockThreshold. Ver docs/decisiones.md.
package main

import (
	"log"
	"os"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/tuning"
)

var seeds = []uint64{101, 102, 103}
var ratios = []int{0, 10, 30}

// combinedCandidates: C0 = S0+A0 (baseline puro), C1 = S3+A0
// (solo el fix de slow_scan), C2 = S3+A3 (slow_scan + el peso de
// AccountDiversity), C3 = S3+A2 (slow_scan + TriggerThreshold=0.20).
// S3 es siempre MaxVisitorsForNovelPath=3 + MinNovelPathRatio=0.35.
// credential_stuffing, ScoreFloor y Policy quedan intactos en los
// cuatro — nunca se tocan acá.
func combinedCandidates() []tuning.Candidate {
	base := tuning.BaselineCandidate()

	s3 := func(c tuning.Candidate) tuning.Candidate {
		c.SlowScan.MaxVisitorsForNovelPath = 3
		c.SlowScan.MinNovelPathRatio = 0.35
		return c
	}

	c0 := base
	c0.Name = "C0-baseline"

	c1 := s3(base)
	c1.Name = "C1-slowscan-only"

	c2 := s3(base)
	c2.Name = "C2-slowscan-account-weight"
	c2.Anomaly.Weights.AccountDiversity = 0.5

	c3 := s3(base)
	c3.Name = "C3-slowscan-trigger020"
	c3.Anomaly.TriggerThreshold = 0.20

	return []tuning.Candidate{c0, c1, c2, c3}
}

func buildScenarios() map[uint64]map[int]datagen.Scenario {
	scenarios := make(map[uint64]map[int]datagen.Scenario, len(seeds))
	for _, seed := range seeds {
		scenarios[seed] = make(map[int]datagen.Scenario, len(ratios))
		for _, ratio := range ratios {
			scenarios[seed][ratio] = datagen.BuildScenario(datagen.DefaultScenarioConfig(seed, float64(ratio)/100))
		}
	}
	return scenarios
}

func main() {
	resolver := datagen.NewSimulatedASNResolver()
	scenarios := buildScenarios()

	if err := os.MkdirAll("reports/tuning", 0o755); err != nil {
		log.Fatalf("sweepcombined: creando carpeta de salida: %v", err)
	}

	candidates := combinedCandidates()
	rowsByCandidate := make(map[string][]tuning.CombinedSweepRow)
	var order []string

	for _, candidate := range candidates {
		order = append(order, candidate.Name)
		for _, seed := range seeds {
			resultsByRatio := make(map[int]tuning.RunResult)
			diagnosticsByRatio := make(map[int][]tuning.EventDiagnostic)

			for _, ratio := range ratios {
				scenario := scenarios[seed][ratio]
				result, err := tuning.RunScenario(scenario, candidate, resolver)
				if err != nil {
					log.Fatalf("sweepcombined: %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
				}
				resultsByRatio[ratio] = result

				if ratio != 0 {
					diagnostics, err := tuning.RunDiagnostics(scenario, candidate, resolver, result.Decisions)
					if err != nil {
						log.Fatalf("sweepcombined: diagnostics %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
					}
					diagnosticsByRatio[ratio] = diagnostics
				}
			}

			row := tuning.ComputeCombinedSweepRow(candidate.Name, seed, resultsByRatio, diagnosticsByRatio)
			rowsByCandidate[candidate.Name] = append(rowsByCandidate[candidate.Name], row)
		}
		log.Printf("sweepcombined: %s listo (%d seeds)", candidate.Name, len(seeds))
	}

	report := tuning.RenderCombinedSweep(rowsByCandidate, order)
	if err := os.WriteFile("reports/tuning/sweep-combined.md", []byte(report), 0o644); err != nil {
		log.Fatalf("sweepcombined: %v", err)
	}
	log.Printf("sweepcombined: reporte escrito en reports/tuning/sweep-combined.md")
}
