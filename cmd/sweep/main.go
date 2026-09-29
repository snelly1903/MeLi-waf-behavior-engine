// Command sweep corre los sweeps de candidatos aprobados para
// slow_scan y statistical_anomaly sobre los escenarios de TUNING
// (seeds 101/102/103, ratios 0/10/30%) — nunca holdout. No modifica
// ScoreFloor, ChallengeThreshold, BlockThreshold ni
// credential_stuffing: cada candidato parte de
// tuning.BaselineCandidate() y solo cambia los campos explícitos que
// ese candidato declara. Ver docs/decisiones.md.
package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/tuning"
)

var seeds = []uint64{101, 102, 103}
var ratios = []int{0, 10, 30}

// slowScanCandidates: S0 baseline, S1 maxvisitors-3, S2 novelratio-035,
// S3 ambos combinados. Nada más cambia respecto del baseline.
func slowScanCandidates() []tuning.Candidate {
	base := tuning.BaselineCandidate()

	s0 := base
	s0.Name = "S0-baseline"

	s1 := base
	s1.Name = "S1-maxvisitors-3"
	s1.SlowScan.MaxVisitorsForNovelPath = 3

	s2 := base
	s2.Name = "S2-novelratio-035"
	s2.SlowScan.MinNovelPathRatio = 0.35

	s3 := base
	s3.Name = "S3-maxvisitors-3-novelratio-035"
	s3.SlowScan.MaxVisitorsForNovelPath = 3
	s3.SlowScan.MinNovelPathRatio = 0.35

	return []tuning.Candidate{s0, s1, s2, s3}
}

// anomalyCandidates: A0 baseline, A1 ZSaturation=3, A2 TriggerThreshold=0.20,
// A3 AccountDiversity weight=0.5, A4 y A5 combinaciones. Nada más
// cambia respecto del baseline — ScoreFloor, Policy y los otros 4
// pesos quedan intactos.
func anomalyCandidates() []tuning.Candidate {
	base := tuning.BaselineCandidate()

	a0 := base
	a0.Name = "A0-baseline"

	a1 := base
	a1.Name = "A1-anomaly-z3"
	a1.Anomaly.ZSaturation = 3

	a2 := base
	a2.Name = "A2-anomaly-trigger020"
	a2.Anomaly.TriggerThreshold = 0.20

	a3 := base
	a3.Name = "A3-anomaly-account-weight05"
	a3.Anomaly.Weights.AccountDiversity = 0.5

	a4 := base
	a4.Name = "A4-anomaly-z3-account-weight05"
	a4.Anomaly.ZSaturation = 3
	a4.Anomaly.Weights.AccountDiversity = 0.5

	a5 := base
	a5.Name = "A5-anomaly-z3-trigger020"
	a5.Anomaly.ZSaturation = 3
	a5.Anomaly.TriggerThreshold = 0.20

	return []tuning.Candidate{a0, a1, a2, a3, a4, a5}
}

// buildScenarios genera, una sola vez, los 9 escenarios de tuning
// (compartidos entre TODOS los candidatos de los dos sweeps) —
// nunca se regeneran por candidato: la comparación tiene que correr
// sobre EXACTAMENTE los mismos eventos.
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
		log.Fatalf("sweep: creando carpeta de salida: %v", err)
	}

	// --- Sweep de Slow Scan -------------------------------------------
	ssCandidates := slowScanCandidates()
	ssRowsByCandidate := make(map[string][]tuning.SlowScanSweepRow)
	var ssOrder []string
	for _, candidate := range ssCandidates {
		ssOrder = append(ssOrder, candidate.Name)
		for _, seed := range seeds {
			resultsByRatio := make(map[int]tuning.RunResult)
			var campaigns []tuning.CampaignGateAnalysis
			for _, ratio := range ratios {
				scenario := scenarios[seed][ratio]
				result, err := tuning.RunScenario(scenario, candidate, resolver)
				if err != nil {
					log.Fatalf("sweep: slowscan %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
				}
				resultsByRatio[ratio] = result

				diagnostics, err := tuning.RunDiagnostics(scenario, candidate, resolver, result.Decisions)
				if err != nil {
					log.Fatalf("sweep: slowscan diagnostics %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
				}
				campaigns = append(campaigns, tuning.AnalyzeSlowScanCampaigns(diagnostics, candidate.SlowScan)...)
			}
			row := tuning.ComputeSlowScanSweepRow(candidate.Name, seed, resultsByRatio, campaigns)
			ssRowsByCandidate[candidate.Name] = append(ssRowsByCandidate[candidate.Name], row)
		}
		log.Printf("sweep: slowscan %s listo (%d seeds)", candidate.Name, len(seeds))
	}
	ssReport := tuning.RenderSlowScanSweep(ssRowsByCandidate, ssOrder)
	if err := os.WriteFile(filepath.Join("reports/tuning", "sweep-slowscan.md"), []byte(ssReport), 0o644); err != nil {
		log.Fatalf("sweep: %v", err)
	}
	log.Printf("sweep: reporte de slow_scan escrito en reports/tuning/sweep-slowscan.md")

	// --- Sweep de Statistical Anomaly -----------------------------------
	anCandidates := anomalyCandidates()
	anRowsByCandidate := make(map[string][]tuning.AnomalySweepRow)
	var anOrder []string

	// Diagnóstico de 0% del baseline (A0), por seed — se guarda para
	// comparar la transición de cada candidato posterior contra él.
	baselineDiagAt0 := make(map[uint64][]tuning.EventDiagnostic)

	for _, candidate := range anCandidates {
		anOrder = append(anOrder, candidate.Name)
		for _, seed := range seeds {
			resultsByRatio := make(map[int]tuning.RunResult)
			var diagAt0 []tuning.EventDiagnostic
			for _, ratio := range ratios {
				scenario := scenarios[seed][ratio]
				result, err := tuning.RunScenario(scenario, candidate, resolver)
				if err != nil {
					log.Fatalf("sweep: anomaly %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
				}
				resultsByRatio[ratio] = result

				if ratio == 0 {
					diagnostics, err := tuning.RunDiagnostics(scenario, candidate, resolver, result.Decisions)
					if err != nil {
						log.Fatalf("sweep: anomaly diagnostics %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
					}
					diagAt0 = diagnostics
				}
			}

			row := tuning.ComputeAnomalySweepRow(candidate.Name, seed, resultsByRatio, diagAt0)

			if candidate.Name == "A0-baseline" {
				baselineDiagAt0[seed] = diagAt0
			} else {
				transition, err := tuning.CompareAnomalyTransitions(baselineDiagAt0[seed], diagAt0, eval.PolicyBroad)
				if err != nil {
					log.Fatalf("sweep: CompareAnomalyTransitions %s seed=%d: %v", candidate.Name, seed, err)
				}
				row.Transition = &transition
			}

			anRowsByCandidate[candidate.Name] = append(anRowsByCandidate[candidate.Name], row)
		}
		log.Printf("sweep: anomaly %s listo (%d seeds)", candidate.Name, len(seeds))
	}
	anReport := tuning.RenderAnomalySweep(anRowsByCandidate, anOrder)
	if err := os.WriteFile(filepath.Join("reports/tuning", "sweep-anomaly.md"), []byte(anReport), 0o644); err != nil {
		log.Fatalf("sweep: %v", err)
	}
	log.Printf("sweep: reporte de anomaly escrito en reports/tuning/sweep-anomaly.md")
}
