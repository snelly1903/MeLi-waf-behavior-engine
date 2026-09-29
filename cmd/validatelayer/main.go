// Command validatelayer es la validación combinada final de la
// detector layer, antes de calibrar ScoreFloor/Policy: compara D0
// (baseline completo, sin ningún cambio de threshold) con D1 (los
// tres detectores ya tuneados: credential_stuffing CSw2, slow_scan
// S3, statistical_anomaly A3), solo sobre tuning (seeds 101/102/103,
// ratios 0/10/30%), nunca holdout. ScoreFloor, ChallengeThreshold y
// BlockThreshold se mantienen exactamente iguales en los dos — esos
// se calibran en un paso posterior. Ver docs/decisiones.md.
package main

import (
	"log"
	"os"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/tuning"
)

var seeds = []uint64{101, 102, 103}
var ratios = []int{0, 10, 30}

// candidates: D0 es tuning.BaselineCandidate() sin ningún cambio. D1
// aplica exactamente los tres cambios aprobados hasta ahora: S3
// (slow_scan), A3 (anomaly) y CSw2 (credential_stuffing —
// Window=90m, MinDistinctIPs=16, MinDistinctAccounts/MinAttempts/
// MinFailedRatio SIN cambios). Policy (ScoreFloor/ChallengeThreshold/
// BlockThreshold) es la de BaselineCandidate() en los dos, sin tocar.
func candidates() []tuning.Candidate {
	d0 := tuning.BaselineCandidate()
	d0.Name = "D0-baseline-completo"

	d1 := tuning.BaselineCandidate()
	d1.Name = "D1-tuned-detectors"
	d1.SlowScan.MaxVisitorsForNovelPath = 3
	d1.SlowScan.MinNovelPathRatio = 0.35
	d1.Anomaly.Weights.AccountDiversity = 0.5
	d1.CredentialStuffing.Window = 90 * time.Minute
	d1.CredentialStuffing.MinDistinctIPs = 16

	return []tuning.Candidate{d0, d1}
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
		log.Fatalf("validatelayer: creando carpeta de salida: %v", err)
	}

	var reports []tuning.DetectorLayerCandidateReport

	for _, candidate := range candidates() {
		rep := tuning.DetectorLayerCandidateReport{
			Candidate:          candidate.Name,
			RowsByRatio:        make(map[int][]tuning.DetectorLayerRow),
			AggByRatio:         make(map[int]tuning.DetectorLayerRow),
			AttributionByRatio: make(map[int][]tuning.MitigationAttribution),
		}

		pooledDelaysByRatio := make(map[int][]tuning.CampaignDelay)
		attributionBySeedRatio := make(map[int][][]tuning.MitigationAttribution)
		var allDiagnostics []tuning.EventDiagnostic

		for _, ratio := range ratios {
			for _, seed := range seeds {
				scenario := scenarios[seed][ratio]
				result, err := tuning.RunScenario(scenario, candidate, resolver)
				if err != nil {
					log.Fatalf("validatelayer: %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
				}
				diagnostics, err := tuning.RunDiagnostics(scenario, candidate, resolver, result.Decisions)
				if err != nil {
					log.Fatalf("validatelayer: diagnostics %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
				}
				allDiagnostics = append(allDiagnostics, diagnostics...)

				row := tuning.ComputeDetectorLayerRow(candidate.Name, result, diagnostics)
				rep.RowsByRatio[ratio] = append(rep.RowsByRatio[ratio], row)
				pooledDelaysByRatio[ratio] = append(pooledDelaysByRatio[ratio], result.Delay...)

				if ratio != 0 {
					attributionBySeedRatio[ratio] = append(attributionBySeedRatio[ratio], tuning.ComputeMitigationAttribution(diagnostics, eval.PolicyBroad))
				}
			}
			rep.AggByRatio[ratio] = tuning.AggregateDetectorLayerRows(rep.RowsByRatio[ratio], pooledDelaysByRatio[ratio])
		}

		for _, ratio := range []int{10, 30} {
			perSeed := attributionBySeedRatio[ratio]
			// perSeed[i] tiene siempre 2 entradas en el mismo orden
			// (credential_stuffing, slow_scan) — ver
			// ComputeMitigationAttribution.
			for vectorIdx := 0; vectorIdx < 2; vectorIdx++ {
				var items []tuning.MitigationAttribution
				for _, seedAttr := range perSeed {
					items = append(items, seedAttr[vectorIdx])
				}
				rep.AttributionByRatio[ratio] = append(rep.AttributionByRatio[ratio], tuning.SumMitigationAttribution(items))
			}
		}

		rep.RiskBuckets = tuning.AnalyzeRiskScoreDistributions(allDiagnostics)

		reports = append(reports, rep)
		log.Printf("validatelayer: %s listo (%d seeds x %d ratios)", candidate.Name, len(seeds), len(ratios))
	}

	report := "# Validación combinada final de la detector layer\n\n" +
		"D0 = baseline completo, sin ningún cambio. D1 = credential_stuffing CSw2 + slow_scan S3 + statistical_anomaly A3. " +
		"ScoreFloor, ChallengeThreshold y BlockThreshold son EXACTAMENTE los mismos en los dos — no se tocan en este paso. " +
		"Solo tuning (seeds 101/102/103, ratios 0/10/30%), sin holdout.\n\n" +
		tuning.RenderDetectorLayerComparison(reports)

	if err := os.WriteFile("reports/tuning/validate-detector-layer.md", []byte(report), 0o644); err != nil {
		log.Fatalf("validatelayer: %v", err)
	}
	log.Printf("validatelayer: reporte escrito en reports/tuning/validate-detector-layer.md")
}
