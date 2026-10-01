// Ejecuta el motor conductual sobre los escenarios de holdout y genera el reporte final.
package main

import (
	"log"
	"os"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/tuning"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/wiring"
)

var tuningSeeds = []uint64{101, 102, 103}
var holdoutSeeds = []uint64{201, 202, 203}
var ratios = []int{0, 10, 30}

func baselineCandidate() tuning.Candidate {
	c := tuning.BaselineCandidate()
	c.Name = "Baseline-original"
	return c
}

func finalCandidate() tuning.Candidate {
	cs, ss, an := wiring.FinalConfigs()
	return tuning.Candidate{
		Name:               "Final-tuned-config",
		CredentialStuffing: cs,
		SlowScan:           ss,
		Anomaly:            an,
		Policy:             wiring.FinalPolicy(),
	}
}

func buildScenarios(seeds []uint64) map[uint64]map[int]datagen.Scenario {
	scenarios := make(map[uint64]map[int]datagen.Scenario, len(seeds))
	for _, seed := range seeds {
		scenarios[seed] = make(map[int]datagen.Scenario, len(ratios))
		for _, ratio := range ratios {
			scenarios[seed][ratio] = datagen.BuildScenario(datagen.DefaultScenarioConfig(seed, float64(ratio)/100))
		}
	}
	return scenarios
}

func runCandidate(candidate tuning.Candidate, seeds []uint64, scenarios map[uint64]map[int]datagen.Scenario, resolver credstuffing.NetworkResolver) (tuning.DetectorLayerCandidateReport, map[int]tuning.ActionDistribution) {
	rep := tuning.DetectorLayerCandidateReport{
		Candidate:          candidate.Name,
		RowsByRatio:        make(map[int][]tuning.DetectorLayerRow),
		AggByRatio:         make(map[int]tuning.DetectorLayerRow),
		AttributionByRatio: make(map[int][]tuning.MitigationAttribution),
	}
	actionsByRatio := make(map[int]tuning.ActionDistribution)

	pooledDelaysByRatio := make(map[int][]tuning.CampaignDelay)
	attributionBySeedRatio := make(map[int][][]tuning.MitigationAttribution)
	actionsBySeedRatio := make(map[int][]tuning.ActionDistribution)
	var allDiagnostics []tuning.EventDiagnostic

	for _, ratio := range ratios {
		for _, seed := range seeds {
			scenario := scenarios[seed][ratio]
			result, err := tuning.RunScenario(scenario, candidate, resolver)
			if err != nil {
				log.Fatalf("holdout: %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
			}
			diagnostics, err := tuning.RunDiagnostics(scenario, candidate, resolver, result.Decisions)
			if err != nil {
				log.Fatalf("holdout: diagnostics %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
			}
			allDiagnostics = append(allDiagnostics, diagnostics...)

			row := tuning.ComputeDetectorLayerRow(candidate.Name, result, diagnostics)
			rep.RowsByRatio[ratio] = append(rep.RowsByRatio[ratio], row)
			pooledDelaysByRatio[ratio] = append(pooledDelaysByRatio[ratio], result.Delay...)

			actions, err := tuning.ComputeActionDistribution(scenario.Events, result.Decisions)
			if err != nil {
				log.Fatalf("holdout: ComputeActionDistribution %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
			}
			actionsBySeedRatio[ratio] = append(actionsBySeedRatio[ratio], actions)

			if ratio != 0 {
				attributionBySeedRatio[ratio] = append(attributionBySeedRatio[ratio], tuning.ComputeMitigationAttribution(diagnostics, eval.PolicyBroad))
			}
		}
		rep.AggByRatio[ratio] = tuning.AggregateDetectorLayerRows(rep.RowsByRatio[ratio], pooledDelaysByRatio[ratio])
		actionsByRatio[ratio] = tuning.SumActionDistribution(actionsBySeedRatio[ratio])
	}

	for _, ratio := range []int{10, 30} {
		perSeed := attributionBySeedRatio[ratio]
		for vectorIdx := 0; vectorIdx < 2; vectorIdx++ {
			var items []tuning.MitigationAttribution
			for _, seedAttr := range perSeed {
				items = append(items, seedAttr[vectorIdx])
			}
			rep.AttributionByRatio[ratio] = append(rep.AttributionByRatio[ratio], tuning.SumMitigationAttribution(items))
		}
	}

	rep.RiskBuckets = tuning.AnalyzeRiskScoreDistributions(allDiagnostics)

	return rep, actionsByRatio
}

func runDataset(label string, seeds []uint64, resolver credstuffing.NetworkResolver) tuning.HoldoutDatasetReport {
	scenarios := buildScenarios(seeds)

	baselineRep, baselineActions := runCandidate(baselineCandidate(), seeds, scenarios, resolver)
	log.Printf("holdout: %s: Baseline-original listo (%d seeds x %d ratios)", label, len(seeds), len(ratios))

	finalRep, finalActions := runCandidate(finalCandidate(), seeds, scenarios, resolver)
	log.Printf("holdout: %s: Final-tuned-config listo (%d seeds x %d ratios)", label, len(seeds), len(ratios))

	return tuning.HoldoutDatasetReport{
		Label:           label,
		Baseline:        baselineRep,
		Final:           finalRep,
		BaselineActions: baselineActions,
		FinalActions:    finalActions,
	}
}

func main() {
	resolver := datagen.NewSimulatedASNResolver()

	if err := os.MkdirAll("reports/holdout", 0o755); err != nil {
		log.Fatalf("holdout: creando carpeta de salida: %v", err)
	}

	tuningReport := runDataset("tuning", tuningSeeds, resolver)
	holdoutReport := runDataset("holdout", holdoutSeeds, resolver)

	report := "# Evaluación final: Baseline vs. Final Tuned Config\n\n" +
		"PRIMERA Y ÚNICA corrida de holdout — seeds 201/202/203, ratios 0/10/30%. " +
		"Comparado contra los mismos escenarios de tuning (seeds 101/102/103) para medir generalización. " +
		"Ningún threshold se modificó en función de estos resultados.\n\n" +
		tuning.RenderHoldoutReport(tuningReport, holdoutReport)

	if err := os.WriteFile("reports/holdout/baseline-vs-final.md", []byte(report), 0o644); err != nil {
		log.Fatalf("holdout: %v", err)
	}
	log.Printf("holdout: reporte escrito en reports/holdout/baseline-vs-final.md")
}
