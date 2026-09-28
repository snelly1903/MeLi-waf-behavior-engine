// Command sweepcs corre los 5 candidatos de credential_stuffing
// aprobados tras el diagnóstico de sensibilidad a Window (tarea 1.9):
// CS0 baseline (Window=30m, MinDistinctIPs=20, MinDistinctAccounts=15,
// MinAttempts=25, MinFailedRatio=0.60), CSw1 (solo Window=90m,
// candidato de control), CSw2 (+MinDistinctIPs=16), CSw3
// (+MinDistinctIPs=16+MinAttempts=24, el "agresivo" derivado
// exactamente de los mínimos observados en 3 seeds) y CSw4
// ("conservador": Window=90m+MinDistinctIPs=18+MinAttempts=25, sin
// tocar Attempts). Corre solo sobre tuning (seeds 101/102/103, ratios
// 0/10/30%), nunca holdout. Todos parten de C2 (S3+A3, ya aprobado
// provisionalmente) para slow_scan/anomaly — S3/A3/ScoreFloor/Policy
// nunca se tocan acá, solo credential_stuffing.
// MinDistinctAccounts/MinFailedRatio se mantienen en su valor actual
// en los cinco candidatos. Ver docs/decisiones.md, tarea 1.9.
package main

import (
	"log"
	"os"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/tuning"
)

var seeds = []uint64{101, 102, 103}
var ratios = []int{0, 10, 30}

func csCandidates() []tuning.Candidate {
	base := func() tuning.Candidate {
		c := tuning.BaselineCandidate()
		c.SlowScan.MaxVisitorsForNovelPath = 3
		c.SlowScan.MinNovelPathRatio = 0.35
		c.Anomaly.Weights.AccountDiversity = 0.5
		return c
	}

	cs0 := base()
	cs0.Name = "CS0-baseline"

	csw1 := base()
	csw1.Name = "CSw1-window90"
	csw1.CredentialStuffing.Window = 90 * time.Minute

	csw2 := base()
	csw2.Name = "CSw2-window90-ips16"
	csw2.CredentialStuffing.Window = 90 * time.Minute
	csw2.CredentialStuffing.MinDistinctIPs = 16

	csw3 := base()
	csw3.Name = "CSw3-window90-ips16-attempts24"
	csw3.CredentialStuffing.Window = 90 * time.Minute
	csw3.CredentialStuffing.MinDistinctIPs = 16
	csw3.CredentialStuffing.MinAttempts = 24

	csw4 := base()
	csw4.Name = "CSw4-conservative"
	csw4.CredentialStuffing.Window = 90 * time.Minute
	csw4.CredentialStuffing.MinDistinctIPs = 18
	csw4.CredentialStuffing.MinAttempts = 25

	return []tuning.Candidate{cs0, csw1, csw2, csw3, csw4}
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
		log.Fatalf("sweepcs: creando carpeta de salida: %v", err)
	}

	candidates := csCandidates()
	rowsByCandidate := make(map[string][]tuning.CredentialStuffingSweepRow)
	campaignsByCandidateRatio := make(map[string]map[int][]tuning.CredentialStuffingCampaignAnalysis)
	var order []string

	for _, candidate := range candidates {
		order = append(order, candidate.Name)
		campaignsByCandidateRatio[candidate.Name] = make(map[int][]tuning.CredentialStuffingCampaignAnalysis)

		for _, seed := range seeds {
			resultsByRatio := make(map[int]tuning.RunResult)
			diagnosticsByRatio := make(map[int][]tuning.EventDiagnostic)
			var campaignsThisSeed []tuning.CredentialStuffingCampaignAnalysis

			for _, ratio := range ratios {
				scenario := scenarios[seed][ratio]
				result, err := tuning.RunScenario(scenario, candidate, resolver)
				if err != nil {
					log.Fatalf("sweepcs: %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
				}
				resultsByRatio[ratio] = result

				if ratio != 0 {
					diagnostics, err := tuning.RunDiagnostics(scenario, candidate, resolver, result.Decisions)
					if err != nil {
						log.Fatalf("sweepcs: diagnostics %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
					}
					diagnosticsByRatio[ratio] = diagnostics

					campaigns, err := tuning.AnalyzeCredentialStuffingCampaigns(scenario.Events, diagnostics, candidate.CredentialStuffing)
					if err != nil {
						log.Fatalf("sweepcs: campaigns %s seed=%d ratio=%d: %v", candidate.Name, seed, ratio, err)
					}
					campaignsThisSeed = append(campaignsThisSeed, campaigns...)
					campaignsByCandidateRatio[candidate.Name][ratio] = append(campaignsByCandidateRatio[candidate.Name][ratio], campaigns...)
				}
			}

			row := tuning.ComputeCredentialStuffingSweepRow(candidate.Name, seed, resultsByRatio, diagnosticsByRatio, campaignsThisSeed)
			rowsByCandidate[candidate.Name] = append(rowsByCandidate[candidate.Name], row)
		}
		log.Printf("sweepcs: %s listo (%d seeds)", candidate.Name, len(seeds))
	}

	report := tuning.RenderCredentialStuffingSweep(rowsByCandidate, campaignsByCandidateRatio, order)
	if err := os.WriteFile("reports/tuning/sweep-credstuffing.md", []byte(report), 0o644); err != nil {
		log.Fatalf("sweepcs: %v", err)
	}
	log.Printf("sweepcs: reporte escrito en reports/tuning/sweep-credstuffing.md")
}
