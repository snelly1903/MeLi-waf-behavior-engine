// Command sweeppolicy es el sweep de Policy (tarea 1.9): con la
// detector layer ya congelada en D1 (credential_stuffing CSw2,
// slow_scan S3, statistical_anomaly A3 — ver docs/decisiones.md),
// evalúa 9 combinaciones de ChallengeThreshold x BlockThreshold sobre
// tuning (seeds 101/102/103, ratios 0/10/30%), sin holdout, sin tocar
// ScoreFloor. Corre los tres detectores UNA sola vez por seed/ratio
// (con la Policy por defecto) y reaplica cada candidato de Policy
// sobre esas mismas decisiones ya calculadas (ver
// tuning.RunResultWithPolicy) — nunca vuelve a correr ningún
// detector, porque esta etapa aísla el mapping RiskScore→Action.
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/tuning"
)

var seeds = []uint64{101, 102, 103}
var ratios = []int{0, 10, 30}

// d1Candidate replica EXACTAMENTE D1 de cmd/validatelayer — la
// detector layer ya congelada y aprobada. Se redefine acá (no se
// puede importar, cmd/validatelayer es package main) — los valores
// tienen que quedar idénticos.
func d1Candidate() tuning.Candidate {
	c := tuning.BaselineCandidate()
	c.Name = "D1-tuned-detectors"
	c.SlowScan.MaxVisitorsForNovelPath = 3
	c.SlowScan.MinNovelPathRatio = 0.35
	c.Anomaly.Weights.AccountDiversity = 0.5
	c.CredentialStuffing.Window = 90 * time.Minute
	c.CredentialStuffing.MinDistinctIPs = 16
	return c
}

// policyCandidates: los 9 puntos del grid Challenge x Block pedidos.
// Los tres valores de Challenge (0.50/0.55/0.60) son todos menores
// que los tres de Block (0.70/0.75/0.80), así que las 9 combinaciones
// sobreviven el filtro Challenge<Block sin descartar ninguna.
func policyCandidates() []tuning.PolicyCandidate {
	challenges := []float64{0.50, 0.55, 0.60}
	blocks := []float64{0.70, 0.75, 0.80}

	var out []tuning.PolicyCandidate
	for _, c := range challenges {
		for _, b := range blocks {
			if c >= b {
				continue
			}
			out = append(out, tuning.PolicyCandidate{
				Name:               policyName(c, b),
				ChallengeThreshold: c,
				BlockThreshold:     b,
			})
		}
	}
	return out
}

func policyName(challenge, block float64) string {
	return fmt.Sprintf("P-c%.2f-b%.2f", challenge, block)
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
	candidate := d1Candidate()

	if err := os.MkdirAll("reports/tuning", 0o755); err != nil {
		log.Fatalf("sweeppolicy: creando carpeta de salida: %v", err)
	}

	// Paso 1: correr los detectores UNA sola vez por seed/ratio.
	type key struct {
		seed  uint64
		ratio int
	}
	baseResults := make(map[key]tuning.RunResult, len(seeds)*len(ratios))
	for _, seed := range seeds {
		for _, ratio := range ratios {
			scenario := scenarios[seed][ratio]
			result, err := tuning.RunScenario(scenario, candidate, resolver)
			if err != nil {
				log.Fatalf("sweeppolicy: RunScenario seed=%d ratio=%d: %v", seed, ratio, err)
			}
			baseResults[key{seed, ratio}] = result
		}
	}
	log.Printf("sweeppolicy: detector layer corrida una sola vez (%d seeds x %d ratios)", len(seeds), len(ratios))

	// Paso 2: para cada candidato de Policy, reaplicar sobre las
	// decisiones ya calculadas — sin volver a correr detectores.
	candidates := policyCandidates()
	rowsByCandidate := make(map[string][]tuning.PolicySweepRow)
	var order []string

	for _, pc := range candidates {
		order = append(order, pc.Name)
		policy := engine.Policy{ChallengeThreshold: pc.ChallengeThreshold, BlockThreshold: pc.BlockThreshold}

		for _, seed := range seeds {
			for _, ratio := range ratios {
				scenario := scenarios[seed][ratio]
				base := baseResults[key{seed, ratio}]

				reapplied := tuning.RunResultWithPolicy(scenario, base.Decisions, resolver, pc.Name, policy)
				row, err := tuning.ComputePolicySweepRow(pc.Name, scenario, reapplied)
				if err != nil {
					log.Fatalf("sweeppolicy: ComputePolicySweepRow %s seed=%d ratio=%d: %v", pc.Name, seed, ratio, err)
				}
				rowsByCandidate[pc.Name] = append(rowsByCandidate[pc.Name], row)
			}
		}
		log.Printf("sweeppolicy: %s (Challenge=%.2f Block=%.2f) listo", pc.Name, pc.ChallengeThreshold, pc.BlockThreshold)
	}

	report := "# Sweep de Policy (tarea 1.9)\n\n" +
		"Detector layer congelada en D1 (credential_stuffing CSw2, slow_scan S3, statistical_anomaly A3). ScoreFloor sin tocar. " +
		"Solo tuning (seeds 101/102/103, ratios 0/10/30%), sin holdout. Los 9 candidatos reaplican Policy sobre las MISMAS decisiones " +
		"de D1 (ConfidenceScore/AttackVector ya calculados) — ningún detector se volvió a correr.\n\n" +
		tuning.RenderPolicySweep(rowsByCandidate, order)

	if err := os.WriteFile("reports/tuning/sweep-policy.md", []byte(report), 0o644); err != nil {
		log.Fatalf("sweeppolicy: %v", err)
	}
	log.Printf("sweeppolicy: reporte escrito en reports/tuning/sweep-policy.md")
}
