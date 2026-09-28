// Command diagnose es la pasada diagnóstica de la tarea 1.9, Punto de
// Control 2: corre la configuración BASELINE (sin ningún cambio de
// threshold) sobre los mismos escenarios de tuning que cmd/tune, pero
// capturando el Finding CRUDO de cada uno de los tres detectores por
// evento (nunca solo la Decision final combinada) — para poder
// explicar, con evidencia explícita y no por eliminación, qué
// parámetro concreto causa cada error observado en el baseline. Ver
// docs/decisiones.md, tarea 1.9.
package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/tuning"
)

func main() {
	seeds := []uint64{101, 102, 103}
	ratios := []int{0, 10, 30}
	out := "reports/tuning/diagnose"

	candidate := tuning.BaselineCandidate()
	resolver := datagen.NewSimulatedASNResolver()

	var all []tuning.EventDiagnostic
	for _, seed := range seeds {
		for _, ratio := range ratios {
			cfg := datagen.DefaultScenarioConfig(seed, float64(ratio)/100)
			scenario := datagen.BuildScenario(cfg)

			result, err := tuning.RunScenario(scenario, candidate, resolver)
			if err != nil {
				log.Fatalf("diagnose: RunScenario seed=%d ratio=%d: %v", seed, ratio, err)
			}
			diagnostics, err := tuning.RunDiagnostics(scenario, candidate, resolver, result.Decisions)
			if err != nil {
				log.Fatalf("diagnose: RunDiagnostics seed=%d ratio=%d: %v", seed, ratio, err)
			}
			all = append(all, diagnostics...)
			log.Printf("diagnose: seed=%d ratio=%d%% — %d eventos diagnosticados", seed, ratio, len(diagnostics))
		}
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		log.Fatalf("diagnose: creando carpeta de salida: %v", err)
	}

	// Sección 1: falsos positivos de statistical_anomaly, solo sobre
	// las corridas de 0% malicious (todo evento ahí es legit por
	// construcción).
	var zeroPercent []tuning.EventDiagnostic
	for _, d := range all {
		if d.Ratio == 0 {
			zeroPercent = append(zeroPercent, d)
		}
	}
	anomalyDiag := tuning.AnalyzeAnomalyFalsePositives(zeroPercent, eval.PolicyBroad)

	// Sección 2: campañas de slow_scan, sobre TODAS las ratios (0%
	// nunca genera ninguna, así que no hace falta filtrar).
	campaigns := tuning.AnalyzeSlowScanCampaigns(all, candidate.SlowScan)

	// Sección 3: distribución de RiskScore por detector, sobre TODO
	// el tráfico (así se ve malicious vs legit de punta a punta).
	riskBuckets := tuning.AnalyzeRiskScoreDistributions(all)

	report := "# Pasada diagnóstica — tarea 1.9, Punto de Control 2\n\n" +
		"Configuración: BASELINE (sin ningún cambio de threshold). " +
		"Seeds de tuning: 101/102/103. Ratios: 0/10/30%.\n\n" +
		tuning.RenderAnomalyDiagnosis(anomalyDiag) +
		tuning.RenderSlowScanCampaigns(campaigns) +
		tuning.RenderRiskScoreDistributions(riskBuckets)

	if err := os.WriteFile(out+".md", []byte(report), 0o644); err != nil {
		log.Fatalf("diagnose: %v", err)
	}
	log.Printf("diagnose: reporte escrito en %s.md (%d FP rows, %d campañas slow_scan, %d buckets de RiskScore)",
		out, len(anomalyDiag.FPRows), len(campaigns), len(riskBuckets))
}
