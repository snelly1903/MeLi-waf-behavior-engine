// Command diagnosecs es la pasada diagnóstica de credential_stuffing:
// para cada campaña real de credential_stuffing en los escenarios de
// tuning, compara la ventana real del detector (lo máximo que llegó a
// ver en CUALQUIER momento dentro de su ventana de correlación)
// contra el ground truth completo de la campaña — motivado por el
// hallazgo del sweep combinado de que credential_stuffing nunca
// aparece como "DetectorOnly" en la mitigación. Corre con el
// candidato C2 (S3+A3) ya aprobado provisionalmente — S3/A3 no se
// tocan, y las métricas de gate de credential_stuffing son
// intrínsecas a su propia Config, no a la de slow_scan/anomaly. No
// modifica ningún threshold. Ver docs/decisiones.md.
package main

import (
	"log"
	"os"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/tuning"
)

// c2Candidate replica exactamente C2 del sweep combinado (S3+A3) —
// ver cmd/sweepcombined/main.go. Se redefine acá en vez de
// importarlo (cmd/sweepcombined es package main, no se puede
// importar) — los valores tienen que quedar IDÉNTICOS a los ya
// aprobados.
func c2Candidate() tuning.Candidate {
	c := tuning.BaselineCandidate()
	c.Name = "C2-slowscan-account-weight"
	c.SlowScan.MaxVisitorsForNovelPath = 3
	c.SlowScan.MinNovelPathRatio = 0.35
	c.Anomaly.Weights.AccountDiversity = 0.5
	return c
}

func main() {
	seeds := []uint64{101, 102, 103}
	ratios := []int{10, 30} // 0% nunca tiene campañas de credential_stuffing

	candidate := c2Candidate()
	resolver := datagen.NewSimulatedASNResolver()

	var allCampaigns []tuning.CredentialStuffingCampaignAnalysis
	for _, seed := range seeds {
		for _, ratio := range ratios {
			scenario := datagen.BuildScenario(datagen.DefaultScenarioConfig(seed, float64(ratio)/100))

			result, err := tuning.RunScenario(scenario, candidate, resolver)
			if err != nil {
				log.Fatalf("diagnosecs: RunScenario seed=%d ratio=%d: %v", seed, ratio, err)
			}
			diagnostics, err := tuning.RunDiagnostics(scenario, candidate, resolver, result.Decisions)
			if err != nil {
				log.Fatalf("diagnosecs: RunDiagnostics seed=%d ratio=%d: %v", seed, ratio, err)
			}

			campaigns, err := tuning.AnalyzeCredentialStuffingCampaigns(scenario.Events, diagnostics, candidate.CredentialStuffing)
			if err != nil {
				log.Fatalf("diagnosecs: AnalyzeCredentialStuffingCampaigns seed=%d ratio=%d: %v", seed, ratio, err)
			}
			allCampaigns = append(allCampaigns, campaigns...)
			log.Printf("diagnosecs: seed=%d ratio=%d%% — %d campaña(s) de credential_stuffing", seed, ratio, len(campaigns))
		}
	}

	if err := os.MkdirAll("reports/tuning", 0o755); err != nil {
		log.Fatalf("diagnosecs: creando carpeta de salida: %v", err)
	}

	report := "# Diagnóstico de credential_stuffing: ventana real vs. ground truth\n\n" +
		"Candidato usado para la atribución cruzada con anomaly: C2 (S3+A3, ya aprobado provisionalmente — sin cambios). " +
		"Los thresholds de credential_stuffing son los actuales, sin tocar.\n\n" +
		tuning.RenderCredentialStuffingCampaigns(allCampaigns)

	if err := os.WriteFile("reports/tuning/diagnose-credstuffing.md", []byte(report), 0o644); err != nil {
		log.Fatalf("diagnosecs: %v", err)
	}
	log.Printf("diagnosecs: reporte escrito en reports/tuning/diagnose-credstuffing.md (%d campañas totales)", len(allCampaigns))
}
