package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// AnomalyFPRow es UN evento legítimo (0% malicious) cuya Decision
// final fue positiva (broad) — un falso positivo — con la evidencia
// EXPLÍCITA de que el detector responsable fue statistical_anomaly:
// nunca se infiere por eliminación, se comprueba que
// CredentialStuffing.Triggered y SlowScan.Triggered sean false Y que
// exista una evaluación de anomaly con Triggered=true.
type AnomalyFPRow struct {
	Seed      uint64
	RequestID string

	// PrincipalDetectorConfirmed es true solo cuando se verificó
	// estructuralmente que ningún otro detector disparó para este
	// evento — la comprobación explícita pedida, no una suposición.
	PrincipalDetectorConfirmed bool

	CombinedScore float64 // antes de ScoreFloor
	RiskScore     float64 // ConfidenceScore de la Decision real
	Action        decision.Action
	ZScores       map[string]float64
}

// AnomalyScoreBucket resume, para un grupo (por ejemplo, todos los
// ALLOW o todos los CHALLENGE de tráfico legítimo), la distribución
// del score combinado de anomaly y de su RiskScore resultante.
type AnomalyScoreBucket struct {
	Action    decision.Action
	Combined  PercentileSummary
	RiskScore PercentileSummary
}

// AnomalyDiagnosis es el resultado completo de la pasada diagnóstica
// sobre statistical_anomaly en tráfico 0% malicious.
type AnomalyDiagnosis struct {
	FPRows   []AnomalyFPRow
	ByAction []AnomalyScoreBucket
}

// AnalyzeAnomalyFalsePositives recorre diagnostics —se espera que
// vengan SOLO de corridas de 0% malicious, donde por ground truth
// TODO evento es legit— y separa (a) los falsos positivos concretos,
// con prueba explícita de que el detector responsable fue anomaly, y
// (b) la distribución completa del score combinado/RiskScore de
// anomaly, agrupada por la Action real que tomó el motor.
//
// policy decide qué Action cuenta como "positivo" (broad, para poder
// ver también los CHALLENGE, no solo los BLOCK) — mismo criterio que
// el resto de esta evaluación.
func AnalyzeAnomalyFalsePositives(diagnostics []EventDiagnostic, policy eval.Policy) AnomalyDiagnosis {
	var diag AnomalyDiagnosis
	byAction := make(map[decision.Action][]struct{ combined, risk float64 })

	for _, d := range diagnostics {
		if d.Label != groundtruth.LabelLegit {
			// Esta función es específicamente para 0% malicious —
			// un evento no-legit en la entrada sería un error del
			// llamador, no algo que deba contarse acá.
			continue
		}

		winner, ok := winningAnomalyEval(d.Anomaly)
		if !ok {
			continue
		}

		byAction[d.Decision.Action] = append(byAction[d.Decision.Action], struct{ combined, risk float64 }{winner.CombinedScore, winner.RiskScore})

		if !policy.IsPositive(d.Decision.Action) {
			continue
		}

		row := AnomalyFPRow{
			Seed:      d.Seed,
			RequestID: d.RequestID,
			// Prueba explícita, no inferencia por eliminación: los
			// otros dos detectores NO dispararon, y anomaly SÍ.
			PrincipalDetectorConfirmed: !d.CredentialStuffing.Triggered && !d.SlowScan.Triggered && winner.Triggered,
			CombinedScore:              winner.CombinedScore,
			RiskScore:                  d.Decision.ConfidenceScore,
			Action:                     d.Decision.Action,
			ZScores:                    winner.ZScores,
		}
		diag.FPRows = append(diag.FPRows, row)
	}

	for _, action := range []decision.Action{decision.ActionAllow, decision.ActionChallenge, decision.ActionBlock} {
		samples, ok := byAction[action]
		if !ok {
			continue
		}
		combined := make([]float64, len(samples))
		risk := make([]float64, len(samples))
		for i, s := range samples {
			combined[i] = s.combined
			risk[i] = s.risk
		}
		diag.ByAction = append(diag.ByAction, AnomalyScoreBucket{
			Action:    action,
			Combined:  Summarize(combined),
			RiskScore: Summarize(risk),
		})
	}

	return diag
}

// RenderAnomalyDiagnosis arma un resumen legible en Markdown de diag.
func RenderAnomalyDiagnosis(diag AnomalyDiagnosis) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("## Falsos positivos (broad) en 0%% malicious — statistical_anomaly\n\n")
	if len(diag.FPRows) == 0 {
		w("Ningún falso positivo encontrado.\n\n")
	} else {
		w("| Seed | RequestID | Principal confirmado | Combined | RiskScore | Action | not_found_z | failed_auth_z | path_diversity_z | without_referer_z | account_diversity_z |\n")
		w("|---|---|---|---|---|---|---|---|---|---|---|\n")
		for _, r := range diag.FPRows {
			w("| %d | %s | %v | %.4f | %.4f | %s | %.2f | %.2f | %.2f | %.2f | %.2f |\n",
				r.Seed, r.RequestID, r.PrincipalDetectorConfirmed, r.CombinedScore, r.RiskScore, r.Action,
				r.ZScores["not_found_ratio_z"], r.ZScores["failed_auth_ratio_z"], r.ZScores["path_diversity_ratio_z"],
				r.ZScores["without_referer_ratio_z"], r.ZScores["account_diversity_ratio_z"],
			)
		}
		w("\n")
	}

	w("## Distribución del score de anomaly en tráfico legítimo (0%% malicious), por action\n\n")
	w("| Action | N | Combined min/p50/p75/p90/p95/max | RiskScore min/p50/p75/p90/p95/max |\n")
	w("|---|---|---|---|\n")
	for _, buck := range diag.ByAction {
		w("| %s | %d | %.4f/%.4f/%.4f/%.4f/%.4f/%.4f | %.4f/%.4f/%.4f/%.4f/%.4f/%.4f |\n",
			buck.Action, buck.Combined.N,
			buck.Combined.Min, buck.Combined.P50, buck.Combined.P75, buck.Combined.P90, buck.Combined.P95, buck.Combined.Max,
			buck.RiskScore.Min, buck.RiskScore.P50, buck.RiskScore.P75, buck.RiskScore.P90, buck.RiskScore.P95, buck.RiskScore.Max,
		)
	}
	w("\n")

	return string(b)
}
