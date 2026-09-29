package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// AnomalyTriggerBreakdown cuenta, entre tráfico legítimo (0%
// malicious), cuántos eventos tuvieron una evaluación de anomaly con
// Triggered=true, separado por la Action FINAL que resultó: un evento
// puede seguir disparando internamente (Triggered=true, hay
// evidencia) pero terminar en ALLOW si su RiskScore quedó por debajo
// de ChallengeThreshold.
type AnomalyTriggerBreakdown struct {
	TriggeredCount          int
	TriggeredAllowCount     int
	TriggeredChallengeCount int
	TriggeredBlockCount     int
}

// ComputeAnomalyTriggerBreakdown recorre diagnostics (se espera que
// vengan solo de corridas de 0% malicious) y arma el desglose.
func ComputeAnomalyTriggerBreakdown(diagnostics []EventDiagnostic) AnomalyTriggerBreakdown {
	var b AnomalyTriggerBreakdown
	for _, d := range diagnostics {
		if d.Label != groundtruth.LabelLegit {
			continue
		}
		winner, ok := winningAnomalyEval(d.Anomaly)
		if !ok || !winner.Triggered {
			continue
		}
		b.TriggeredCount++
		switch d.Decision.Action {
		case decision.ActionAllow:
			b.TriggeredAllowCount++
		case decision.ActionChallenge:
			b.TriggeredChallengeCount++
		case decision.ActionBlock:
			b.TriggeredBlockCount++
		}
	}
	return b
}

// AnomalyTransitionCounts compara la MISMA corrida (mismo seed, mismo
// escenario de 0% malicious) evaluada con dos candidatos distintos —
// baseline y candidate, en ESE orden, ambos sobre los MISMOS eventos
// (mismo índice) — y clasifica cada evento que era un falso positivo
// broad en baseline en una de tres categorías, nunca mezcladas:
//
//   - NoLongerTriggered: la evaluación de anomaly de ese evento dejó
//     de disparar por completo en candidate (Triggered pasó a false).
//   - StillTriggeredNowAllow: la evaluación SIGUE disparando
//     (Triggered=true, hay evidencia real) pero la Action final pasó
//     a ALLOW — se resolvió por la interacción con Policy, no porque
//     el detector "dejara de ver" nada.
//   - StillPositive: sigue siendo un falso positivo broad en
//     candidate — sin resolver.
type AnomalyTransitionCounts struct {
	NoLongerTriggered      int
	StillTriggeredNowAllow int
	StillPositive          int
}

// CompareAnomalyTransitions requiere que baseline y candidate tengan
// exactamente la misma longitud y el mismo orden de eventos (la misma
// corrida de datagen.BuildScenario, evaluada con dos candidatos
// distintos) — se cruzan por índice, nunca por RequestID.
func CompareAnomalyTransitions(baseline, candidate []EventDiagnostic, policy eval.Policy) (AnomalyTransitionCounts, error) {
	if len(baseline) != len(candidate) {
		return AnomalyTransitionCounts{}, fmt.Errorf("tuning: CompareAnomalyTransitions: %d eventos en baseline, %d en candidate — deben coincidir", len(baseline), len(candidate))
	}

	var t AnomalyTransitionCounts
	for i := range baseline {
		if baseline[i].Label != groundtruth.LabelLegit {
			continue
		}
		if !policy.IsPositive(baseline[i].Decision.Action) {
			continue // no era un FP en baseline, no hay transición que reportar
		}
		candWinner, ok := winningAnomalyEval(candidate[i].Anomaly)
		switch {
		case !ok || !candWinner.Triggered:
			t.NoLongerTriggered++
		case !policy.IsPositive(candidate[i].Decision.Action):
			t.StillTriggeredNowAllow++
		default:
			t.StillPositive++
		}
	}
	return t, nil
}

// AnomalySweepRow es, para UN candidato y UN seed, todas las métricas
// pedidas explícitamente para el sweep de statistical_anomaly.
type AnomalySweepRow struct {
	Candidate string
	Seed      uint64

	BroadFPCountAt0 int
	FPRAt0          eval.Ratio

	Trigger AnomalyTriggerBreakdown

	BroadRecallAt10 eval.Ratio
	BroadRecallAt30 eval.Ratio

	RecallCredentialStuffingAt10 eval.Ratio
	RecallCredentialStuffingAt30 eval.Ratio
	RecallSlowScanAt10           eval.Ratio
	RecallSlowScanAt30           eval.Ratio

	RiskScoreAt0     PercentileSummary
	CombinedScoreAt0 PercentileSummary

	// Transition, si no es nil, compara este candidato contra A0
	// (baseline) para los mismos eventos de 0% — nil para el propio
	// A0 (no tiene sentido comparar baseline contra sí mismo).
	Transition *AnomalyTransitionCounts
}

// ComputeAnomalySweepRow arma la fila de un candidato/seed a partir
// de resultsByRatio (un RunResult por ratio) y diagnosticsAt0 (el
// detalle crudo por evento de la corrida de 0% de ESTE candidato,
// usado para el desglose de Trigger y las distribuciones de score).
func ComputeAnomalySweepRow(candidateName string, seed uint64, resultsByRatio map[int]RunResult, diagnosticsAt0 []EventDiagnostic) AnomalySweepRow {
	row := AnomalySweepRow{Candidate: candidateName, Seed: seed}

	if r, ok := resultsByRatio[0]; ok {
		row.BroadFPCountAt0 = r.Eval.Broad.Matrix.FP
		row.FPRAt0 = r.Eval.Broad.Metrics.FPR
	}
	if r, ok := resultsByRatio[10]; ok {
		row.BroadRecallAt10 = r.Eval.Broad.Metrics.Recall
		row.RecallCredentialStuffingAt10 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelCredentialStuffing)
		row.RecallSlowScanAt10 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelSlowScan)
	}
	if r, ok := resultsByRatio[30]; ok {
		row.BroadRecallAt30 = r.Eval.Broad.Metrics.Recall
		row.RecallCredentialStuffingAt30 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelCredentialStuffing)
		row.RecallSlowScanAt30 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelSlowScan)
	}

	row.Trigger = ComputeAnomalyTriggerBreakdown(diagnosticsAt0)

	var risk, combined []float64
	for _, d := range diagnosticsAt0 {
		if d.Label != groundtruth.LabelLegit {
			continue
		}
		winner, ok := winningAnomalyEval(d.Anomaly)
		if !ok {
			continue
		}
		risk = append(risk, winner.RiskScore)
		combined = append(combined, winner.CombinedScore)
	}
	row.RiskScoreAt0 = Summarize(risk)
	row.CombinedScoreAt0 = Summarize(combined)

	return row
}

// RenderAnomalySweep arma el reporte en Markdown del sweep completo.
func RenderAnomalySweep(rowsByCandidate map[string][]AnomalySweepRow, order []string) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("# Sweep de Statistical Anomaly (tuning, seeds 101/102/103, ratios 0/10/30%%)\n\n")

	w("## FP, recall y distribución de score, por candidato y seed\n\n")
	w("| Candidato | Seed | Broad FP@0%% | FPR@0%% | Findings Triggered@0%% (ALLOW/CHALLENGE/BLOCK) | BroadRecall@10%% | BroadRecall@30%% | Recall CS@10%%/30%% | Recall SS@10%%/30%% |\n")
	w("|---|---|---|---|---|---|---|---|---|\n")
	for _, name := range order {
		for _, r := range rowsByCandidate[name] {
			w("| %s | %d | %d | %s | %d (%d/%d/%d) | %s | %s | %s/%s | %s/%s |\n",
				r.Candidate, r.Seed, r.BroadFPCountAt0, formatRatio(r.FPRAt0),
				r.Trigger.TriggeredCount, r.Trigger.TriggeredAllowCount, r.Trigger.TriggeredChallengeCount, r.Trigger.TriggeredBlockCount,
				formatRatio(r.BroadRecallAt10), formatRatio(r.BroadRecallAt30),
				formatRatio(r.RecallCredentialStuffingAt10), formatRatio(r.RecallCredentialStuffingAt30),
				formatRatio(r.RecallSlowScanAt10), formatRatio(r.RecallSlowScanAt30),
			)
		}
	}
	w("\n")

	w("## Distribución de score en tráfico legítimo (0%%), por candidato y seed\n\n")
	w("| Candidato | Seed | RiskScore p50/p75/p90/p95/max | Combined p50/p75/p90/p95/max |\n")
	w("|---|---|---|---|\n")
	for _, name := range order {
		for _, r := range rowsByCandidate[name] {
			rs, cs := r.RiskScoreAt0, r.CombinedScoreAt0
			w("| %s | %d | %.4f/%.4f/%.4f/%.4f/%.4f | %.4f/%.4f/%.4f/%.4f/%.4f |\n",
				r.Candidate, r.Seed,
				rs.P50, rs.P75, rs.P90, rs.P95, rs.Max,
				cs.P50, cs.P75, cs.P90, cs.P95, cs.Max,
			)
		}
	}
	w("\n")

	w("## Transición respecto de A0-baseline (solo eventos que eran FP broad en baseline)\n\n")
	w("| Candidato | Seed | Dejó de Triggered | Sigue Triggered, ahora ALLOW | Sigue siendo FP (sin resolver) |\n")
	w("|---|---|---|---|---|\n")
	for _, name := range order {
		for _, r := range rowsByCandidate[name] {
			if r.Transition == nil {
				continue
			}
			w("| %s | %d | %d | %d | %d |\n", r.Candidate, r.Seed, r.Transition.NoLongerTriggered, r.Transition.StillTriggeredNowAllow, r.Transition.StillPositive)
		}
	}
	w("\n")

	return string(b)
}
