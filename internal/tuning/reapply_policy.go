package tuning

import (
	"math"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// ReapplyPolicy recalcula ÚNICAMENTE decision.Decision.Action de cada
// elemento de decisions según policy — RequestID, Timestamp,
// EntityID, ConfidenceScore, AttackVector, ContributingSignals y
// Explanation quedan EXACTAMENTE iguales: son la evidencia cruda que
// ya produjeron los detectores (principal.RiskScore/AttackVector en
// engine.BehavioralDecider.Decide), que NO depende de
// ChallengeThreshold/BlockThreshold.
//
// Válido para cualquier policy cuyo ChallengeThreshold sea > 0: un
// evento donde ningún detector disparó tiene ConfidenceScore=0 (valor
// cero de decision.Decision), y policy.ActionFor(0) da ALLOW igual
// que el camino real de Decide para ese caso (que fuerza ALLOW sin
// llamar a actionFor). Con ChallengeThreshold=0 esto podría divergir
// — ningún candidato del sweep de Policy usa 0, así que la
// equivalencia se mantiene siempre en ese sweep.
func ReapplyPolicy(decisions []decision.Decision, policy engine.Policy) []decision.Decision {
	out := make([]decision.Decision, len(decisions))
	for i, d := range decisions {
		d.Action = policy.ActionFor(d.ConfidenceScore)
		out[i] = d
	}
	return out
}

// RunResultWithPolicy arma un RunResult reaplicando policy sobre
// baseDecisions (ya calculadas por RunScenario con OTRA Policy, pero
// con los mismos detectores/candidato) — nunca vuelve a correr ningún
// detector. scenario y resolver deben ser los MISMOS que produjeron
// baseDecisions.
func RunResultWithPolicy(scenario datagen.Scenario, baseDecisions []decision.Decision, resolver credstuffing.NetworkResolver, candidateName string, policy engine.Policy) RunResult {
	decisions := ReapplyPolicy(baseDecisions, policy)

	labels := make(map[string]groundtruth.Label, len(scenario.Events))
	for _, le := range scenario.Events {
		labels[le.Event.RequestID] = le.Label
	}

	evalResult := eval.Evaluate(eval.LoadLabelsResult{Labels: labels}, decisions)
	delay := ComputeDetectionDelay(scenario.Events, decisions, resolver, eval.PolicyBroad)

	return RunResult{
		Candidate:    candidateName,
		Seed:         scenario.Stats.Seed,
		Ratio:        int(math.Round(scenario.Stats.TargetMaliciousRatio * 100)),
		Decisions:    decisions,
		Eval:         evalResult,
		Delay:        delay,
		DelaySummary: SummarizeDelay(delay),
	}
}

// strictByAttackVector es el equivalente STRICT de
// Result.ByAttackVector (que internal/eval.Evaluate calcula
// hardcodeado con PolicyBroad) — necesario para el sweep de Policy,
// que pide recall STRICT por vector, no solo broad.
func strictByAttackVector(scenario datagen.Scenario, decisions []decision.Decision) []eval.AttackVectorRecall {
	labels := make(map[string]groundtruth.Label, len(scenario.Events))
	for _, le := range scenario.Events {
		labels[le.Event.RequestID] = le.Label
	}
	joined, _ := eval.Join(labels, eval.Issues{}, decisions)
	return eval.ByAttackVectorRecall(joined, eval.PolicyStrict)
}
