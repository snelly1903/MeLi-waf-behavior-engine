// Reaplica una política de acciones sobre decisiones ya calculadas sin re-ejecutar el motor.
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

func ReapplyPolicy(decisions []decision.Decision, policy engine.Policy) []decision.Decision {
	out := make([]decision.Decision, len(decisions))
	for i, d := range decisions {
		d.Action = policy.ActionFor(d.ConfidenceScore)
		out[i] = d
	}
	return out
}

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

func strictByAttackVector(scenario datagen.Scenario, decisions []decision.Decision) []eval.AttackVectorRecall {
	labels := make(map[string]groundtruth.Label, len(scenario.Events))
	for _, le := range scenario.Events {
		labels[le.Event.RequestID] = le.Label
	}
	joined, _ := eval.Join(labels, eval.Issues{}, decisions)
	return eval.ByAttackVectorRecall(joined, eval.PolicyStrict)
}
