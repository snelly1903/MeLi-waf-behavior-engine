// Ejecuta un candidato sobre un escenario y calcula sus métricas.
package tuning

import (
	"math"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type RunResult struct {
	Candidate string
	Seed      uint64
	Ratio     int

	Decisions    []decision.Decision
	Eval         eval.Result
	Delay        []CampaignDelay
	DelaySummary []DelaySummary
}

func RunScenario(scenario datagen.Scenario, candidate Candidate, resolver credstuffing.NetworkResolver) (RunResult, error) {
	decider, err := candidate.Build(resolver)
	if err != nil {
		return RunResult{}, err
	}

	events := make([]event.Event, len(scenario.Events))
	labels := make(map[string]groundtruth.Label, len(scenario.Events))
	for i, le := range scenario.Events {
		events[i] = le.Payload()
		labels[le.Event.RequestID] = le.Label
	}

	decisions := Replay(events, decider)

	evalResult := eval.Evaluate(eval.LoadLabelsResult{Labels: labels}, decisions)
	delay := ComputeDetectionDelay(scenario.Events, decisions, resolver, eval.PolicyBroad)

	return RunResult{
		Candidate:    candidate.Name,
		Seed:         scenario.Stats.Seed,
		Ratio:        int(math.Round(scenario.Stats.TargetMaliciousRatio * 100)),
		Decisions:    decisions,
		Eval:         evalResult,
		Delay:        delay,
		DelaySummary: SummarizeDelay(delay),
	}, nil
}
