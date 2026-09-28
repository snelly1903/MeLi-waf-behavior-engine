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

// RunResult es el resultado de correr UN candidato sobre UN escenario
// (una combinación seed×ratio) — la unidad atómica que después se
// agrega entre seeds ("estabilidad", ver aggregate.go) y se compara
// entre candidatos (ver report.go).
type RunResult struct {
	Candidate string
	Seed      uint64
	Ratio     int // 0, 10 o 30 — el TargetMaliciousRatio del escenario, en porcentaje

	Decisions    []decision.Decision
	Eval         eval.Result
	Delay        []CampaignDelay
	DelaySummary []DelaySummary
}

// RunScenario corre candidate sobre scenario (ya generado en memoria
// por datagen.BuildScenario) y calcula tanto las métricas de
// internal/eval como el detection delay — todo en memoria, sin leer
// ni escribir ningún archivo. resolver es el MISMO NetworkResolver
// que usa candidate.Build y ComputeDetectionDelay: la agrupación de
// campañas de credential stuffing tiene que ser exactamente la que el
// detector ve, nunca una tabla derivada por separado.
//
// Cada llamada arranca con estado limpio (ver Candidate.Build) — así
// que correr el mismo candidate sobre varios escenarios (distintos
// seeds/ratios) nunca contamina un run con el anterior.
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
