package tuning

import (
	"context"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

// Replay corre decider sobre events, en el mismo orden en que vienen
// (tienen que estar ya ordenados cronológicamente — mismo requisito
// que internal/baseline.Detect, y garantizado por
// datagen.WriteScenario). Es literalmente el mismo trabajo que hace
// internal/httpapi.Server en cada POST /v1/events, pero sin HTTP en
// el medio: decider.Decide ya hace Observe+Evaluate internamente por
// evento (ver engine.BehavioralDecider.Decide).
//
// Devuelve exactamente len(events) decisiones, en el mismo orden —
// decisions[i] es la respuesta a events[i]. Esto es lo que permite
// cruzar cada decisión con su evento original sin pasar por
// request_id (ver ComputeDetectionDelay, que necesita esa
// correspondencia por índice para conocer ClientIP/Timestamp de cada
// decisión).
func Replay(events []event.Event, decider engine.Decider) []decision.Decision {
	ctx := context.Background()
	decisions := make([]decision.Decision, len(events))
	for i, e := range events {
		decisions[i] = decider.Decide(ctx, e)
	}
	return decisions
}
