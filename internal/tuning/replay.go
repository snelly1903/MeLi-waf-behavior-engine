package tuning

import (
	"context"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

func Replay(events []event.Event, decider engine.Decider) []decision.Decision {
	ctx := context.Background()
	decisions := make([]decision.Decision, len(events))
	for i, e := range events {
		decisions[i] = decider.Decide(ctx, e)
	}
	return decisions
}
