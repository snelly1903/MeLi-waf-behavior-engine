// Define la interfaz Decider y el decisor trivial AllowAllDecider.
package engine

import (
	"context"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

type Decider interface {
	Decide(ctx context.Context, e event.Event) decision.Decision
}

type AllowAllDecider struct{}

func (AllowAllDecider) Decide(_ context.Context, e event.Event) decision.Decision {
	return decision.Decision{
		RequestID:    e.RequestID,
		Timestamp:    e.Timestamp,
		EntityID:     "ip:" + e.ClientIP.String(),
		Action:       decision.ActionAllow,
		AttackVector: decision.AttackVectorUnknown,
		Explanation:  "no behavioral detector is implemented yet; default policy is ALLOW",
	}
}
