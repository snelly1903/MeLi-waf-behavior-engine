// Package engine define la abstracción mínima del motor de detección
// desde el punto de vista de la capa HTTP (tarea 1.1): dado un evento
// ya validado, decide qué hacer. La capa HTTP (internal/httpapi) nunca
// sabe cómo se toma la decisión — solo sabe que existe algo
// (Decider) que la toma. Todavía no hay ningún detector conductual:
// AllowAllDecider es el único Decider que existe hoy, y sirve de
// relleno hasta que la Fase 1 agregue los detectores reales detrás de
// la misma interfaz.
package engine

import (
	"context"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

// Decider decide qué hacer con un evento ya validado. Recibe
// context.Context desde el día uno, aunque AllowAllDecider no lo usa
// todavía: así, cuando la Fase 1 agregue dependencias reales
// (consultas a un store, tracing de OpenTelemetry, cancelación por
// timeout del cliente HTTP), no hace falta rediseñar esta interfaz ni
// tocar a todos los que ya la implementan.
//
// Decide no devuelve error: en esta etapa la decisión siempre se
// puede calcular a partir de un evento ya validado, no existe ningún
// modo de falla real. Si una implementación futura lo necesita, se
// ajusta la interfaz en ese momento.
type Decider interface {
	Decide(ctx context.Context, e event.Event) decision.Decision
}

// AllowAllDecider es el Decider de la tarea 1.1: sin ningún detector
// conductual implementado, todo evento se permite. AttackVector
// siempre queda en "unknown" (no se evaluó ninguna señal),
// ConfidenceScore siempre en 0 (sin ningún indicio de riesgo por
// evaluar), y Explanation siempre tiene un texto fijo y determinista
// — incluso una decisión de ALLOW queda auditable, no solo las de
// CHALLENGE/BLOCK que decision.Validate exige explicar.
type AllowAllDecider struct{}

// Decide implementa Decider.
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
