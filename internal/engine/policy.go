package engine

import (
	"errors"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
)

// Policy decide qué decision.Action corresponde a un puntaje de
// riesgo combinado. Los umbrales viven acá, no en ningún detector
// individual — ya documentado desde la tarea 0.3
// (decision.Decision.ConfidenceScore) y reconfirmado en las tareas
// 1.3/1.4: un detector solo entrega evidencia (Triggered + RiskScore),
// nunca decide la acción final.
type Policy struct {
	// ChallengeThreshold es el puntaje mínimo (inclusive) a partir del
	// cual la acción pasa de ALLOW a CHALLENGE.
	ChallengeThreshold float64

	// BlockThreshold es el puntaje mínimo (inclusive) a partir del cual
	// la acción pasa a BLOCK. Se comprueba primero que
	// ChallengeThreshold.
	BlockThreshold float64
}

// ErrInvalidPolicy se devuelve cuando Policy no cumple
// 0 <= ChallengeThreshold < BlockThreshold <= 1.
var ErrInvalidPolicy = errors.New("engine: policy must satisfy 0 <= challenge_threshold < block_threshold <= 1")

// Validate comprueba que p tenga umbrales utilizables.
func (p Policy) Validate() error {
	if p.ChallengeThreshold < 0 || p.ChallengeThreshold >= p.BlockThreshold || p.BlockThreshold > 1 {
		return ErrInvalidPolicy
	}
	return nil
}

// actionFor traduce un puntaje de riesgo combinado en una acción. Los
// dos límites son inclusive: un score exactamente en BlockThreshold ya
// es BLOCK, uno exactamente en ChallengeThreshold ya es CHALLENGE.
func (p Policy) actionFor(score float64) decision.Action {
	switch {
	case score >= p.BlockThreshold:
		return decision.ActionBlock
	case score >= p.ChallengeThreshold:
		return decision.ActionChallenge
	default:
		return decision.ActionAllow
	}
}
