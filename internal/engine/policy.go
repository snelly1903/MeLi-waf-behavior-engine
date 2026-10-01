// Traduce el risk score en una acción ALLOW, CHALLENGE o BLOCK según umbrales.
package engine

import (
	"errors"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
)

type Policy struct {
	ChallengeThreshold float64

	BlockThreshold float64
}

var ErrInvalidPolicy = errors.New("engine: policy must satisfy 0 <= challenge_threshold < block_threshold <= 1")

func (p Policy) Validate() error {
	if p.ChallengeThreshold < 0 || p.ChallengeThreshold >= p.BlockThreshold || p.BlockThreshold > 1 {
		return ErrInvalidPolicy
	}
	return nil
}

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

func (p Policy) ActionFor(score float64) decision.Action {
	return p.actionFor(score)
}
