// Define el resultado que produce un detector individual sobre un evento.
package finding

import "github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"

type Finding struct {
	Triggered bool

	AttackVector decision.AttackVector

	RiskScore float64

	ContributingSignals []decision.ContributingSignal

	Explanation string

	EntityID string
}
