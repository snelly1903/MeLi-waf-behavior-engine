package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// ActionDistribution es, para UNA corrida, cuántos eventos legítimos
// y cuántos maliciosos (cualquier vector) terminaron en cada Action —
// la base de False Challenge Rate y False Block Rate, que existen
// para entender el costo de fricción (CHALLENGE) sobre tráfico
// legítimo por separado del costo de bloqueo (BLOCK), no solo la
// Precision/Recall agregada.
type ActionDistribution struct {
	LegitAllow     int
	LegitChallenge int
	LegitBlock     int

	MaliciousAllow     int
	MaliciousChallenge int
	MaliciousBlock     int
}

// LegitTotal y MaliciousTotal son los denominadores de las tasas de
// abajo.
func (d ActionDistribution) LegitTotal() int {
	return d.LegitAllow + d.LegitChallenge + d.LegitBlock
}

func (d ActionDistribution) MaliciousTotal() int {
	return d.MaliciousAllow + d.MaliciousChallenge + d.MaliciousBlock
}

// FalseChallengeRate es la fracción de tráfico LEGÍTIMO que recibió
// CHALLENGE — el costo de fricción impuesto a usuarios reales, nunca
// confundido con FalseBlockRate (que mide el costo más grave,
// bloquear a un usuario real).
func (d ActionDistribution) FalseChallengeRate() eval.Ratio {
	return ratioOf(d.LegitChallenge, d.LegitTotal())
}

// FalseBlockRate es la fracción de tráfico LEGÍTIMO que recibió
// BLOCK — matemáticamente idéntica a la Strict FPR (Strict solo
// cuenta BLOCK como positivo), se expone acá aparte con este nombre
// porque así se pidió explícitamente para el sweep de Policy.
func (d ActionDistribution) FalseBlockRate() eval.Ratio {
	return ratioOf(d.LegitBlock, d.LegitTotal())
}

// ComputeActionDistribution cruza scenarioEvents (con su Label) y
// decisions — mismo orden y longitud, se cruzan por índice, nunca por
// RequestID (mismo criterio que ComputeDetectionDelay).
func ComputeActionDistribution(scenarioEvents []groundtruth.LabeledEvent, decisions []decision.Decision) (ActionDistribution, error) {
	if len(scenarioEvents) != len(decisions) {
		return ActionDistribution{}, fmt.Errorf("tuning: ComputeActionDistribution: %d eventos, %d decisiones — deben coincidir", len(scenarioEvents), len(decisions))
	}

	var d ActionDistribution
	for i, le := range scenarioEvents {
		malicious := le.Label != groundtruth.LabelLegit
		switch decisions[i].Action {
		case decision.ActionAllow:
			if malicious {
				d.MaliciousAllow++
			} else {
				d.LegitAllow++
			}
		case decision.ActionChallenge:
			if malicious {
				d.MaliciousChallenge++
			} else {
				d.LegitChallenge++
			}
		case decision.ActionBlock:
			if malicious {
				d.MaliciousBlock++
			} else {
				d.LegitBlock++
			}
		}
	}
	return d, nil
}

// SumActionDistribution suma, campo a campo, varios ActionDistribution
// (uno por seed) — conteos enteros, suma exacta, sin sesgo de tamaño
// de seed.
func SumActionDistribution(items []ActionDistribution) ActionDistribution {
	var sum ActionDistribution
	for _, a := range items {
		sum.LegitAllow += a.LegitAllow
		sum.LegitChallenge += a.LegitChallenge
		sum.LegitBlock += a.LegitBlock
		sum.MaliciousAllow += a.MaliciousAllow
		sum.MaliciousChallenge += a.MaliciousChallenge
		sum.MaliciousBlock += a.MaliciousBlock
	}
	return sum
}
