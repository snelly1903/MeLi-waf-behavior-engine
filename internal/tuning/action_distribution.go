// Calcula la distribución de acciones sobre tráfico legítimo y malicioso.
package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type ActionDistribution struct {
	LegitAllow     int
	LegitChallenge int
	LegitBlock     int

	MaliciousAllow     int
	MaliciousChallenge int
	MaliciousBlock     int
}

func (d ActionDistribution) LegitTotal() int {
	return d.LegitAllow + d.LegitChallenge + d.LegitBlock
}

func (d ActionDistribution) MaliciousTotal() int {
	return d.MaliciousAllow + d.MaliciousChallenge + d.MaliciousBlock
}

func (d ActionDistribution) FalseChallengeRate() eval.Ratio {
	return ratioOf(d.LegitChallenge, d.LegitTotal())
}

func (d ActionDistribution) FalseBlockRate() eval.Ratio {
	return ratioOf(d.LegitBlock, d.LegitTotal())
}

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
