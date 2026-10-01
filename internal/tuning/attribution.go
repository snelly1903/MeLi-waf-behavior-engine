// Atribuye cada mitigación al detector que la produjo.
package tuning

import (
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type MitigationAttribution struct {
	Vector groundtruth.Label

	Mitigated int

	DetectorOnly int

	WithAnomalyAssist int

	AnomalyOnly int

	Neither int
}

func ComputeMitigationAttribution(diagnostics []EventDiagnostic, policy eval.Policy) []MitigationAttribution {
	vectors := []struct {
		label groundtruth.Label
		own   func(EventDiagnostic) bool
	}{
		{groundtruth.LabelCredentialStuffing, func(d EventDiagnostic) bool { return d.CredentialStuffing.Triggered }},
		{groundtruth.LabelSlowScan, func(d EventDiagnostic) bool { return d.SlowScan.Triggered }},
	}

	result := make([]MitigationAttribution, len(vectors))
	for i, v := range vectors {
		result[i] = MitigationAttribution{Vector: v.label}
		for _, d := range diagnostics {
			if d.Label != v.label {
				continue
			}
			if !policy.IsPositive(d.Decision.Action) {
				continue
			}
			result[i].Mitigated++

			own := v.own(d)
			winner, ok := winningAnomalyEval(d.Anomaly)
			anomalyTriggered := ok && winner.Triggered

			switch {
			case own && anomalyTriggered:
				result[i].WithAnomalyAssist++
			case own && !anomalyTriggered:
				result[i].DetectorOnly++
			case !own && anomalyTriggered:
				result[i].AnomalyOnly++
			default:
				result[i].Neither++
			}
		}
	}
	return result
}
