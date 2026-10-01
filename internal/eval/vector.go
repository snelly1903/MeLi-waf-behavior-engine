// Calcula el recall por vector de ataque y la precisión de la atribución de vector.
package eval

import (
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type AttackVectorRecall struct {
	Vector         groundtruth.Label
	TruePositives  int
	FalseNegatives int
	Recall         Ratio
}

func ByAttackVectorRecall(records []JoinedRecord, policy Policy) []AttackVectorRecall {
	vectors := []groundtruth.Label{groundtruth.LabelCredentialStuffing, groundtruth.LabelSlowScan}
	results := make([]AttackVectorRecall, 0, len(vectors))

	for _, vector := range vectors {
		var tp, fn int
		for _, r := range records {
			if r.Label != vector {
				continue
			}
			if policy.isPositive(r.Decision.Action) {
				tp++
			} else {
				fn++
			}
		}
		results = append(results, AttackVectorRecall{
			Vector:         vector,
			TruePositives:  tp,
			FalseNegatives: fn,
			Recall:         ratio(tp, tp+fn),
		})
	}
	return results
}

type VectorAttribution struct {
	Correct   int
	Unknown   int
	Incorrect int
}

func (v VectorAttribution) Accuracy() Ratio {
	return ratio(v.Correct, v.Correct+v.Incorrect)
}

func EvaluateVectorAttribution(records []JoinedRecord) VectorAttribution {
	var v VectorAttribution
	for _, r := range records {
		if r.Label == groundtruth.LabelLegit {
			continue
		}
		if !PolicyBroad.isPositive(r.Decision.Action) {
			continue
		}

		expected := decision.AttackVector(r.Label)
		switch {
		case r.Decision.AttackVector == expected:
			v.Correct++
		case r.Decision.AttackVector == decision.AttackVectorUnknown:
			v.Unknown++
		default:
			v.Incorrect++
		}
	}
	return v
}
