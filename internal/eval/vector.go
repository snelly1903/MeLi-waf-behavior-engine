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

// De todos los ataques de credential stuffing y slow scan que realmente
// ocurrieron, ¿qué porcentaje detectamos de cada uno?
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
	// Correct: Decision.AttackVector coincide con la etiqueta real.
	Correct int
	// Unknown: el motor respondió AttackVectorUnknown — honestamente
	// no supo atribuirlo a un vector específico. El PDF permite
	// explícitamente este valor.
	Unknown int
	// Incorrect: el motor afirmó un vector concreto y se equivocó.
	Incorrect int
}

// Accuracy es Correct / (Correct + Incorrect) — deja Unknown fuera del
// denominador: un motor que dice honestamente "no sé" no debería
// penalizarse igual que uno que se equivoca con seguridad.
func (v VectorAttribution) Accuracy() Ratio {
	return ratio(v.Correct, v.Correct+v.Incorrect)
}

// Cuando el WAF detectó una petición maliciosa,
//
//	¿identificó correctamente el tipo de ataque?
func EvaluateVectorAttribution(records []JoinedRecord) VectorAttribution {
	var v VectorAttribution
	for _, r := range records {
		if r.Label == groundtruth.LabelLegit {
			continue
		}
		if !PolicyBroad.isPositive(r.Decision.Action) {
			continue
		}

		// Label y AttackVector son dos tipos de string distintos
		// (groundtruth.Label y decision.AttackVector) con los mismos
		// valores de texto ("credential_stuffing", "slow_scan") — la
		// conversión de tipo los compara sin duplicar las constantes.
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
