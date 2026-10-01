package eval

import (
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)
type Ratio struct {
	Value   float64
	Defined bool
}

func ratio(numerator, denominator int) Ratio {
	if denominator == 0 {
		return Ratio{Defined: false}
	}
	return Ratio{Value: float64(numerator) / float64(denominator), Defined: true}
}

type ConfusionMatrix struct {
	TP, FP, FN, TN int
}

func (m ConfusionMatrix) Total() int { return m.TP + m.FP + m.FN + m.TN }

type Metrics struct {
	Precision Ratio
	Recall    Ratio
	FPR       Ratio
	FNR       Ratio
	Accuracy  Ratio
	F1 Ratio
}

// f1 calcula la media armónica de precision y recall, propagando
// "indefinido" (nunca disimulado como 0) desde cualquiera de sus dos
// entradas o desde su propia división por cero.
func f1(precision, recall Ratio) Ratio {
	if !precision.Defined || !recall.Defined {
		return Ratio{Defined: false}
	}
	denom := precision.Value + recall.Value
	if denom == 0 {
		return Ratio{Defined: false}
	}
	return Ratio{Value: 2 * precision.Value * recall.Value / denom, Defined: true}
}

// Metrics calcula las métricas derivadas de m.
func (m ConfusionMatrix) Metrics() Metrics {
	precision := ratio(m.TP, m.TP+m.FP)
	recall := ratio(m.TP, m.TP+m.FN)
	return Metrics{
		Precision: precision,
		Recall:    recall,
		FPR:       ratio(m.FP, m.FP+m.TN),
		FNR:       ratio(m.FN, m.FN+m.TP),
		Accuracy:  ratio(m.TP+m.TN, m.Total()),
		F1:        f1(precision, recall),
	}
}

type Policy int

const (
	PolicyStrict Policy = iota
	PolicyBroad
)

func (p Policy) IsPositive(a decision.Action) bool {
	return p.isPositive(a)
}

func (p Policy) isPositive(a decision.Action) bool {
	switch p {
	case PolicyStrict:
		return a == decision.ActionBlock
	case PolicyBroad:
		return a == decision.ActionChallenge || a == decision.ActionBlock
	default:
		return false
	}
}

func BuildConfusionMatrix(records []JoinedRecord, policy Policy) ConfusionMatrix {
	var m ConfusionMatrix
	for _, r := range records {
		actualPositive := r.Label != groundtruth.LabelLegit
		predictedPositive := policy.isPositive(r.Decision.Action)

		switch {
		case actualPositive && predictedPositive:
			m.TP++
		case actualPositive && !predictedPositive:
			m.FN++
		case !actualPositive && predictedPositive:
			m.FP++
		default:
			m.TN++
		}
	}
	return m
}
