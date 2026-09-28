package eval

import (
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// Ratio es una métrica que puede no tener sentido calcular — por
// ejemplo, la precisión cuando el motor nunca predijo positivo ni una
// sola vez (división por cero). Defined=false significa "no aplica" y
// nunca se disimula con un 0 ni con un 1 (ver docs/decisiones.md,
// tarea 0.7).
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

// ConfusionMatrix son los cuatro conteos base de una política de
// evaluación.
type ConfusionMatrix struct {
	TP, FP, FN, TN int
}

// Total es la cantidad de eventos evaluados en esta matriz.
func (m ConfusionMatrix) Total() int { return m.TP + m.FP + m.FN + m.TN }

// Metrics son las métricas derivadas de una ConfusionMatrix. Cada una
// comprueba su PROPIO denominador por separado: no existe una regla
// única del tipo "en el escenario de 0% todo es N/A". Precision
// depende de cuántas veces predijo positivo el motor (TP+FP), Recall y
// FNR dependen de cuántos positivos reales había (TP+FN), y FPR
// depende de cuántos negativos reales había (FP+TN) — son tres
// condiciones distintas, y perfectamente pueden darse combinaciones
// donde una métrica es N/A y las otras no. Por ejemplo: en el
// escenario de 0% de tráfico malicioso, TP+FN siempre es 0 (no hay
// ningún positivo real), así que Recall y FNR son N/A — pero si el
// motor bloqueó aunque sea un evento legítimo por error, TP+FP > 0 y
// Precision SÍ está definida (va a dar 0%, porque ese único positivo
// predicho fue un falso positivo).
type Metrics struct {
	Precision Ratio
	Recall    Ratio
	FPR       Ratio
	FNR       Ratio
	Accuracy  Ratio
	// F1 es la media armónica de Precision y Recall (2PR/(P+R)) — la
	// métrica que resume ambas en un solo número cuando hace falta
	// comparar configuraciones (tarea 1.9). Indefinida (N/A, nunca 0)
	// si Precision o Recall lo son, o si ambas son exactamente 0 (2*0*0/0,
	// otra división por cero).
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

// Policy decide qué acciones cuentan como "predicción positiva".
type Policy int

const (
	// PolicyStrict: solo BLOCK es positivo. ALLOW y CHALLENGE cuentan
	// como negativo.
	PolicyStrict Policy = iota
	// PolicyBroad: CHALLENGE y BLOCK son positivos. Solo ALLOW cuenta
	// como negativo. Modela que un CHALLENGE es una fricción barata,
	// no una molestia grave como un BLOCK — ver docs/decisiones.md.
	PolicyBroad
)

// IsPositive expone isPositive para paquetes fuera de internal/eval
// que necesitan la misma regla "qué cuenta como predicción positiva"
// — por ejemplo internal/tuning (tarea 1.9), para decidir cuándo una
// campaña quedó detectada, sin duplicar esta lógica en otro lugar.
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

// BuildConfusionMatrix arma la matriz de confusión de policy sobre
// records ya cruzados (ver Join). "Positivo real" es cualquier
// etiqueta distinta de legit — sin importar si es credential_stuffing
// o slow_scan, ambas cuentan igual acá; el desglose por tipo de ataque
// vive aparte, en vector.go.
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
