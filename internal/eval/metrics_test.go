package eval

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func checkRatio(t *testing.T, name string, got Ratio, wantDefined bool, wantValue float64) {
	t.Helper()
	if got.Defined != wantDefined {
		t.Errorf("%s.Defined = %v, want %v", name, got.Defined, wantDefined)
		return
	}
	if wantDefined && got.Value != wantValue {
		t.Errorf("%s.Value = %v, want %v", name, got.Value, wantValue)
	}
}

// TestConfusionMatrix_Metrics_HandComputed usa una matriz calculada a
// mano: TP=3, FP=1, FN=2, TN=4 (total 10).
//
//	Precision = 3 / (3+1) = 0.75
//	Recall    = 3 / (3+2) = 0.6
//	FPR       = 1 / (1+4) = 0.2
//	FNR       = 2 / (2+3) = 0.4
//	Accuracy  = (3+4) / 10 = 0.7
//	F1        = 2*0.75*0.6 / (0.75+0.6) = 0.6666...
func TestConfusionMatrix_Metrics_HandComputed(t *testing.T) {
	m := ConfusionMatrix{TP: 3, FP: 1, FN: 2, TN: 4}
	got := m.Metrics()

	checkRatio(t, "Precision", got.Precision, true, 0.75)
	checkRatio(t, "Recall", got.Recall, true, 0.6)
	checkRatio(t, "FPR", got.FPR, true, 0.2)
	checkRatio(t, "FNR", got.FNR, true, 0.4)
	checkRatio(t, "Accuracy", got.Accuracy, true, 0.7)
	// Se calcula con variables float64 (no constantes) a propósito:
	// una expresión constante como "2*0.75*0.6/(0.75+0.6)" la evalúa
	// el compilador con precisión arbitraria y redondea al final,
	// dando un bit distinto al de la misma fórmula calculada en
	// tiempo de ejecución (que sí hace cada paso en float64) — la
	// diferencia es de 1 ULP, no un error real, pero rompía la
	// comparación exacta de checkRatio.
	var precisionValue, recallValue float64 = 0.75, 0.6
	wantF1 := 2 * precisionValue * recallValue / (precisionValue + recallValue)
	checkRatio(t, "F1", got.F1, true, wantF1)
}

// TestConfusionMatrix_Metrics_AllZero comprueba que, sin ningún dato
// (matriz vacía), las cinco métricas son N/A — no 0%, no 100%.
func TestConfusionMatrix_Metrics_AllZero(t *testing.T) {
	got := ConfusionMatrix{}.Metrics()

	checkRatio(t, "Precision", got.Precision, false, 0)
	checkRatio(t, "Recall", got.Recall, false, 0)
	checkRatio(t, "FPR", got.FPR, false, 0)
	checkRatio(t, "FNR", got.FNR, false, 0)
	checkRatio(t, "Accuracy", got.Accuracy, false, 0)
	checkRatio(t, "F1", got.F1, false, 0)
}

// TestConfusionMatrix_Metrics_F1_UndefinedWhenEitherInputIsUndefined
// cubre los dos casos en que F1 tiene que ser N/A porque Precision o
// Recall ya lo eran — nunca calculando 2*0*algo/algo como si el 0
// fuera un valor real.
func TestConfusionMatrix_Metrics_F1_UndefinedWhenEitherInputIsUndefined(t *testing.T) {
	// TP=0, FP=2, FN=0, TN=5: Precision definida (=0), Recall N/A
	// (0+0). F1 tiene que seguir a Recall y quedar N/A.
	got := ConfusionMatrix{TP: 0, FP: 2, FN: 0, TN: 5}.Metrics()
	checkRatio(t, "F1", got.F1, false, 0)

	// TP=0, FP=0, FN=3, TN=5: espejo — Recall definida (=0), Precision
	// N/A (0+0).
	got = ConfusionMatrix{TP: 0, FP: 0, FN: 3, TN: 5}.Metrics()
	checkRatio(t, "F1", got.F1, false, 0)
}

// TestConfusionMatrix_Metrics_F1_UndefinedWhenBothZero cubre el tercer
// caso posible: Precision Y Recall están AMBAS definidas, pero ambas
// dan exactamente 0 (TP=0 con FP>0 y FN>0 a la vez) — F1 sería 0/0,
// así que también tiene que quedar N/A, no "0".
func TestConfusionMatrix_Metrics_F1_UndefinedWhenBothZero(t *testing.T) {
	got := ConfusionMatrix{TP: 0, FP: 2, FN: 3, TN: 5}.Metrics()
	checkRatio(t, "Precision", got.Precision, true, 0)
	checkRatio(t, "Recall", got.Recall, true, 0)
	checkRatio(t, "F1", got.F1, false, 0)
}

// TestConfusionMatrix_Metrics_PrecisionDefinedWithoutPositives es el
// caso que corrige la idea de que "0% de tráfico malicioso implica
// todo N/A": acá no hay NINGÚN positivo real (TP+FN=0, como pasaría en
// el escenario de 0%), pero el motor SÍ predijo positivo dos veces —
// las dos equivocadas (FP=2). Cada métrica depende de su propio
// denominador:
//
//	Precision = 0 / (0+2) = 0    (definida: el motor sí predijo positivo)
//	Recall    = 0 / (0+0)        (N/A: no había ningún positivo real)
//	FPR       = 2 / (2+5) = 0.2857...
//	FNR       = 0 / (0+0)        (N/A: mismo motivo que Recall)
//	Accuracy  = 5 / 7            (siempre definida si hay al menos un evento)
func TestConfusionMatrix_Metrics_PrecisionDefinedWithoutPositives(t *testing.T) {
	m := ConfusionMatrix{TP: 0, FP: 2, FN: 0, TN: 5}
	got := m.Metrics()

	checkRatio(t, "Precision", got.Precision, true, 0)
	checkRatio(t, "Recall", got.Recall, false, 0)
	checkRatio(t, "FPR", got.FPR, true, 2.0/7.0)
	checkRatio(t, "FNR", got.FNR, false, 0)
	checkRatio(t, "Accuracy", got.Accuracy, true, 5.0/7.0)
}

// TestConfusionMatrix_Metrics_RecallDefinedWithoutPredictedPositives es
// el espejo del test anterior: hay positivos reales (FN=3), pero el
// motor nunca predijo positivo ni una vez (TP=0, FP=0) — un motor que
// permite todo. Acá Recall SÍ está definido (y da 0%), pero Precision
// no tiene sentido calcularla (0/0).
func TestConfusionMatrix_Metrics_RecallDefinedWithoutPredictedPositives(t *testing.T) {
	m := ConfusionMatrix{TP: 0, FP: 0, FN: 3, TN: 5}
	got := m.Metrics()

	checkRatio(t, "Precision", got.Precision, false, 0)
	checkRatio(t, "Recall", got.Recall, true, 0)
	checkRatio(t, "FNR", got.FNR, true, 1)
}

func TestBuildConfusionMatrix_StrictVsBroadPolicy(t *testing.T) {
	records := []JoinedRecord{
		{RequestID: "r-1", Label: groundtruth.LabelLegit, Decision: fakeDecision("r-1", decision.ActionChallenge)},
		{RequestID: "r-2", Label: groundtruth.LabelCredentialStuffing, Decision: fakeDecision("r-2", decision.ActionChallenge)},
		{RequestID: "r-3", Label: groundtruth.LabelSlowScan, Decision: fakeDecision("r-3", decision.ActionBlock)},
		{RequestID: "r-4", Label: groundtruth.LabelLegit, Decision: fakeDecision("r-4", decision.ActionAllow)},
	}

	strict := BuildConfusionMatrix(records, PolicyStrict)
	// Con la política estricta, solo BLOCK cuenta como positivo: r-1
	// (CHALLENGE, legit) y r-2 (CHALLENGE, ataque) cuentan como
	// negativos predichos.
	wantStrict := ConfusionMatrix{TP: 1, FP: 0, FN: 1, TN: 2}
	if strict != wantStrict {
		t.Errorf("strict matrix = %+v, want %+v", strict, wantStrict)
	}

	broad := BuildConfusionMatrix(records, PolicyBroad)
	// Con la política amplia, CHALLENGE también cuenta como positivo:
	// r-1 pasa a ser un falso positivo, r-2 pasa a ser un verdadero
	// positivo.
	wantBroad := ConfusionMatrix{TP: 2, FP: 1, FN: 0, TN: 1}
	if broad != wantBroad {
		t.Errorf("broad matrix = %+v, want %+v", broad, wantBroad)
	}
}

// TestPolicy_IsPositive_MatchesInternalRule confirma que el método
// exportado IsPositive (para que internal/tuning pueda reusar la
// misma regla sin duplicarla) da exactamente los mismos resultados que
// ya prueba TestBuildConfusionMatrix_StrictVsBroadPolicy
// indirectamente.
func TestPolicy_IsPositive_MatchesInternalRule(t *testing.T) {
	tests := []struct {
		action     decision.Action
		wantStrict bool
		wantBroad  bool
	}{
		{decision.ActionAllow, false, false},
		{decision.ActionChallenge, false, true},
		{decision.ActionBlock, true, true},
	}
	for _, tc := range tests {
		if got := PolicyStrict.IsPositive(tc.action); got != tc.wantStrict {
			t.Errorf("PolicyStrict.IsPositive(%v) = %v, want %v", tc.action, got, tc.wantStrict)
		}
		if got := PolicyBroad.IsPositive(tc.action); got != tc.wantBroad {
			t.Errorf("PolicyBroad.IsPositive(%v) = %v, want %v", tc.action, got, tc.wantBroad)
		}
	}
}
