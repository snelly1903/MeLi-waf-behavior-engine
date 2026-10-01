// Prueba las métricas de la matriz de confusión y las políticas estricta y amplia.
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

func TestConfusionMatrix_Metrics_HandComputed(t *testing.T) {
	m := ConfusionMatrix{TP: 3, FP: 1, FN: 2, TN: 4}
	got := m.Metrics()

	checkRatio(t, "Precision", got.Precision, true, 0.75)
	checkRatio(t, "Recall", got.Recall, true, 0.6)
	checkRatio(t, "FPR", got.FPR, true, 0.2)
	checkRatio(t, "FNR", got.FNR, true, 0.4)
	checkRatio(t, "Accuracy", got.Accuracy, true, 0.7)
	var precisionValue, recallValue float64 = 0.75, 0.6
	wantF1 := 2 * precisionValue * recallValue / (precisionValue + recallValue)
	checkRatio(t, "F1", got.F1, true, wantF1)
}

func TestConfusionMatrix_Metrics_AllZero(t *testing.T) {
	got := ConfusionMatrix{}.Metrics()

	checkRatio(t, "Precision", got.Precision, false, 0)
	checkRatio(t, "Recall", got.Recall, false, 0)
	checkRatio(t, "FPR", got.FPR, false, 0)
	checkRatio(t, "FNR", got.FNR, false, 0)
	checkRatio(t, "Accuracy", got.Accuracy, false, 0)
	checkRatio(t, "F1", got.F1, false, 0)
}

func TestConfusionMatrix_Metrics_F1_UndefinedWhenEitherInputIsUndefined(t *testing.T) {
	got := ConfusionMatrix{TP: 0, FP: 2, FN: 0, TN: 5}.Metrics()
	checkRatio(t, "F1", got.F1, false, 0)

	got = ConfusionMatrix{TP: 0, FP: 0, FN: 3, TN: 5}.Metrics()
	checkRatio(t, "F1", got.F1, false, 0)
}

func TestConfusionMatrix_Metrics_F1_UndefinedWhenBothZero(t *testing.T) {
	got := ConfusionMatrix{TP: 0, FP: 2, FN: 3, TN: 5}.Metrics()
	checkRatio(t, "Precision", got.Precision, true, 0)
	checkRatio(t, "Recall", got.Recall, true, 0)
	checkRatio(t, "F1", got.F1, false, 0)
}

func TestConfusionMatrix_Metrics_PrecisionDefinedWithoutPositives(t *testing.T) {
	m := ConfusionMatrix{TP: 0, FP: 2, FN: 0, TN: 5}
	got := m.Metrics()

	checkRatio(t, "Precision", got.Precision, true, 0)
	checkRatio(t, "Recall", got.Recall, false, 0)
	checkRatio(t, "FPR", got.FPR, true, 2.0/7.0)
	checkRatio(t, "FNR", got.FNR, false, 0)
	checkRatio(t, "Accuracy", got.Accuracy, true, 5.0/7.0)
}

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
	wantStrict := ConfusionMatrix{TP: 1, FP: 0, FN: 1, TN: 2}
	if strict != wantStrict {
		t.Errorf("strict matrix = %+v, want %+v", strict, wantStrict)
	}

	broad := BuildConfusionMatrix(records, PolicyBroad)
	wantBroad := ConfusionMatrix{TP: 2, FP: 1, FN: 0, TN: 1}
	if broad != wantBroad {
		t.Errorf("broad matrix = %+v, want %+v", broad, wantBroad)
	}
}

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
