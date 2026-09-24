package eval

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// TestEvaluateDecisions_InvalidDecisionIsExcludedNotAllow confirma el
// requisito explícito de la tarea 0.8: una decisión que no pasa
// decision.Validate() no se cuenta silenciosamente como ALLOW, y
// tampoco aparece duplicada en MissingDecisionIDs además de en
// InvalidDecisionIDs.
func TestEvaluateDecisions_InvalidDecisionIsExcludedNotAllow(t *testing.T) {
	labels := map[string]groundtruth.Label{
		"r-1": groundtruth.LabelLegit,
		"r-2": groundtruth.LabelCredentialStuffing,
	}
	// r-2 llega con una decisión BLOCK inválida (sin explanation ni
	// contributing_signals) — decision.Validate la rechaza.
	decisionsResult := LoadDecisionsResult{
		Decisions: []decision.Decision{
			fakeDecision("r-1", decision.ActionAllow),
		},
		InvalidIDs: []string{"r-2"},
	}

	result := EvaluateDecisions(LoadLabelsResult{Labels: labels}, decisionsResult)

	if len(result.Issues.InvalidDecisionIDs) != 1 || result.Issues.InvalidDecisionIDs[0] != "r-2" {
		t.Errorf("InvalidDecisionIDs = %v, want [r-2]", result.Issues.InvalidDecisionIDs)
	}
	if len(result.Issues.MissingDecisionIDs) != 0 {
		t.Errorf("MissingDecisionIDs = %v, want none (r-2 is invalid, not missing)", result.Issues.MissingDecisionIDs)
	}
	if result.Issues.Clean() {
		t.Error("Issues.Clean() = true, want false (r-2 is invalid)")
	}
	// r-2 no entra al cálculo: solo r-1 (legit, ALLOW) queda cruzado.
	if result.TotalJoined != 1 {
		t.Errorf("TotalJoined = %d, want 1", result.TotalJoined)
	}
}

// TestEvaluateDecisions_CorruptLinesMarkDirty confirma que las líneas
// no interpretables de decisions.jsonl también ensucian Issues.Clean().
func TestEvaluateDecisions_CorruptLinesMarkDirty(t *testing.T) {
	labels := map[string]groundtruth.Label{"r-1": groundtruth.LabelLegit}
	decisionsResult := LoadDecisionsResult{
		Decisions:    []decision.Decision{fakeDecision("r-1", decision.ActionAllow)},
		CorruptLines: []int{7},
	}

	result := EvaluateDecisions(LoadLabelsResult{Labels: labels}, decisionsResult)

	if result.Issues.Clean() {
		t.Error("Issues.Clean() = true, want false (line 7 is corrupt)")
	}
	if len(result.Issues.CorruptDecisionLines) != 1 || result.Issues.CorruptDecisionLines[0] != 7 {
		t.Errorf("CorruptDecisionLines = %v, want [7]", result.Issues.CorruptDecisionLines)
	}
}

// TestEvaluateDecisions_ConfusionMatrixTotalsMatchEvaluatedRecords es
// la comprobación defensiva pedida explícitamente: TP+TN+FP+FN tiene
// que coincidir exactamente con el número de registros evaluados, en
// las dos políticas, incluso cuando hay decisiones inválidas o
// corruptas de por medio (esos registros quedan afuera de la matriz,
// nunca cuentan "gratis" en ningún casillero).
func TestEvaluateDecisions_ConfusionMatrixTotalsMatchEvaluatedRecords(t *testing.T) {
	labels := sampleLabels()
	decisions := decideAllowAll(labels)

	decisionsResult := LoadDecisionsResult{
		Decisions:    decisions,
		InvalidIDs:   []string{"nonexistent-but-tracked"},
		CorruptLines: []int{3},
	}
	result := EvaluateDecisions(LoadLabelsResult{Labels: labels}, decisionsResult)

	if got := result.Strict.Matrix.Total(); got != result.TotalJoined {
		t.Errorf("strict matrix total = %d, want %d (TotalJoined)", got, result.TotalJoined)
	}
	if got := result.Broad.Matrix.Total(); got != result.TotalJoined {
		t.Errorf("broad matrix total = %d, want %d (TotalJoined)", got, result.TotalJoined)
	}
}
