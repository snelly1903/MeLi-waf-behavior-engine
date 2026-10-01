// Prueba que las decisiones inválidas y las líneas corruptas se reflejen en la evaluación.
package eval

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func TestEvaluateDecisions_InvalidDecisionIsExcludedNotAllow(t *testing.T) {
	labels := map[string]groundtruth.Label{
		"r-1": groundtruth.LabelLegit,
		"r-2": groundtruth.LabelCredentialStuffing,
	}
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
	if result.TotalJoined != 1 {
		t.Errorf("TotalJoined = %d, want 1", result.TotalJoined)
	}
}

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
