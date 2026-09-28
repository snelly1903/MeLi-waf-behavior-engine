package tuning

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func diagAt(label groundtruth.Label, action decision.Action, triggered bool, riskScore float64) EventDiagnostic {
	return EventDiagnostic{
		Label:    label,
		Decision: decision.Decision{Action: action, ConfidenceScore: riskScore},
		Anomaly:  []anomaly.DebugEvaluation{{Triggered: triggered, RiskScore: riskScore}},
	}
}

func TestComputeAnomalyTriggerBreakdown_SplitsByFinalAction(t *testing.T) {
	diagnostics := []EventDiagnostic{
		diagAt(groundtruth.LabelLegit, decision.ActionAllow, false, 0),
		diagAt(groundtruth.LabelLegit, decision.ActionAllow, true, 0.3),     // Triggered pero ALLOW
		diagAt(groundtruth.LabelLegit, decision.ActionChallenge, true, 0.5), // Triggered y CHALLENGE
	}
	b := ComputeAnomalyTriggerBreakdown(diagnostics)

	if b.TriggeredCount != 2 {
		t.Errorf("TriggeredCount = %d, want 2", b.TriggeredCount)
	}
	if b.TriggeredAllowCount != 1 {
		t.Errorf("TriggeredAllowCount = %d, want 1", b.TriggeredAllowCount)
	}
	if b.TriggeredChallengeCount != 1 {
		t.Errorf("TriggeredChallengeCount = %d, want 1", b.TriggeredChallengeCount)
	}
}

// TestCompareAnomalyTransitions_ThreeOutcomes cubre las tres
// categorías, sin mezclarlas: un evento que deja de disparar del
// todo, uno que sigue disparando pero termina en ALLOW, y uno que
// sigue siendo positivo sin resolver.
func TestCompareAnomalyTransitions_ThreeOutcomes(t *testing.T) {
	baseline := []EventDiagnostic{
		diagAt(groundtruth.LabelLegit, decision.ActionChallenge, true, 0.55), // r-1: FP en baseline
		diagAt(groundtruth.LabelLegit, decision.ActionChallenge, true, 0.52), // r-2: FP en baseline
		diagAt(groundtruth.LabelLegit, decision.ActionChallenge, true, 0.60), // r-3: FP en baseline
		diagAt(groundtruth.LabelLegit, decision.ActionAllow, false, 0),       // r-4: nunca fue FP
	}
	candidate := []EventDiagnostic{
		diagAt(groundtruth.LabelLegit, decision.ActionAllow, false, 0),       // r-1: ya no dispara
		diagAt(groundtruth.LabelLegit, decision.ActionAllow, true, 0.30),     // r-2: sigue disparando, ahora ALLOW
		diagAt(groundtruth.LabelLegit, decision.ActionChallenge, true, 0.58), // r-3: sigue siendo FP
		diagAt(groundtruth.LabelLegit, decision.ActionAllow, false, 0),       // r-4: irrelevante (nunca fue FP)
	}

	got, err := CompareAnomalyTransitions(baseline, candidate, eval.PolicyBroad)
	if err != nil {
		t.Fatalf("CompareAnomalyTransitions: %v", err)
	}
	want := AnomalyTransitionCounts{NoLongerTriggered: 1, StillTriggeredNowAllow: 1, StillPositive: 1}
	if got != want {
		t.Errorf("got = %+v, want %+v", got, want)
	}
}

func TestCompareAnomalyTransitions_LengthMismatch_ReturnsError(t *testing.T) {
	_, err := CompareAnomalyTransitions([]EventDiagnostic{{}}, []EventDiagnostic{{}, {}}, eval.PolicyBroad)
	if err == nil {
		t.Fatal("error = nil, want un error por longitudes distintas")
	}
}

func TestAggregateSlowScanSweepRows_MeansDefinedValuesOnly(t *testing.T) {
	rows := []SlowScanSweepRow{
		{Candidate: "S1", Seed: 101, FPRAt0: eval.Ratio{Value: 0.02, Defined: true}, BroadRecallAt30: eval.Ratio{Value: 0.4, Defined: true}},
		{Candidate: "S1", Seed: 102, FPRAt0: eval.Ratio{Value: 0.04, Defined: true}, BroadRecallAt30: eval.Ratio{Defined: false}},
	}
	agg := AggregateSlowScanSweepRows(rows)
	if !agg.FPRAt0.Defined || agg.FPRAt0.Value != 0.03 {
		t.Errorf("FPRAt0 = %+v, want {0.03, true}", agg.FPRAt0)
	}
	// Solo un seed tenía BroadRecallAt30 definido -- el promedio tiene
	// que usar solo ese, no tratar el N/A como 0.
	if !agg.BroadRecallAt30.Defined || agg.BroadRecallAt30.Value != 0.4 {
		t.Errorf("BroadRecallAt30 = %+v, want {0.4, true} (promedio solo sobre el seed definido)", agg.BroadRecallAt30)
	}
}
