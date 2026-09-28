package tuning

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func TestPooledVectorRecall_SumsRawCountsBeforeRecall(t *testing.T) {
	items := []eval.AttackVectorRecall{
		{Vector: groundtruth.LabelCredentialStuffing, TruePositives: 9, FalseNegatives: 1},  // seed grande: recall 0.9, n=10
		{Vector: groundtruth.LabelCredentialStuffing, TruePositives: 1, FalseNegatives: 99}, // seed chico: recall 0.01, n=100
	}
	got := pooledVectorRecall(items)
	if got.TruePositives != 10 || got.FalseNegatives != 100 {
		t.Fatalf("TP/FN pooled = %d/%d, want 10/100", got.TruePositives, got.FalseNegatives)
	}
	// Pooled correcto: 10/110 ≈ 0.0909 -- NUNCA el promedio simple
	// (0.9+0.01)/2 ≈ 0.455, que ignoraría que el segundo seed pesa
	// 10x más eventos que el primero.
	want := 10.0 / 110.0
	if diff := got.Recall.Value - want; !got.Recall.Defined || diff > 0.0001 || diff < -0.0001 {
		t.Errorf("Recall pooled = %+v, want {%.4f, true} (pooled, no promedio simple de 0.455)", got.Recall, want)
	}
}

func TestAggregatePolicySweepRows_PoolsActionsAndVectorRecall(t *testing.T) {
	rows := []PolicySweepRow{
		{
			Candidate: "P1", Ratio: 10,
			Broad:         eval.ConfusionMatrix{TP: 8, FP: 2, FN: 2, TN: 88},
			Strict:        eval.ConfusionMatrix{TP: 3, FP: 0, FN: 7, TN: 90},
			Actions:       ActionDistribution{LegitAllow: 88, LegitChallenge: 2, MaliciousAllow: 2, MaliciousChallenge: 5, MaliciousBlock: 3},
			CSVectorBroad: eval.AttackVectorRecall{Vector: groundtruth.LabelCredentialStuffing, TruePositives: 5, FalseNegatives: 1},
		},
		{
			Candidate: "P1", Ratio: 10,
			Broad:         eval.ConfusionMatrix{TP: 4, FP: 1, FN: 1, TN: 44},
			Strict:        eval.ConfusionMatrix{TP: 1, FP: 0, FN: 4, TN: 45},
			Actions:       ActionDistribution{LegitAllow: 44, LegitChallenge: 1, MaliciousAllow: 1, MaliciousChallenge: 3, MaliciousBlock: 1},
			CSVectorBroad: eval.AttackVectorRecall{Vector: groundtruth.LabelCredentialStuffing, TruePositives: 2, FalseNegatives: 1},
		},
	}
	agg := AggregatePolicySweepRows(rows)

	wantBroad := eval.ConfusionMatrix{TP: 12, FP: 3, FN: 3, TN: 132}
	if agg.Broad != wantBroad {
		t.Errorf("Broad pooled = %+v, want %+v", agg.Broad, wantBroad)
	}
	if agg.Actions.LegitAllow != 132 || agg.Actions.LegitChallenge != 3 {
		t.Errorf("Actions pooled = %+v, want LegitAllow=132 LegitChallenge=3", agg.Actions)
	}
	if agg.CSVectorBroad.TruePositives != 7 || agg.CSVectorBroad.FalseNegatives != 2 {
		t.Errorf("CSVectorBroad pooled = %+v, want TP=7 FN=2", agg.CSVectorBroad)
	}
}

func TestComputePolicySweepStability_IgnoresUndefinedRatios(t *testing.T) {
	rows := []PolicySweepRow{
		{Candidate: "P1", Ratio: 0, FPRBroad: eval.Ratio{Value: 0.02, Defined: true}, RecallBroad: eval.Ratio{Defined: false}},
		{Candidate: "P1", Ratio: 0, FPRBroad: eval.Ratio{Value: 0.06, Defined: true}, RecallBroad: eval.Ratio{Defined: false}},
	}
	s := ComputePolicySweepStability(rows)
	if diff := s.FPRBroadRange - 0.04; diff > 0.0001 || diff < -0.0001 {
		t.Errorf("FPRBroadRange = %.4f, want 0.04", s.FPRBroadRange)
	}
	if s.BroadRecallRange != 0 {
		t.Errorf("BroadRecallRange = %.4f, want 0 (ambos N/A, sin valores)", s.BroadRecallRange)
	}
}
