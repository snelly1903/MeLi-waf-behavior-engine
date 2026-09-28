package tuning

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func legitEvent(seed uint64, requestID string, action decision.Action, confidence float64, csTriggered, ssTriggered bool, anomalyEval anomaly.DebugEvaluation) EventDiagnostic {
	return EventDiagnostic{
		Seed:               seed,
		Ratio:              0,
		RequestID:          requestID,
		Label:              groundtruth.LabelLegit,
		Decision:           decision.Decision{Action: action, ConfidenceScore: confidence, AttackVector: decision.AttackVectorUnknown},
		CredentialStuffing: finding.Finding{Triggered: csTriggered},
		SlowScan:           finding.Finding{Triggered: ssTriggered},
		Anomaly:            []anomaly.DebugEvaluation{anomalyEval},
	}
}

// TestAnalyzeAnomalyFalsePositives_ConfirmsPrincipalExplicitly cubre
// el punto central del Punto de Control 2: para un FP real, se
// verifica EXPLÍCITAMENTE (no por eliminación) que los otros dos
// detectores no dispararon.
func TestAnalyzeAnomalyFalsePositives_ConfirmsPrincipalExplicitly(t *testing.T) {
	diagnostics := []EventDiagnostic{
		legitEvent(101, "r-1", decision.ActionChallenge, 0.42, false, false, anomaly.DebugEvaluation{
			Scope: "ip:1", Triggered: true, CombinedScore: 0.55, RiskScore: 0.42,
			ZScores: map[string]float64{"without_referer_ratio_z": 9.8},
		}),
		legitEvent(101, "r-2", decision.ActionAllow, 0, false, false, anomaly.DebugEvaluation{
			Scope: "ip:2", Triggered: false, CombinedScore: 0.10,
		}),
	}

	diag := AnalyzeAnomalyFalsePositives(diagnostics, eval.PolicyBroad)

	if len(diag.FPRows) != 1 {
		t.Fatalf("FPRows = %d, want 1", len(diag.FPRows))
	}
	row := diag.FPRows[0]
	if !row.PrincipalDetectorConfirmed {
		t.Error("PrincipalDetectorConfirmed = false, want true (los otros dos detectores no dispararon)")
	}
	if row.RequestID != "r-1" || row.Seed != 101 {
		t.Errorf("row = %+v, want RequestID=r-1 Seed=101", row)
	}
	if row.CombinedScore != 0.55 {
		t.Errorf("CombinedScore = %v, want 0.55", row.CombinedScore)
	}
	if row.ZScores["without_referer_ratio_z"] != 9.8 {
		t.Errorf("ZScores[without_referer_ratio_z] = %v, want 9.8", row.ZScores["without_referer_ratio_z"])
	}
}

// TestAnalyzeAnomalyFalsePositives_FlagsWhenAnotherDetectorAlsoFired
// confirma que, si por algún motivo otro detector SÍ disparó para el
// mismo evento, PrincipalDetectorConfirmed queda en false — nunca se
// afirma "fue anomaly" sin la prueba explícita.
func TestAnalyzeAnomalyFalsePositives_FlagsWhenAnotherDetectorAlsoFired(t *testing.T) {
	diagnostics := []EventDiagnostic{
		legitEvent(101, "r-1", decision.ActionChallenge, 0.42, true /* cs también disparó */, false, anomaly.DebugEvaluation{
			Scope: "ip:1", Triggered: true, CombinedScore: 0.55, RiskScore: 0.42,
		}),
	}
	diag := AnalyzeAnomalyFalsePositives(diagnostics, eval.PolicyBroad)
	if diag.FPRows[0].PrincipalDetectorConfirmed {
		t.Error("PrincipalDetectorConfirmed = true, want false (credential_stuffing también disparó para este evento)")
	}
}

// TestAnalyzeAnomalyFalsePositives_ByAction_SeparatesAllowFromChallenge
// confirma que la distribución de score se separa por Action, tal
// como se pidió explícitamente.
func TestAnalyzeAnomalyFalsePositives_ByAction_SeparatesAllowFromChallenge(t *testing.T) {
	diagnostics := []EventDiagnostic{
		legitEvent(101, "r-1", decision.ActionAllow, 0, false, false, anomaly.DebugEvaluation{Triggered: false, CombinedScore: 0.10}),
		legitEvent(101, "r-2", decision.ActionAllow, 0, false, false, anomaly.DebugEvaluation{Triggered: false, CombinedScore: 0.20}),
		legitEvent(101, "r-3", decision.ActionChallenge, 0.40, false, false, anomaly.DebugEvaluation{Triggered: true, CombinedScore: 0.50, RiskScore: 0.40}),
	}
	diag := AnalyzeAnomalyFalsePositives(diagnostics, eval.PolicyBroad)

	var allowBucket, challengeBucket *AnomalyScoreBucket
	for i := range diag.ByAction {
		switch diag.ByAction[i].Action {
		case decision.ActionAllow:
			allowBucket = &diag.ByAction[i]
		case decision.ActionChallenge:
			challengeBucket = &diag.ByAction[i]
		}
	}
	if allowBucket == nil || allowBucket.Combined.N != 2 {
		t.Fatalf("allowBucket = %+v, want N=2", allowBucket)
	}
	if challengeBucket == nil || challengeBucket.Combined.N != 1 {
		t.Fatalf("challengeBucket = %+v, want N=1", challengeBucket)
	}
	if challengeBucket.Combined.Max != 0.50 {
		t.Errorf("challengeBucket.Combined.Max = %v, want 0.50", challengeBucket.Combined.Max)
	}
}
