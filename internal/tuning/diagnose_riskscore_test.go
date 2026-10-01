// Prueba el análisis de distribuciones de risk score.
package tuning

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func riskEvent(label groundtruth.Label, csRisk, ssRisk, anRisk float64, anTriggered bool) EventDiagnostic {
	return EventDiagnostic{
		Label:              label,
		CredentialStuffing: finding.Finding{Triggered: csRisk > 0, RiskScore: csRisk},
		SlowScan:           finding.Finding{Triggered: ssRisk > 0, RiskScore: ssRisk},
		Anomaly:            []anomaly.DebugEvaluation{{Triggered: anTriggered, RiskScore: anRisk}},
	}
}

func TestAnalyzeRiskScoreDistributions_SeparatesMaliciousFromLegit(t *testing.T) {
	diagnostics := []EventDiagnostic{
		riskEvent(groundtruth.LabelLegit, 0, 0, 0, false),
		riskEvent(groundtruth.LabelLegit, 0, 0, 0, false),
		riskEvent(groundtruth.LabelCredentialStuffing, 0.5, 0, 0, false),
		riskEvent(groundtruth.LabelSlowScan, 0, 0.7, 0, false),
	}

	buckets := AnalyzeRiskScoreDistributions(diagnostics)

	find := func(detector, group string) *RiskScoreBucket {
		for i := range buckets {
			if buckets[i].Detector == detector && buckets[i].Group == group {
				return &buckets[i]
			}
		}
		return nil
	}

	csMalicious := find("credential_stuffing", "malicious")
	if csMalicious == nil || csMalicious.Summary.N != 1 || csMalicious.Summary.Max != 0.5 {
		t.Errorf("credential_stuffing/malicious = %+v, want N=1 Max=0.5", csMalicious)
	}
	csLegit := find("credential_stuffing", "legit")
	if csLegit == nil || csLegit.Summary.N != 2 {
		t.Errorf("credential_stuffing/legit = %+v, want N=2", csLegit)
	}
	csOther := find("credential_stuffing", "other_attack")
	if csOther == nil || csOther.Summary.N != 1 {
		t.Errorf("credential_stuffing/other_attack = %+v, want N=1 (el evento de slow_scan)", csOther)
	}

	ssMalicious := find("slow_scan", "malicious")
	if ssMalicious == nil || ssMalicious.Summary.Max != 0.7 {
		t.Errorf("slow_scan/malicious = %+v, want Max=0.7", ssMalicious)
	}
}

func TestAnalyzeRiskScoreDistributions_AnomalyHasNoOwnType_UsesGenericMalicious(t *testing.T) {
	diagnostics := []EventDiagnostic{
		riskEvent(groundtruth.LabelCredentialStuffing, 0, 0, 0.3, true),
		riskEvent(groundtruth.LabelSlowScan, 0, 0, 0.4, true),
		riskEvent(groundtruth.LabelLegit, 0, 0, 0, false),
	}
	buckets := AnalyzeRiskScoreDistributions(diagnostics)

	var anMalicious, anLegit *RiskScoreBucket
	for i := range buckets {
		if buckets[i].Detector != "statistical_anomaly" {
			continue
		}
		switch buckets[i].Group {
		case "malicious":
			anMalicious = &buckets[i]
		case "legit":
			anLegit = &buckets[i]
		}
	}
	if anMalicious == nil || anMalicious.Summary.N != 2 {
		t.Errorf("statistical_anomaly/malicious = %+v, want N=2 (credential_stuffing Y slow_scan juntos)", anMalicious)
	}
	if anLegit == nil || anLegit.Summary.N != 1 {
		t.Errorf("statistical_anomaly/legit = %+v, want N=1", anLegit)
	}
}

func TestAnalyzeRiskScoreDistributions_RiskScoreZero_IncludedNotExcluded(t *testing.T) {
	diagnostics := []EventDiagnostic{
		riskEvent(groundtruth.LabelLegit, 0, 0, 0, false),
	}
	buckets := AnalyzeRiskScoreDistributions(diagnostics)
	for _, b := range buckets {
		if b.Group == "legit" && b.Summary.N != 1 {
			t.Errorf("%s/legit N = %d, want 1 (el evento con RiskScore=0 cuenta)", b.Detector, b.Summary.N)
		}
	}
}
