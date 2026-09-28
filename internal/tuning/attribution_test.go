package tuning

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func attrEvent(label groundtruth.Label, action decision.Action, csTriggered, ssTriggered, anTriggered bool) EventDiagnostic {
	return EventDiagnostic{
		Label:              label,
		Decision:           decision.Decision{Action: action},
		CredentialStuffing: finding.Finding{Triggered: csTriggered},
		SlowScan:           finding.Finding{Triggered: ssTriggered},
		Anomaly:            []anomaly.DebugEvaluation{{Triggered: anTriggered}},
	}
}

// TestComputeMitigationAttribution_FourCategories cubre las cuatro
// combinaciones posibles para credential_stuffing: solo su propio
// detector, detector propio + anomaly, solo anomaly, y ninguno de los
// dos (señal cruzada) — nunca mezcladas.
func TestComputeMitigationAttribution_FourCategories(t *testing.T) {
	diagnostics := []EventDiagnostic{
		attrEvent(groundtruth.LabelCredentialStuffing, decision.ActionChallenge, true, false, false), // solo cs
		attrEvent(groundtruth.LabelCredentialStuffing, decision.ActionChallenge, true, false, true),  // cs + anomaly
		attrEvent(groundtruth.LabelCredentialStuffing, decision.ActionChallenge, false, false, true), // solo anomaly
		attrEvent(groundtruth.LabelCredentialStuffing, decision.ActionChallenge, false, true, false), // señal cruzada (slow_scan)
		attrEvent(groundtruth.LabelCredentialStuffing, decision.ActionAllow, false, false, false),    // no mitigado -- no cuenta
	}

	result := ComputeMitigationAttribution(diagnostics, eval.PolicyBroad)

	var cs *MitigationAttribution
	for i := range result {
		if result[i].Vector == groundtruth.LabelCredentialStuffing {
			cs = &result[i]
		}
	}
	if cs == nil {
		t.Fatal("no se encontró el resultado de credential_stuffing")
	}
	if cs.Mitigated != 4 {
		t.Errorf("Mitigated = %d, want 4 (el ALLOW no cuenta)", cs.Mitigated)
	}
	if cs.DetectorOnly != 1 {
		t.Errorf("DetectorOnly = %d, want 1", cs.DetectorOnly)
	}
	if cs.WithAnomalyAssist != 1 {
		t.Errorf("WithAnomalyAssist = %d, want 1", cs.WithAnomalyAssist)
	}
	if cs.AnomalyOnly != 1 {
		t.Errorf("AnomalyOnly = %d, want 1", cs.AnomalyOnly)
	}
	if cs.Neither != 1 {
		t.Errorf("Neither = %d, want 1 (señal cruzada de slow_scan)", cs.Neither)
	}
}

func TestComputeMitigationAttribution_ReturnsBothVectors(t *testing.T) {
	result := ComputeMitigationAttribution(nil, eval.PolicyBroad)
	if len(result) != 2 {
		t.Fatalf("len(result) = %d, want 2 (credential_stuffing y slow_scan siempre presentes)", len(result))
	}
}
