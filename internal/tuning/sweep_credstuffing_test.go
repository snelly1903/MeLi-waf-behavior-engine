package tuning

import (
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func csDiagWithTrigger(triggered bool) EventDiagnostic {
	return EventDiagnostic{
		Label:              groundtruth.LabelCredentialStuffing,
		CredentialStuffing: finding.Finding{Triggered: triggered},
	}
}

// TestCredentialStuffingDetectorRecall_RequestLevel_NeverUsesDecision
// confirma que la métrica es puramente request-level sobre
// CredentialStuffing.Triggered — nunca sobre la Decision final
// (acá ni siquiera se rellena Decision, y el resultado tiene que ser
// el mismo igual).
func TestCredentialStuffingDetectorRecall_RequestLevel_NeverUsesDecision(t *testing.T) {
	diagnostics := []EventDiagnostic{
		csDiagWithTrigger(true),
		csDiagWithTrigger(true),
		csDiagWithTrigger(false),
		{Label: groundtruth.LabelLegit, CredentialStuffing: finding.Finding{Triggered: true}}, // no cuenta: no es CS
	}
	got := credentialStuffingDetectorRecall(diagnostics)
	if !got.Defined || got.Value != 2.0/3.0 {
		t.Errorf("credentialStuffingDetectorRecall = %+v, want {0.667, true} (2 de 3 eventos CS con gate disparado)", got)
	}
}

func TestCredentialStuffingDetectorRecall_NoCSEvents_Undefined(t *testing.T) {
	got := credentialStuffingDetectorRecall([]EventDiagnostic{{Label: groundtruth.LabelLegit}})
	if got.Defined {
		t.Errorf("Defined = true, want false (0 eventos CS, división por cero evitada)")
	}
}

func TestCsDetectionStats_OnlyAveragesDetectedCampaigns(t *testing.T) {
	campaigns := []CredentialStuffingCampaignAnalysis{
		{DetectedEventually: true, FirstDetectionRequestIndex: 10, TimeToFirstDetection: OptionalDuration{Value: 2 * time.Hour, Defined: true}},
		{DetectedEventually: true, FirstDetectionRequestIndex: 20, TimeToFirstDetection: OptionalDuration{Value: 4 * time.Hour, Defined: true}},
		{DetectedEventually: false, FirstDetectionRequestIndex: 0},
	}
	meanReq, medianReq, meanTime := csDetectionStats(campaigns)
	if !meanReq.Defined || meanReq.Value != 15 {
		t.Errorf("meanReq = %+v, want {15, true} (promedio de 10 y 20, ignorando la no detectada)", meanReq)
	}
	if !medianReq.Defined {
		t.Error("medianReq no definida, want definida")
	}
	if !meanTime.Defined || meanTime.Value != 3*time.Hour {
		t.Errorf("meanTime = %+v, want {3h, true}", meanTime)
	}
}

func TestCsDetectionStats_NoneDetected_Undefined(t *testing.T) {
	meanReq, medianReq, meanTime := csDetectionStats([]CredentialStuffingCampaignAnalysis{{DetectedEventually: false}})
	if meanReq.Defined || medianReq.Defined || meanTime.Defined {
		t.Error("stats definidas con 0 campañas detectadas, want todas N/A")
	}
}

// TestPooledAttributionPct_SumsRawCountsBeforePercentage confirma que
// agregar varias campañas usa los conteos crudos (nunca promedia
// porcentajes ya redondeados de campañas de distinto tamaño).
func TestPooledAttributionPct_SumsRawCountsBeforePercentage(t *testing.T) {
	campaigns := []CredentialStuffingCampaignAnalysis{
		{CredOnlyEvents: 0, AnomOnlyEvents: 90, BothEvents: 0, NeitherEvents: 10}, // 100 eventos, 90% anomaly-only
		{CredOnlyEvents: 0, AnomOnlyEvents: 5, BothEvents: 0, NeitherEvents: 5},   // 10 eventos, 50% anomaly-only
	}
	_, anomOnly, _, _ := pooledAttributionPct(campaigns)
	// Pooled correcto: (90+5)/(100+10) = 95/110 ≈ 86.36%, NUNCA el
	// promedio simple (90+50)/2 = 70%.
	want := 95.0 / 110.0 * 100
	if diff := anomOnly - want; diff > 0.01 || diff < -0.01 {
		t.Errorf("PctAnomalyOnly pooled = %.4f, want %.4f (conteos crudos, no promedio de porcentajes)", anomOnly, want)
	}
}

func TestMeanOptionalDuration_IgnoresUndefined(t *testing.T) {
	got := meanOptionalDuration([]OptionalDuration{
		{Value: 2 * time.Hour, Defined: true},
		{Defined: false},
		{Value: 4 * time.Hour, Defined: true},
	})
	if !got.Defined || got.Value != 3*time.Hour {
		t.Errorf("meanOptionalDuration = %+v, want {3h, true}", got)
	}
}
