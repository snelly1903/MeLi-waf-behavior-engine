package tuning

import (
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func TestSlowScanDetectorRecall_RequestLevel(t *testing.T) {
	diagnostics := []EventDiagnostic{
		{Label: groundtruth.LabelSlowScan, SlowScan: finding.Finding{Triggered: true}},
		{Label: groundtruth.LabelSlowScan, SlowScan: finding.Finding{Triggered: false}},
		{Label: groundtruth.LabelCredentialStuffing, SlowScan: finding.Finding{Triggered: true}}, // no cuenta: no es slow_scan
	}
	got := slowScanDetectorRecall(diagnostics)
	if !got.Defined || got.Value != 0.5 {
		t.Errorf("slowScanDetectorRecall = %+v, want {0.5, true}", got)
	}
}

// TestAggregateDetectorLayerRows_PoolsRawMatricesNotRatios confirma
// que la matriz de confusión agregada es la SUMA cruda de los 3
// seeds (nunca un promedio de Precision/Recall ya calculados por
// separado) — dos seeds de tamaño MUY distinto tienen que pesar según
// su propio volumen, no 50/50.
func TestAggregateDetectorLayerRows_PoolsRawMatricesNotRatios(t *testing.T) {
	rows := []DetectorLayerRow{
		{Candidate: "D0", Ratio: 10, Broad: eval.ConfusionMatrix{TP: 9, FP: 1, FN: 1, TN: 89}}, // seed grande: precision 0.9
		{Candidate: "D0", Ratio: 10, Broad: eval.ConfusionMatrix{TP: 1, FP: 1, FN: 0, TN: 8}},  // seed chico: precision 0.5
	}
	agg := AggregateDetectorLayerRows(rows, nil)

	wantMatrix := eval.ConfusionMatrix{TP: 10, FP: 2, FN: 1, TN: 97}
	if agg.Broad != wantMatrix {
		t.Fatalf("Broad pooled = %+v, want %+v", agg.Broad, wantMatrix)
	}
	// Precision pooled = 10/(10+2) = 0.8333 -- DISTINTO del promedio
	// simple (0.9+0.5)/2 = 0.7, que sería engañoso porque ignora que
	// el primer seed pesa casi 10x más eventos que el segundo.
	wantPrecision := 10.0 / 12.0
	if !agg.PrecisionBroad.Defined {
		t.Fatal("PrecisionBroad no definida")
	}
	if diff := agg.PrecisionBroad.Value - wantPrecision; diff > 0.0001 || diff < -0.0001 {
		t.Errorf("PrecisionBroad pooled = %.4f, want %.4f (pooled, no promedio simple de 0.7)", agg.PrecisionBroad.Value, wantPrecision)
	}
}

func TestAggregateDetectorLayerRows_DelayByVector_UsesPooledDelays(t *testing.T) {
	pooledDelays := []CampaignDelay{
		{Vector: groundtruth.LabelCredentialStuffing, CampaignKey: "network:asn:1", TotalRequests: 10, Detected: true, RequestsToDetection: 5, TimeToDetection: time.Hour},
		{Vector: groundtruth.LabelCredentialStuffing, CampaignKey: "network:asn:2", TotalRequests: 10, Detected: false},
	}
	agg := AggregateDetectorLayerRows([]DetectorLayerRow{{Candidate: "D0", Ratio: 10}}, pooledDelays)

	if len(agg.DelayByVector) != 1 {
		t.Fatalf("DelayByVector = %d entradas, want 1 (solo credential_stuffing)", len(agg.DelayByVector))
	}
	d := agg.DelayByVector[0]
	if d.Campaigns != 2 || d.DetectedCampaigns != 1 {
		t.Errorf("Campaigns/DetectedCampaigns = %d/%d, want 2/1", d.Campaigns, d.DetectedCampaigns)
	}
}

func TestSumMitigationAttribution_SumsIntFieldsAcrossSeeds(t *testing.T) {
	items := []MitigationAttribution{
		{Vector: groundtruth.LabelCredentialStuffing, Mitigated: 10, DetectorOnly: 2, WithAnomalyAssist: 3, AnomalyOnly: 4, Neither: 1},
		{Vector: groundtruth.LabelCredentialStuffing, Mitigated: 5, DetectorOnly: 1, WithAnomalyAssist: 1, AnomalyOnly: 2, Neither: 1},
	}
	sum := SumMitigationAttribution(items)
	want := MitigationAttribution{Vector: groundtruth.LabelCredentialStuffing, Mitigated: 15, DetectorOnly: 3, WithAnomalyAssist: 4, AnomalyOnly: 6, Neither: 2}
	if sum != want {
		t.Errorf("sum = %+v, want %+v", sum, want)
	}
}

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
