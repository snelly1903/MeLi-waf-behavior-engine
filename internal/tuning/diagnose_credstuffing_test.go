package tuning

import (
	"net/netip"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func csLabeledEvent(requestID string, offset time.Duration, ip netip.Addr, account string) groundtruth.LabeledEvent {
	return groundtruth.LabeledEvent{
		Label: groundtruth.LabelCredentialStuffing,
		Event: event.Event{
			RequestID:     requestID,
			Timestamp:     testBase.Add(offset),
			ClientIP:      ip,
			Method:        "POST",
			Path:          "/login",
			StatusCode:    401,
			LoginUserHash: account,
		},
	}
}

func csDiag(seed uint64, ratio int, group string, gateIPs, gateAttempts int, credTriggered, anomTriggered bool) EventDiagnostic {
	return EventDiagnostic{
		Seed:                        seed,
		Ratio:                       ratio,
		Label:                       groundtruth.LabelCredentialStuffing,
		CredentialStuffing:          finding.Finding{Triggered: credTriggered},
		CredentialStuffingGate:      credstuffing.GateMetrics{Group: group, DistinctIPs: gateIPs, TotalAttempts: gateAttempts, Triggered: credTriggered},
		CredentialStuffingGateFound: true,
		Anomaly:                     []anomaly.DebugEvaluation{{Triggered: anomTriggered}},
	}
}

func testCSConfig() credstuffing.Config {
	return credstuffing.Config{
		MinDistinctIPs:      20,
		MinDistinctAccounts: 15,
		MinAttempts:         25,
		MinFailedRatio:      0.6,
	}
}

// TestAnalyzeCredentialStuffingCampaigns_MaxWindowNeverReachesThreshold
// cubre el caso central de esta pasada: una campaña cuyo máximo de
// DistinctIPs-por-ventana, en TODA su vida, nunca cruza
// MinDistinctIPs — el reporte tiene que identificarlo explícitamente
// como el gate limitante, nunca asumirlo.
func TestAnalyzeCredentialStuffingCampaigns_MaxWindowNeverReachesThreshold(t *testing.T) {
	events := []groundtruth.LabeledEvent{
		csLabeledEvent("r-1", 0, netip.MustParseAddr("192.0.2.1"), "acct-A"),
		csLabeledEvent("r-2", time.Minute, netip.MustParseAddr("192.0.2.2"), "acct-B"),
	}
	diagnostics := []EventDiagnostic{
		csDiag(101, 10, "asn:64512", 1, 1, false, false),
		csDiag(101, 10, "asn:64512", 2, 2, false, false), // el máximo de ventana nunca pasa de 2
	}

	campaigns, err := AnalyzeCredentialStuffingCampaigns(events, diagnostics, testCSConfig())
	if err != nil {
		t.Fatalf("AnalyzeCredentialStuffingCampaigns: %v", err)
	}
	if len(campaigns) != 1 {
		t.Fatalf("campaigns = %d, want 1", len(campaigns))
	}
	c := campaigns[0]

	if c.MaxWindowDistinctIPs != 2 {
		t.Errorf("MaxWindowDistinctIPs = %d, want 2", c.MaxWindowDistinctIPs)
	}
	if c.TotalDistinctIPs != 2 {
		t.Errorf("TotalDistinctIPs (ground truth) = %d, want 2", c.TotalDistinctIPs)
	}
	if c.DetectedEventually {
		t.Error("DetectedEventually = true, want false")
	}
	found := false
	for _, g := range c.LimitingGates {
		if g == "MinDistinctIPs(2<20)" {
			found = true
		}
	}
	if !found {
		t.Errorf("LimitingGates = %v, want incluir MinDistinctIPs(2<20)", c.LimitingGates)
	}
}

// TestAnalyzeCredentialStuffingCampaigns_GroupsBySeedRatioAndNetwork
// confirma que dos campañas de seeds/ratios distintos, aunque
// compartan el mismo grupo de red simulado, nunca se mezclan.
func TestAnalyzeCredentialStuffingCampaigns_GroupsBySeedRatioAndNetwork(t *testing.T) {
	events := []groundtruth.LabeledEvent{
		csLabeledEvent("r-1", 0, netip.MustParseAddr("192.0.2.1"), "acct-A"),
		csLabeledEvent("r-2", 0, netip.MustParseAddr("192.0.2.2"), "acct-B"),
	}
	diagnostics := []EventDiagnostic{
		csDiag(101, 10, "asn:64512", 1, 1, false, false),
		csDiag(102, 10, "asn:64512", 1, 1, false, false), // mismo grupo, seed distinto
	}
	campaigns, err := AnalyzeCredentialStuffingCampaigns(events, diagnostics, testCSConfig())
	if err != nil {
		t.Fatalf("AnalyzeCredentialStuffingCampaigns: %v", err)
	}
	if len(campaigns) != 2 {
		t.Fatalf("campaigns = %d, want 2 (seeds distintos, nunca se mezclan)", len(campaigns))
	}
}

// TestAnalyzeCredentialStuffingCampaigns_AttributionPercentagesSumTo100
func TestAnalyzeCredentialStuffingCampaigns_AttributionPercentagesSumTo100(t *testing.T) {
	events := []groundtruth.LabeledEvent{
		csLabeledEvent("r-1", 0, netip.MustParseAddr("192.0.2.1"), "acct-A"),
		csLabeledEvent("r-2", 0, netip.MustParseAddr("192.0.2.2"), "acct-B"),
		csLabeledEvent("r-3", 0, netip.MustParseAddr("192.0.2.3"), "acct-C"),
		csLabeledEvent("r-4", 0, netip.MustParseAddr("192.0.2.4"), "acct-D"),
	}
	diagnostics := []EventDiagnostic{
		csDiag(101, 30, "asn:64512", 1, 1, true, false),  // credential only
		csDiag(101, 30, "asn:64512", 2, 2, true, true),   // both
		csDiag(101, 30, "asn:64512", 3, 3, false, true),  // anomaly only
		csDiag(101, 30, "asn:64512", 4, 4, false, false), // neither
	}
	campaigns, err := AnalyzeCredentialStuffingCampaigns(events, diagnostics, testCSConfig())
	if err != nil {
		t.Fatalf("AnalyzeCredentialStuffingCampaigns: %v", err)
	}
	c := campaigns[0]
	sum := c.PctCredentialOnly + c.PctAnomalyOnly + c.PctBoth + c.PctNeither
	if sum < 99.9 || sum > 100.1 {
		t.Errorf("suma de porcentajes = %.2f, want ≈100", sum)
	}
	if c.PctCredentialOnly != 25 || c.PctAnomalyOnly != 25 || c.PctBoth != 25 || c.PctNeither != 25 {
		t.Errorf("porcentajes = %+v, want 25/25/25/25", c)
	}
}

func TestAnalyzeCredentialStuffingCampaigns_LengthMismatch_ReturnsError(t *testing.T) {
	_, err := AnalyzeCredentialStuffingCampaigns([]groundtruth.LabeledEvent{{}}, []EventDiagnostic{{}, {}}, testCSConfig())
	if err == nil {
		t.Fatal("error = nil, want un error por longitudes distintas")
	}
}
