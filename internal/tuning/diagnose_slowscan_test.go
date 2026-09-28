package tuning

import (
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

func slowScanEvent(seed uint64, ratio int, requestID, ip string, triggered bool, gate slowscan.GateMetrics) EventDiagnostic {
	return EventDiagnostic{
		Seed:          seed,
		Ratio:         ratio,
		RequestID:     requestID,
		Label:         groundtruth.LabelSlowScan,
		SlowScan:      finding.Finding{Triggered: triggered},
		SlowScanGates: []slowscan.GateMetrics{gate},
	}
}

func testSlowScanConfig() slowscan.Config {
	return slowscan.Config{
		Window:                  time.Hour, // no importa para este test
		MinRequests:             15,
		MinDistinctPaths:        10,
		MinNotFoundRatio:        0.5,
		MinRouteEntropy:         0.6,
		MinNovelPathRatio:       0.5,
		MaxVisitorsForNovelPath: 2,
		Weights:                 slowscan.ScoreWeights{Requests: 1, Paths: 1, NotFound: 1, Entropy: 1, Novelty: 1, Referer: 1},
		ScoreFloor:              0.2,
	}
}

// TestAnalyzeSlowScanCampaigns_DetectedLate_ReportsGateJustBeforeDetection
// cubre el caso central pedido: una campaña de 5 requests que
// dispara en el 5to — el reporte tiene que mostrar el estado del gate
// en el 4to request (inmediatamente antes), no en el momento de la
// detección (donde, por definición, ya pasa todo).
func TestAnalyzeSlowScanCampaigns_DetectedLate_ReportsGateJustBeforeDetection(t *testing.T) {
	events := []EventDiagnostic{
		slowScanEvent(101, 30, "r-1", "ip1", false, slowscan.GateMetrics{TotalRequests: 5, DistinctPaths: 5, NotFoundRatio: 1.0, RouteEntropy: 1.0, NovelPathRatio: 1.0}),
		slowScanEvent(101, 30, "r-2", "ip1", false, slowscan.GateMetrics{TotalRequests: 10, DistinctPaths: 10, NotFoundRatio: 1.0, RouteEntropy: 1.0, NovelPathRatio: 1.0}),
		slowScanEvent(101, 30, "r-3", "ip1", false, slowscan.GateMetrics{TotalRequests: 14, DistinctPaths: 14, NotFoundRatio: 1.0, RouteEntropy: 1.0, NovelPathRatio: 1.0}), // TotalRequests todavía < 15
		slowScanEvent(101, 30, "r-4", "ip1", true, slowscan.GateMetrics{TotalRequests: 15, DistinctPaths: 15, NotFoundRatio: 1.0, RouteEntropy: 1.0, NovelPathRatio: 1.0}),  // dispara acá
	}
	// El campaignKey se deriva de slowScanScope, que usa el último
	// elemento de SlowScanGates — para que coincida entre eventos,
	// hay que fijar el mismo Scope en los cuatro.
	for i := range events {
		events[i].SlowScanGates[0].Scope = "ip:1"
	}

	campaigns := AnalyzeSlowScanCampaigns(events, testSlowScanConfig())
	if len(campaigns) != 1 {
		t.Fatalf("campaigns = %d, want 1", len(campaigns))
	}
	c := campaigns[0]

	if !c.DetectedEventually {
		t.Fatal("DetectedEventually = false, want true")
	}
	if c.FirstDetectionRequestIndex != 4 {
		t.Errorf("FirstDetectionRequestIndex = %d, want 4", c.FirstDetectionRequestIndex)
	}
	if c.RequestsBeforeDetection != 3 {
		t.Errorf("RequestsBeforeDetection = %d, want 3", c.RequestsBeforeDetection)
	}
	// El gate reportado tiene que ser el del 3er evento (TotalRequests=14),
	// NO el del 4to (donde ya dispara).
	if c.GateAtLimit.TotalRequests != 14 {
		t.Errorf("GateAtLimit.TotalRequests = %d, want 14 (el request inmediatamente antes de la detección)", c.GateAtLimit.TotalRequests)
	}
	if len(c.LimitingGates) != 1 {
		t.Fatalf("LimitingGates = %v, want exactamente 1 condición limitante (TotalRequests)", c.LimitingGates)
	}
}

// TestAnalyzeSlowScanCampaigns_NeverDetected_ReportsLastEvent cubre
// una campaña que nunca cruza el gate — el reporte tiene que mostrar
// el estado en el ÚLTIMO evento, y DetectedEventually en false (nunca
// disimulado).
func TestAnalyzeSlowScanCampaigns_NeverDetected_ReportsLastEvent(t *testing.T) {
	events := []EventDiagnostic{
		slowScanEvent(102, 30, "r-1", "ip2", false, slowscan.GateMetrics{TotalRequests: 3, DistinctPaths: 3, NotFoundRatio: 1.0, RouteEntropy: 1.0, NovelPathRatio: 1.0}),
		slowScanEvent(102, 30, "r-2", "ip2", false, slowscan.GateMetrics{TotalRequests: 6, DistinctPaths: 6, NotFoundRatio: 1.0, RouteEntropy: 1.0, NovelPathRatio: 1.0}),
	}
	for i := range events {
		events[i].SlowScanGates[0].Scope = "ip:2"
	}

	campaigns := AnalyzeSlowScanCampaigns(events, testSlowScanConfig())
	c := campaigns[0]

	if c.DetectedEventually {
		t.Error("DetectedEventually = true, want false")
	}
	if c.FirstDetectionRequestIndex != 0 {
		t.Errorf("FirstDetectionRequestIndex = %d, want 0", c.FirstDetectionRequestIndex)
	}
	if c.RequestsBeforeDetection != c.TotalRequests {
		t.Errorf("RequestsBeforeDetection = %d, want %d (=TotalRequests, nunca detectada)", c.RequestsBeforeDetection, c.TotalRequests)
	}
	if c.GateAtLimit.TotalRequests != 6 {
		t.Errorf("GateAtLimit.TotalRequests = %d, want 6 (el último evento de la campaña)", c.GateAtLimit.TotalRequests)
	}
}

// TestAnalyzeSlowScanCampaigns_MultipleCampaigns_SeparatedByScopeAndSeed
// confirma que dos IPs distintas son dos campañas distintas, incluso
// con la misma ratio y seed.
func TestAnalyzeSlowScanCampaigns_MultipleCampaigns_SeparatedByScopeAndSeed(t *testing.T) {
	e1 := slowScanEvent(101, 30, "r-1", "ip1", false, slowscan.GateMetrics{TotalRequests: 1})
	e1.SlowScanGates[0].Scope = "ip:1"
	e2 := slowScanEvent(101, 30, "r-2", "ip2", false, slowscan.GateMetrics{TotalRequests: 1})
	e2.SlowScanGates[0].Scope = "ip:2"

	campaigns := AnalyzeSlowScanCampaigns([]EventDiagnostic{e1, e2}, testSlowScanConfig())
	if len(campaigns) != 2 {
		t.Fatalf("campaigns = %d, want 2", len(campaigns))
	}
}

func TestCampaignSizeDistribution_HandComputed(t *testing.T) {
	campaigns := []CampaignGateAnalysis{{TotalRequests: 5}, {TotalRequests: 10}, {TotalRequests: 15}}
	dist := CampaignSizeDistribution(campaigns)
	if dist.N != 3 || dist.Min != 5 || dist.Max != 15 {
		t.Errorf("dist = %+v, want N=3 Min=5 Max=15", dist)
	}
}
