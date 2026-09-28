package tuning

import (
	"net/netip"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func decisionFor(le groundtruth.LabeledEvent, action decision.Action) decision.Decision {
	return decision.Decision{
		RequestID: le.Event.RequestID,
		Timestamp: le.Event.Timestamp,
		EntityID:  "ip:" + le.Event.ClientIP.String(),
		Action:    action,
	}
}

// TestComputeDetectionDelay_CredentialStuffing_GroupsByASNNotByIP es
// el test central del ajuste 1: dos IPs DISTINTAS, del mismo grupo de
// red simulado, participando de la MISMA campaña de credential
// stuffing distribuido — igual que hace el detector real (tarea 1.3),
// nunca una campaña por IP. La primera decisión positiva de
// CUALQUIERA de las dos IPs cuenta como la detección de la campaña
// completa.
func TestComputeDetectionDelay_CredentialStuffing_GroupsByASNNotByIP(t *testing.T) {
	ipA := netip.MustParseAddr("192.0.2.10")
	ipB := netip.MustParseAddr("192.0.2.20")
	resolver := fakeCampaignResolver{ipA: "asn:64512", ipB: "asn:64512"}

	events := []groundtruth.LabeledEvent{
		labeledEvent(groundtruth.LabelCredentialStuffing, "r-1", 0, ipA, "/login", 401),
		labeledEvent(groundtruth.LabelCredentialStuffing, "r-2", time.Minute, ipB, "/login", 401),
		labeledEvent(groundtruth.LabelCredentialStuffing, "r-3", 2*time.Minute, ipA, "/login", 401),
	}
	decisions := []decision.Decision{
		decisionFor(events[0], decision.ActionAllow),
		decisionFor(events[1], decision.ActionBlock), // la 2da IP es la que dispara
		decisionFor(events[2], decision.ActionAllow),
	}

	delays := ComputeDetectionDelay(events, decisions, resolver, eval.PolicyBroad)

	if len(delays) != 1 {
		t.Fatalf("delays = %d campañas, want 1 (las dos IPs son la misma campaña de red)", len(delays))
	}
	d := delays[0]
	if d.CampaignKey != "network:asn:64512" {
		t.Errorf("CampaignKey = %q, want %q", d.CampaignKey, "network:asn:64512")
	}
	if d.TotalRequests != 3 {
		t.Errorf("TotalRequests = %d, want 3 (suma de las dos IPs)", d.TotalRequests)
	}
	if !d.Detected {
		t.Fatal("Detected = false, want true")
	}
	// La detección fue el 2do request de la campaña (r-2), sin
	// importar que viniera de una IP distinta a la del primero.
	if d.RequestsToDetection != 2 {
		t.Errorf("RequestsToDetection = %d, want 2", d.RequestsToDetection)
	}
	if d.TimeToDetection != time.Minute {
		t.Errorf("TimeToDetection = %v, want %v", d.TimeToDetection, time.Minute)
	}
}

// TestComputeDetectionDelay_SlowScan_OneCampaignPerIP confirma que,
// para slow_scan, dos IPs escaneando por separado son DOS campañas
// distintas (nunca se agrupan como en credential stuffing) — cada
// escáner es su propia entidad, igual que ve internal/slowscan.Detector.
func TestComputeDetectionDelay_SlowScan_OneCampaignPerIP(t *testing.T) {
	ipA := netip.MustParseAddr("192.0.2.30")
	ipB := netip.MustParseAddr("192.0.2.40")
	resolver := fakeCampaignResolver{}

	events := []groundtruth.LabeledEvent{
		labeledEvent(groundtruth.LabelSlowScan, "r-1", 0, ipA, "/a", 404),
		labeledEvent(groundtruth.LabelSlowScan, "r-2", time.Second, ipB, "/b", 404),
	}
	decisions := []decision.Decision{
		decisionFor(events[0], decision.ActionAllow),
		decisionFor(events[1], decision.ActionAllow),
	}

	delays := ComputeDetectionDelay(events, decisions, resolver, eval.PolicyBroad)

	if len(delays) != 2 {
		t.Fatalf("delays = %d campañas, want 2 (una por IP)", len(delays))
	}
	for _, d := range delays {
		if d.Detected {
			t.Errorf("campaign %q Detected = true, want false (ninguna decisión fue positiva)", d.CampaignKey)
		}
		if d.TotalRequests != 1 {
			t.Errorf("campaign %q TotalRequests = %d, want 1", d.CampaignKey, d.TotalRequests)
		}
	}
}

// TestComputeDetectionDelay_NeverDetected_ReportsFalseNotZero
// confirma que una campaña nunca detectada queda con Detected=false y
// que RequestsToDetection/TimeToDetection nunca se leen como si fueran
// datos válidos (0 request, 0 tiempo) — el objetivo explícito de no
// usar esta métrica para esconder falsos negativos iniciales.
func TestComputeDetectionDelay_NeverDetected_ReportsFalseNotZero(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.5")
	resolver := fakeCampaignResolver{}

	events := []groundtruth.LabeledEvent{
		labeledEvent(groundtruth.LabelSlowScan, "r-1", 0, ip, "/a", 404),
		labeledEvent(groundtruth.LabelSlowScan, "r-2", time.Second, ip, "/b", 404),
	}
	decisions := []decision.Decision{
		decisionFor(events[0], decision.ActionAllow),
		decisionFor(events[1], decision.ActionAllow),
	}

	delays := ComputeDetectionDelay(events, decisions, resolver, eval.PolicyBroad)
	if len(delays) != 1 {
		t.Fatalf("delays = %d, want 1", len(delays))
	}
	if delays[0].Detected {
		t.Fatal("Detected = true, want false")
	}
	if delays[0].RequestsToDetection != 0 || delays[0].TimeToDetection != 0 {
		t.Errorf("RequestsToDetection/TimeToDetection deberían quedar en su cero cuando Detected=false, got %d/%v",
			delays[0].RequestsToDetection, delays[0].TimeToDetection)
	}
}

// TestComputeDetectionDelay_LegitTraffic_NeverFormsACampaign confirma
// que el tráfico legítimo nunca aparece en el resultado, aunque
// comparta IP/grupo con tráfico malicioso.
func TestComputeDetectionDelay_LegitTraffic_NeverFormsACampaign(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.50")
	resolver := fakeCampaignResolver{ip: "asn:64512"}

	events := []groundtruth.LabeledEvent{
		labeledEvent(groundtruth.LabelLegit, "r-1", 0, ip, "/", 200),
	}
	decisions := []decision.Decision{decisionFor(events[0], decision.ActionAllow)}

	delays := ComputeDetectionDelay(events, decisions, resolver, eval.PolicyBroad)
	if len(delays) != 0 {
		t.Fatalf("delays = %d, want 0 (tráfico legítimo nunca forma campaña)", len(delays))
	}
}

// TestComputeDetectionDelay_UnresolvedIP_ExcludedNeverGuessed cubre
// una IP de credential stuffing que el resolver no puede resolver a
// ningún grupo — nunca se inventa una campaña para ella.
func TestComputeDetectionDelay_UnresolvedIP_ExcludedNeverGuessed(t *testing.T) {
	ip := netip.MustParseAddr("198.51.100.9")
	resolver := fakeCampaignResolver{} // deliberadamente vacío

	events := []groundtruth.LabeledEvent{
		labeledEvent(groundtruth.LabelCredentialStuffing, "r-1", 0, ip, "/login", 401),
	}
	decisions := []decision.Decision{decisionFor(events[0], decision.ActionAllow)}

	delays := ComputeDetectionDelay(events, decisions, resolver, eval.PolicyBroad)
	if len(delays) != 0 {
		t.Fatalf("delays = %d, want 0 (IP sin resolver, no se inventa un grupo)", len(delays))
	}
}

// TestSummarizeDelay_EventualDetectionRate_NeverHidesZeroDetections
// confirma que la tasa de detección eventual sí baja a 0% (no queda
// N/A) cuando hay campañas pero ninguna fue detectada — distinto del
// caso "cero campañas", que sí es N/A (ver el siguiente test).
func TestSummarizeDelay_EventualDetectionRate_NeverHidesZeroDetections(t *testing.T) {
	delays := []CampaignDelay{
		{Vector: groundtruth.LabelSlowScan, CampaignKey: "ip:1", TotalRequests: 5, Detected: false},
		{Vector: groundtruth.LabelSlowScan, CampaignKey: "ip:2", TotalRequests: 3, Detected: false},
	}
	summaries := SummarizeDelay(delays)
	if len(summaries) != 1 {
		t.Fatalf("summaries = %d, want 1", len(summaries))
	}
	s := summaries[0]
	if !s.EventualDetectionRate.Defined || s.EventualDetectionRate.Value != 0 {
		t.Errorf("EventualDetectionRate = %+v, want {0, true}", s.EventualDetectionRate)
	}
	if s.MeanRequestsToDetection.Defined {
		t.Error("MeanRequestsToDetection.Defined = true, want false (ninguna campaña detectada, promediar no tiene sentido)")
	}
}

// TestSummarizeDelay_NoCampaigns_ReturnsNoSummary confirma que un
// vector sin ninguna campaña en absoluto simplemente no aparece en el
// resultado — nunca un summary con 0/0 disimulado.
func TestSummarizeDelay_NoCampaigns_ReturnsNoSummary(t *testing.T) {
	summaries := SummarizeDelay(nil)
	if len(summaries) != 0 {
		t.Fatalf("summaries = %d, want 0", len(summaries))
	}
}
