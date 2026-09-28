package tuning

import (
	"net/netip"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func windowTestCSConfig() credstuffing.Config {
	return credstuffing.Config{
		MinDistinctIPs:      20,
		MinDistinctAccounts: 15,
		MinAttempts:         25,
		MinFailedRatio:      0.6,
		Weights:             credstuffing.ScoreWeights{IPs: 1, Accounts: 1, Attempts: 1, Ratio: 1},
		ScoreFloor:          0.2,
	}
}

// TestAnalyzeWindowSensitivity_WiderWindowNeverShrinksMax cubre el
// caso central: una campaña de baja intensidad, esparcida en el
// tiempo, cuyo máximo de IPs-por-ventana con Window=30m es 2 (las dos
// primeras) porque la 3ra IP llega fuera de esa ventana relativa a
// las anteriores — con Window=90m las tres entran juntas, así que el
// máximo tiene que subir a 3, nunca bajar.
func TestAnalyzeWindowSensitivity_WiderWindowNeverShrinksMax(t *testing.T) {
	ip1 := netip.MustParseAddr("192.0.2.1")
	ip2 := netip.MustParseAddr("192.0.2.2")
	ip3 := netip.MustParseAddr("192.0.2.3")

	events := []groundtruth.LabeledEvent{
		csLabeledEvent("r-1", 0, ip1, "acct-A"),
		csLabeledEvent("r-2", 20*time.Minute, ip2, "acct-B"),
		csLabeledEvent("r-3", 40*time.Minute, ip3, "acct-C"),
	}
	scenario := datagen.Scenario{
		Events: events,
		Stats:  datagen.ScenarioStats{Seed: 101, TargetMaliciousRatio: 0.10},
	}
	resolver := fakeCampaignResolver{ip1: "asn:64512", ip2: "asn:64512", ip3: "asn:64512"}

	rows, err := AnalyzeWindowSensitivity(scenario, resolver, windowTestCSConfig(), []time.Duration{30 * time.Minute, 90 * time.Minute})
	if err != nil {
		t.Fatalf("AnalyzeWindowSensitivity: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (una por Window)", len(rows))
	}

	byWindow := make(map[time.Duration]WindowSensitivityRow)
	for _, r := range rows {
		byWindow[r.Window] = r
	}

	if got := byWindow[30*time.Minute].MaxDistinctIPs; got != 2 {
		t.Errorf("MaxDistinctIPs con Window=30m = %d, want 2 (ip1 sale de la ventana de 30m antes de que llegue ip3)", got)
	}
	if got := byWindow[90*time.Minute].MaxDistinctIPs; got != 3 {
		t.Errorf("MaxDistinctIPs con Window=90m = %d, want 3 (las tres caben juntas)", got)
	}
	if byWindow[30*time.Minute].CrossesMinDistinctIPs {
		t.Error("CrossesMinDistinctIPs con Window=30m = true, want false (2<20)")
	}
}

// TestAnalyzeWindowSensitivity_IgnoresLabelForObserveButNotForMax
// confirma que el detector observa TODOS los eventos (igual que en
// producción, donde no conoce el ground truth), pero el máximo
// reportado solo se actualiza en los eventos etiquetados
// credential_stuffing de la campaña — un evento legítimo del mismo
// grupo de red puede sumar a las observaciones internas sin
// convertirse él mismo en una fila de máximo.
func TestAnalyzeWindowSensitivity_IgnoresLabelForObserveButNotForMax(t *testing.T) {
	ip1 := netip.MustParseAddr("192.0.2.1")
	ip2 := netip.MustParseAddr("192.0.2.2")

	events := []groundtruth.LabeledEvent{
		csLabeledEvent("r-1", 0, ip1, "acct-A"),
		{
			Label: groundtruth.LabelLegit,
			Event: csLabeledEvent("r-2", time.Minute, ip2, "acct-B").Event,
		},
	}
	scenario := datagen.Scenario{
		Events: events,
		Stats:  datagen.ScenarioStats{Seed: 101, TargetMaliciousRatio: 0.10},
	}
	resolver := fakeCampaignResolver{ip1: "asn:64512", ip2: "asn:64512"}

	rows, err := AnalyzeWindowSensitivity(scenario, resolver, windowTestCSConfig(), []time.Duration{30 * time.Minute})
	if err != nil {
		t.Fatalf("AnalyzeWindowSensitivity: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	// El gate ya vio las 2 IPs (Observe corrió para ambas), pero el
	// máximo solo se registra en el evento CS-etiquetado (r-1), que
	// vio 1 sola IP en ese momento.
	if rows[0].MaxDistinctIPs != 1 {
		t.Errorf("MaxDistinctIPs = %d, want 1 (solo se mide en el evento CS-etiquetado, antes de que llegue el legítimo)", rows[0].MaxDistinctIPs)
	}
}
