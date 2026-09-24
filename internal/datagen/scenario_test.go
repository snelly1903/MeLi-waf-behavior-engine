package datagen

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func TestBuildScenario_Reproducible(t *testing.T) {
	for _, ratio := range []float64{0, 0.10, 0.30} {
		t.Run(ratioName(ratio), func(t *testing.T) {
			cfg := DefaultScenarioConfig(123, ratio)

			a := BuildScenario(cfg)
			b := BuildScenario(cfg)

			dataA, err := json.Marshal(a)
			if err != nil {
				t.Fatalf("json.Marshal(a): %v", err)
			}
			dataB, err := json.Marshal(b)
			if err != nil {
				t.Fatalf("json.Marshal(b): %v", err)
			}
			if string(dataA) != string(dataB) {
				t.Fatal("same seed produced a different scenario")
			}
		})
	}
}

func ratioName(r float64) string {
	switch r {
	case 0:
		return "0pct"
	case 0.10:
		return "10pct"
	case 0.30:
		return "30pct"
	default:
		return "other"
	}
}

func TestBuildScenario_ZeroPercent_HasNoMaliciousTraffic(t *testing.T) {
	s := BuildScenario(DefaultScenarioConfig(1, 0))

	if s.Stats.CredentialStuffingEvents != 0 || s.Stats.SlowScanEvents != 0 {
		t.Fatalf("0%% scenario has malicious events: %+v", s.Stats)
	}
	if s.Stats.AchievedMaliciousRatio != 0 {
		t.Fatalf("achieved ratio = %v, want 0", s.Stats.AchievedMaliciousRatio)
	}
	for _, le := range s.Events {
		if le.Label != groundtruth.LabelLegit {
			t.Fatalf("0%% scenario contains a non-legit event: %+v", le)
		}
	}
}

// TestBuildScenario_ZeroPercent_StillHasHardCases confirma que el
// escenario "sin ataques" no es un caso de juguete: sigue conteniendo
// los casos difíciles (NAT de oficina, cliente API sin referer/sesión,
// algún 404 legítimo, tráfico legítimo sobre el ASN de hosting) — así
// la medición de falsos positivos sobre este escenario es honesta.
func TestBuildScenario_ZeroPercent_StillHasHardCases(t *testing.T) {
	s := BuildScenario(DefaultScenarioConfig(1, 0))

	var hasNoRefererNoSession, has404, hasHostingASNTraffic bool
	ipCounts := make(map[string]int)

	for _, le := range s.Events {
		e := le.Event
		if e.Referer == "" && e.SessionID == "" {
			hasNoRefererNoSession = true
		}
		if e.StatusCode == 404 {
			has404 = true
		}
		if PoolHostingSim.Prefix.Contains(e.ClientIP) {
			hasHostingASNTraffic = true
		}
		ipCounts[e.ClientIP.String()]++
	}

	if !hasNoRefererNoSession {
		t.Error("no legit event without referer and without session — the API-client trap is missing")
	}
	if !has404 {
		t.Error("no legit 404 at all — the broken-link trap is missing")
	}
	if !hasHostingASNTraffic {
		t.Error("no legit traffic on the hosting ASN — ProfileHostedTenant is missing")
	}

	sharedIPFound := false
	for _, n := range ipCounts {
		if n > 20 { // un único empleado ronda ~16 eventos; un cluster de 6 supera esto largo
			sharedIPFound = true
		}
	}
	if !sharedIPFound {
		t.Error("no IP with a high event count — the office NAT trap seems missing")
	}
}

func TestBuildScenario_AchievedRatioWithinTolerance(t *testing.T) {
	const tolerance = 0.03 // 3 puntos porcentuales

	for _, ratio := range []float64{0.10, 0.30} {
		t.Run(ratioName(ratio), func(t *testing.T) {
			s := BuildScenario(DefaultScenarioConfig(42, ratio))
			diff := s.Stats.AchievedMaliciousRatio - ratio
			if diff < 0 {
				diff = -diff
			}
			if diff > tolerance {
				t.Fatalf("achieved ratio %.4f is more than %.2f away from target %.2f",
					s.Stats.AchievedMaliciousRatio, tolerance, ratio)
			}
		})
	}
}

func TestBuildScenario_UniqueRequestIDs(t *testing.T) {
	s := BuildScenario(DefaultScenarioConfig(7, 0.30))

	seen := make(map[string]bool, len(s.Events))
	for _, le := range s.Events {
		if seen[le.Event.RequestID] {
			t.Fatalf("duplicate request_id across the merged scenario: %s", le.Event.RequestID)
		}
		seen[le.Event.RequestID] = true
	}
}

func TestBuildScenario_TimestampsSorted(t *testing.T) {
	s := BuildScenario(DefaultScenarioConfig(8, 0.30))
	for i := 1; i < len(s.Events); i++ {
		if s.Events[i].Event.Timestamp.Before(s.Events[i-1].Event.Timestamp) {
			t.Fatalf("timestamps not sorted at index %d", i)
		}
	}
}

// TestBuildScenario_CampaignsFitWithinWindow comprueba que las dos
// campañas de ataque quedan contenidas dentro de la ventana total del
// escenario — necesario para que el futuro motor, con sus ventanas de
// tiempo configurables, tenga margen suficiente para operar sobre un
// solo archivo de escenario.
func TestBuildScenario_CampaignsFitWithinWindow(t *testing.T) {
	cfg := DefaultScenarioConfig(9, 0.30)
	s := BuildScenario(cfg)
	end := cfg.Start.Add(cfg.Window)

	for _, le := range s.Events {
		if le.Label == groundtruth.LabelLegit {
			continue
		}
		ts := le.Event.Timestamp
		if ts.Before(cfg.Start) || ts.After(end) {
			t.Errorf("attack event outside the scenario window [%v, %v]: %v (%s)", cfg.Start, end, ts, le.Label)
		}
	}
}

// TestBuildScenario_HostedTenantAndAttackerIPsAreDisjoint confirma la
// garantía del punto 9 de la tarea 0.6: en este escenario controlado,
// ninguna IP de ProfileHostedTenant coincide con una IP atacante.
func TestBuildScenario_HostedTenantAndAttackerIPsAreDisjoint(t *testing.T) {
	s := BuildScenario(DefaultScenarioConfig(10, 0.30))

	tenantIPs := make(map[string]bool)
	attackerIPs := make(map[string]bool)
	for _, le := range s.Events {
		ip := le.Event.ClientIP.String()
		switch le.Label {
		case groundtruth.LabelLegit:
			if PoolHostingSim.Prefix.Contains(le.Event.ClientIP) {
				tenantIPs[ip] = true
			}
		case groundtruth.LabelCredentialStuffing, groundtruth.LabelSlowScan:
			attackerIPs[ip] = true
		}
	}

	for ip := range tenantIPs {
		if attackerIPs[ip] {
			t.Errorf("IP %s is used both by a legit hosted tenant and by an attacker in the same scenario", ip)
		}
	}
}

func TestWriteScenario_EventsAndLabelsShareExactlyTheSameRequestIDs(t *testing.T) {
	s := BuildScenario(DefaultScenarioConfig(11, 0.10))
	dir := t.TempDir()

	if err := WriteScenario(dir, s); err != nil {
		t.Fatalf("WriteScenario: %v", err)
	}

	eventIDs := readRequestIDs(t, filepath.Join(dir, "events.jsonl"))
	labelIDs := readRequestIDs(t, filepath.Join(dir, "labels.jsonl"))

	if len(eventIDs) != len(s.Events) {
		t.Fatalf("events.jsonl has %d lines, want %d", len(eventIDs), len(s.Events))
	}
	if len(labelIDs) != len(s.Events) {
		t.Fatalf("labels.jsonl has %d lines, want %d", len(labelIDs), len(s.Events))
	}
	for id := range eventIDs {
		if !labelIDs[id] {
			t.Errorf("request_id %s is in events.jsonl but not in labels.jsonl", id)
		}
	}
	for id := range labelIDs {
		if !eventIDs[id] {
			t.Errorf("request_id %s is in labels.jsonl but not in events.jsonl", id)
		}
	}
}

func readRequestIDs(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("os.Open(%s): %v", path, err)
	}
	defer f.Close()

	ids := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var rec struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("json.Unmarshal line: %v", err)
		}
		ids[rec.RequestID] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	return ids
}

// TestWriteScenario_EventsFileNeverCarriesLabel es la comprobación de
// aislamiento del ground truth, esta vez sobre el ARCHIVO ya escrito a
// disco (no solo en memoria) — la garantía real que le importa al
// "motor WAF nunca recibe ni lee las etiquetas".
func TestWriteScenario_EventsFileNeverCarriesLabel(t *testing.T) {
	s := BuildScenario(DefaultScenarioConfig(12, 0.10))
	dir := t.TempDir()

	if err := WriteScenario(dir, s); err != nil {
		t.Fatalf("WriteScenario: %v", err)
	}

	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("os.Open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(scanner.Bytes(), &decoded); err != nil {
			t.Fatalf("line %d: json.Unmarshal: %v", lineNum, err)
		}
		if _, exists := decoded["label"]; exists {
			t.Fatalf("line %d of events.jsonl has a %q key: %s", lineNum, "label", scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	if lineNum != len(s.Events) {
		t.Fatalf("events.jsonl has %d lines, want %d", lineNum, len(s.Events))
	}
}

func TestWriteScenario_ManifestIsReproducible(t *testing.T) {
	cfg := DefaultScenarioConfig(13, 0.30)

	dirA := t.TempDir()
	if err := WriteScenario(dirA, BuildScenario(cfg)); err != nil {
		t.Fatalf("WriteScenario (a): %v", err)
	}
	dirB := t.TempDir()
	if err := WriteScenario(dirB, BuildScenario(cfg)); err != nil {
		t.Fatalf("WriteScenario (b): %v", err)
	}

	manifestA, err := os.ReadFile(filepath.Join(dirA, "manifest.json"))
	if err != nil {
		t.Fatalf("os.ReadFile (a): %v", err)
	}
	manifestB, err := os.ReadFile(filepath.Join(dirB, "manifest.json"))
	if err != nil {
		t.Fatalf("os.ReadFile (b): %v", err)
	}
	if string(manifestA) != string(manifestB) {
		t.Fatal("manifest.json differs between two runs with the same seed")
	}
}
