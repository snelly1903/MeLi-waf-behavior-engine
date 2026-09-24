package datagen

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func TestGenerateSlowScanSession_Reproducible(t *testing.T) {
	ip := PoolHostingSim.RandomAddr(NewRNG(500))

	a := GenerateSlowScanSession(NewRNG(50), DefaultSlowScanProfile, campaignStart, ip)
	b := GenerateSlowScanSession(NewRNG(50), DefaultSlowScanProfile, campaignStart, ip)

	dataA, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("json.Marshal(a): %v", err)
	}
	dataB, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("json.Marshal(b): %v", err)
	}
	if string(dataA) != string(dataB) {
		t.Fatal("same seed produced different slow-scan output")
	}
}

func TestGenerateSlowScanSession_EventsPassValidator(t *testing.T) {
	rng := NewRNG(51)
	ip := PoolHostingSim.RandomAddr(rng)
	events := GenerateSlowScanSession(rng, DefaultSlowScanProfile, campaignStart, ip)
	if len(events) == 0 {
		t.Fatal("session generated zero events")
	}
	for i, le := range events {
		if err := validatorAsOfEachEvent(le); err != nil {
			t.Errorf("event %d (%s %s): %v", i, le.Event.Method, le.Event.Path, err)
		}
	}
}

func TestGenerateSlowScanSession_GapsWithinBounds(t *testing.T) {
	profile := DefaultSlowScanProfile
	rng := NewRNG(52)
	ip := PoolHostingSim.RandomAddr(rng)
	events := GenerateSlowScanSession(rng, profile, campaignStart, ip)

	for i := 1; i < len(events); i++ {
		gap := events[i].Event.Timestamp.Sub(events[i-1].Event.Timestamp)
		if gap < profile.MinGap || gap > profile.MaxGap {
			t.Fatalf("gap between event %d and %d is %v, want between %v and %v", i-1, i, gap, profile.MinGap, profile.MaxGap)
		}
	}
}

// TestSlowScanPathDiversity_HigherThanLegitNavegante es una comprobación
// comparativa, no un umbral absoluto: la entropía de rutas del escaneo
// lento tiene que ser claramente mayor que la de un navegante legítimo
// con el mismo número de requests, porque esa es justamente la señal
// que describe el PDF ("entropía de rutas solicitadas") — comparar
// contra el propio dataset es más confiable que fijar un número mágico.
func TestSlowScanPathDiversity_HigherThanLegitNavegante(t *testing.T) {
	rngScan := NewRNG(53)
	scanIP := PoolHostingSim.RandomAddr(rngScan)
	scanEvents := GenerateSlowScanSession(rngScan, DefaultSlowScanProfile, campaignStart, scanIP)

	rngNav := NewRNG(53)
	navIP := ProfileNavegante.Pool.RandomAddr(rngNav)
	navEvents := GenerateLegitSession(rngNav, ProfileNavegante, campaignStart, navIP)

	scanRatio := distinctPathRatio(scanEvents)
	navRatio := distinctPathRatio(navEvents)

	if scanRatio <= navRatio {
		t.Fatalf("slow-scan path diversity (%.2f) is not higher than a legit navegante's (%.2f)", scanRatio, navRatio)
	}
}

func distinctPathRatio(events []groundtruth.LabeledEvent) float64 {
	distinct := make(map[string]bool)
	for _, le := range events {
		distinct[le.Event.Path] = true
	}
	return float64(len(distinct)) / float64(len(events))
}

func TestGenerateSlowScanSession_404RatioHighButNotAbsolute(t *testing.T) {
	rng := NewRNG(54)
	ip := PoolHostingSim.RandomAddr(rng)
	events := GenerateSlowScanSession(rng, DefaultSlowScanProfile, campaignStart, ip)

	var notFound, ok int
	for _, le := range events {
		switch le.Event.StatusCode {
		case 404:
			notFound++
		case 200:
			ok++
		}
	}

	if notFound == 0 {
		t.Fatal("no 404 responses at all — the sensitive-path exploration signal would be missing")
	}
	if ok == 0 {
		t.Fatal("no 200 responses at all — the session never touched a real, valid path")
	}
	ratio := float64(notFound) / float64(len(events))
	if ratio <= 0.5 {
		t.Fatalf("404 ratio = %.2f, want > 0.5 (most requests target the wordlist, which doesn't exist)", ratio)
	}
}

func TestGenerateSlowScanSession_UsesOnlyDeclaredPaths(t *testing.T) {
	profile := DefaultSlowScanProfile
	sensitive := make(map[string]bool)
	for _, p := range profile.SensitivePaths {
		sensitive[p] = true
	}
	valid := make(map[string]bool)
	for _, p := range profile.ValidPaths {
		valid[p] = true
	}

	rng := NewRNG(55)
	ip := PoolHostingSim.RandomAddr(rng)
	events := GenerateSlowScanSession(rng, profile, campaignStart, ip)

	for _, le := range events {
		if !sensitive[le.Event.Path] && !valid[le.Event.Path] {
			t.Errorf("event used an undeclared path: %q", le.Event.Path)
		}
	}
}

func TestGenerateSlowScanSession_FuzzParamsOnlyOnValidPaths(t *testing.T) {
	profile := DefaultSlowScanProfile
	sensitive := make(map[string]bool)
	for _, p := range profile.SensitivePaths {
		sensitive[p] = true
	}

	rng := NewRNG(56)
	ip := PoolHostingSim.RandomAddr(rng)
	events := GenerateSlowScanSession(rng, profile, campaignStart, ip)

	for _, le := range events {
		if len(le.Event.QueryParams) > 0 && sensitive[le.Event.Path] {
			t.Errorf("a sensitive-path event (%q) carried query params, want fuzz params only on valid paths", le.Event.Path)
		}
	}
}

func TestGenerateSlowScanSession_UniqueRequestIDs(t *testing.T) {
	rng := NewRNG(57)
	ip := PoolHostingSim.RandomAddr(rng)
	events := GenerateSlowScanSession(rng, DefaultSlowScanProfile, campaignStart, ip)

	seen := make(map[string]bool, len(events))
	for _, le := range events {
		if seen[le.Event.RequestID] {
			t.Fatalf("duplicate request_id: %s", le.Event.RequestID)
		}
		seen[le.Event.RequestID] = true
	}
}

func TestGenerateSlowScanSession_AllEventsLabeled(t *testing.T) {
	rng := NewRNG(58)
	ip := PoolHostingSim.RandomAddr(rng)
	for _, le := range GenerateSlowScanSession(rng, DefaultSlowScanProfile, campaignStart, ip) {
		if le.Label != groundtruth.LabelSlowScan {
			t.Errorf("event labeled %q, want %q", le.Label, groundtruth.LabelSlowScan)
		}
	}
}

func TestGenerateSlowScanCampaign_Reproducible(t *testing.T) {
	a := GenerateSlowScanCampaign(NewRNG(60), DefaultSlowScanProfile, 10, campaignStart, 20*time.Minute)
	b := GenerateSlowScanCampaign(NewRNG(60), DefaultSlowScanProfile, 10, campaignStart, 20*time.Minute)

	dataA, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("json.Marshal(a): %v", err)
	}
	dataB, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("json.Marshal(b): %v", err)
	}
	if string(dataA) != string(dataB) {
		t.Fatal("same seed produced different slow-scan campaign output")
	}
}

func TestGenerateSlowScanCampaign_IndependentScannersUseDistinctIPs(t *testing.T) {
	const scanners = 8
	events := GenerateSlowScanCampaign(NewRNG(61), DefaultSlowScanProfile, scanners, campaignStart, 15*time.Minute)

	ips := make(map[string]bool)
	for _, le := range events {
		ips[le.Event.ClientIP.String()] = true
	}
	if len(ips) != scanners {
		t.Fatalf("campaign used %d distinct IPs, want exactly %d", len(ips), scanners)
	}
}

func TestGenerateSlowScanCampaign_TimestampsSorted(t *testing.T) {
	events := GenerateSlowScanCampaign(NewRNG(62), DefaultSlowScanProfile, 6, campaignStart, 15*time.Minute)
	for i := 1; i < len(events); i++ {
		if events[i].Event.Timestamp.Before(events[i-1].Event.Timestamp) {
			t.Fatalf("timestamps not sorted at index %d", i)
		}
	}
}
