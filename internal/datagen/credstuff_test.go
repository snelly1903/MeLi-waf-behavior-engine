package datagen

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

var campaignStart = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

func TestGenerateCredentialStuffingCampaign_Reproducible(t *testing.T) {
	a := GenerateCredentialStuffingCampaign(NewRNG(100), DefaultCredentialStuffingCampaign, campaignStart)
	b := GenerateCredentialStuffingCampaign(NewRNG(100), DefaultCredentialStuffingCampaign, campaignStart)

	dataA, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("json.Marshal(a): %v", err)
	}
	dataB, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("json.Marshal(b): %v", err)
	}
	if string(dataA) != string(dataB) {
		t.Fatal("same seed produced different credential stuffing output")
	}
}

func TestGenerateCredentialStuffingCampaign_EventsPassValidator(t *testing.T) {
	events := GenerateCredentialStuffingCampaign(NewRNG(1), DefaultCredentialStuffingCampaign, campaignStart)
	if len(events) == 0 {
		t.Fatal("campaign generated zero events")
	}
	for i, le := range events {
		if err := validatorAsOfEachEvent(le); err != nil {
			t.Errorf("event %d (ip=%v): %v", i, le.Event.ClientIP, err)
		}
	}
}

func TestGenerateCredentialStuffingCampaign_DistinctIPsWithinAttemptBounds(t *testing.T) {
	cfg := DefaultCredentialStuffingCampaign
	events := GenerateCredentialStuffingCampaign(NewRNG(2), cfg, campaignStart)

	attemptsPerIP := make(map[string]int)
	for _, le := range events {
		attemptsPerIP[le.Event.ClientIP.String()]++
	}

	if len(attemptsPerIP) != cfg.IPCount {
		t.Fatalf("campaign used %d distinct IPs, want exactly %d", len(attemptsPerIP), cfg.IPCount)
	}

	for ip, n := range attemptsPerIP {
		if n < cfg.MinAttemptsPerIP || n > cfg.MaxAttemptsPerIP {
			t.Errorf("IP %s had %d attempts, want between %d and %d (the low individual rate is what makes this attack invisible to a per-IP rate limit)",
				ip, n, cfg.MinAttemptsPerIP, cfg.MaxAttemptsPerIP)
		}
	}
}

func TestGenerateCredentialStuffingCampaign_AccountDiversity(t *testing.T) {
	events := GenerateCredentialStuffingCampaign(NewRNG(3), DefaultCredentialStuffingCampaign, campaignStart)

	distinct := make(map[string]bool)
	for _, le := range events {
		distinct[le.Event.LoginUserHash] = true
	}

	ratio := float64(len(distinct)) / float64(len(events))
	if ratio < 0.8 {
		t.Fatalf("distinct account ratio = %.2f, want > 0.8 (the attack tries a different account almost every time)", ratio)
	}
}

func TestGenerateCredentialStuffingCampaign_StatusCodeMix(t *testing.T) {
	events := GenerateCredentialStuffingCampaign(NewRNG(4), DefaultCredentialStuffingCampaign, campaignStart)

	var failures, allowedOther int
	for _, le := range events {
		switch le.Event.StatusCode {
		case 401, 403:
			failures++
		case 200:
			// éxito ocasional, esperado
		default:
			allowedOther++
		}
	}

	if allowedOther != 0 {
		t.Errorf("found %d events with a status code outside {200, 401, 403}", allowedOther)
	}
	ratio := float64(failures) / float64(len(events))
	if ratio < 0.9 {
		t.Fatalf("failure (401+403) ratio = %.2f, want > 0.9", ratio)
	}
}

func TestGenerateCredentialStuffingCampaign_UniqueRequestIDs(t *testing.T) {
	events := GenerateCredentialStuffingCampaign(NewRNG(5), DefaultCredentialStuffingCampaign, campaignStart)
	seen := make(map[string]bool, len(events))
	for _, le := range events {
		if seen[le.Event.RequestID] {
			t.Fatalf("duplicate request_id: %s", le.Event.RequestID)
		}
		seen[le.Event.RequestID] = true
	}
}

func TestGenerateCredentialStuffingCampaign_TimestampsSortedAndWithinWindow(t *testing.T) {
	cfg := DefaultCredentialStuffingCampaign
	events := GenerateCredentialStuffingCampaign(NewRNG(6), cfg, campaignStart)

	end := campaignStart.Add(cfg.Window)
	for i, le := range events {
		if le.Event.Timestamp.Before(campaignStart) || le.Event.Timestamp.After(end) {
			t.Errorf("event %d timestamp %v is outside the campaign window [%v, %v]", i, le.Event.Timestamp, campaignStart, end)
		}
		if i > 0 && le.Event.Timestamp.Before(events[i-1].Event.Timestamp) {
			t.Fatalf("timestamps not sorted at index %d", i)
		}
	}
}

func TestGenerateCredentialStuffingCampaign_AllEventsLabeled(t *testing.T) {
	events := GenerateCredentialStuffingCampaign(NewRNG(7), DefaultCredentialStuffingCampaign, campaignStart)
	for _, le := range events {
		if le.Label != groundtruth.LabelCredentialStuffing {
			t.Errorf("event labeled %q, want %q", le.Label, groundtruth.LabelCredentialStuffing)
		}
	}
}

// TestGenerateCredentialStuffingCampaign_PayloadNeverCarriesLabel es una
// capa extra de confianza específica de este generador, además de la
// garantía genérica ya probada en internal/groundtruth (tarea 0.3).
func TestGenerateCredentialStuffingCampaign_PayloadNeverCarriesLabel(t *testing.T) {
	events := GenerateCredentialStuffingCampaign(NewRNG(8), DefaultCredentialStuffingCampaign, campaignStart)
	for _, le := range events {
		data, err := json.Marshal(le.Payload())
		if err != nil {
			t.Fatalf("json.Marshal(le.Payload()): %v", err)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if _, exists := decoded["label"]; exists {
			t.Fatalf("payload has a %q key: %s", "label", data)
		}
	}
}

func TestIPPool_DistinctAddrs_AreUniqueAndWithinPrefix(t *testing.T) {
	rng := NewRNG(9)
	addrs := PoolHostingSim.DistinctAddrs(rng, 150)

	if len(addrs) != 150 {
		t.Fatalf("DistinctAddrs(150) returned %d addresses", len(addrs))
	}
	seen := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		if seen[a.String()] {
			t.Fatalf("duplicate address: %v", a)
		}
		seen[a.String()] = true
		if !PoolHostingSim.Prefix.Contains(a) {
			t.Fatalf("address %v is outside %v", a, PoolHostingSim.Prefix)
		}
	}
}

func TestIPPool_DistinctAddrs_PanicsWhenExceedingCapacity(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("DistinctAddrs(300) on a /24 did not panic")
		}
	}()
	PoolHostingSim.DistinctAddrs(NewRNG(1), 300)
}
