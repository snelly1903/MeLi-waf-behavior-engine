// Prueba umbrales, ventana deslizante y modos de conteo del rate limit.
package baseline

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

var testBase = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

func mustAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}

func ev(id string, ip netip.Addr, path string, offset time.Duration) event.Event {
	return event.Event{
		RequestID:  id,
		Timestamp:  testBase.Add(offset),
		ClientIP:   ip,
		Method:     "GET",
		Path:       path,
		StatusCode: 200,
	}
}

func evSession(id string, ip netip.Addr, sessionID string, offset time.Duration) event.Event {
	e := ev(id, ip, "/home", offset)
	e.SessionID = sessionID
	return e
}

func actionsOf(decisions []decision.Decision) []decision.Action {
	out := make([]decision.Action, len(decisions))
	for i, d := range decisions {
		out[i] = d.Action
	}
	return out
}

func equalActions(a, b []decision.Action) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDetect_BelowThreshold_AllAllow(t *testing.T) {
	ip := mustAddr("203.0.113.1")
	events := []event.Event{
		ev("r-1", ip, "/", 0),
		ev("r-2", ip, "/", 10*time.Second),
		ev("r-3", ip, "/", 20*time.Second),
	}
	cfg := Config{MaxRequests: 10, Window: time.Minute, Mode: CountModeAll}

	decisions, err := Detect(events, cfg)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	want := []decision.Action{decision.ActionAllow, decision.ActionAllow, decision.ActionAllow}
	if got := actionsOf(decisions); !equalActions(got, want) {
		t.Errorf("actions = %v, want %v", got, want)
	}
}

func TestDetect_ExactThresholdThenFirstOverflow(t *testing.T) {
	ip := mustAddr("203.0.113.2")
	events := []event.Event{
		ev("r-1", ip, "/", 0),
		ev("r-2", ip, "/", 10*time.Second),
		ev("r-3", ip, "/", 20*time.Second),
		ev("r-4", ip, "/", 30*time.Second),
	}
	cfg := Config{MaxRequests: 3, Window: time.Minute, Mode: CountModeAll}

	decisions, err := Detect(events, cfg)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	want := []decision.Action{decision.ActionAllow, decision.ActionAllow, decision.ActionAllow, decision.ActionBlock}
	if got := actionsOf(decisions); !equalActions(got, want) {
		t.Errorf("actions = %v, want %v", got, want)
	}
}

func TestDetect_TwoIPs_IndependentCounters(t *testing.T) {
	ipA := mustAddr("203.0.113.10")
	ipB := mustAddr("203.0.113.20")
	events := []event.Event{
		ev("a-1", ipA, "/", 0),
		ev("b-1", ipB, "/", 1*time.Second),
		ev("a-2", ipA, "/", 2*time.Second),
		ev("b-2", ipB, "/", 3*time.Second),
		ev("a-3", ipA, "/", 4*time.Second),
		ev("b-3", ipB, "/", 5*time.Second),
	}
	cfg := Config{MaxRequests: 3, Window: time.Minute, Mode: CountModeAll}

	decisions, err := Detect(events, cfg)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, d := range decisions {
		if d.Action != decision.ActionAllow {
			t.Errorf("decision for %s = %s, want ALLOW (neither IP reached 4 requests)", d.RequestID, d.Action)
		}
	}
}

func TestDetect_NATManySessions_SameIPStillShared(t *testing.T) {
	ip := mustAddr("203.0.113.30")
	events := []event.Event{
		evSession("r-1", ip, "s-1", 0),
		evSession("r-2", ip, "s-2", 5*time.Second),
		evSession("r-3", ip, "s-3", 10*time.Second),
		evSession("r-4", ip, "s-4", 15*time.Second),
	}
	cfg := Config{MaxRequests: 3, Window: time.Minute, Mode: CountModeAll}

	decisions, err := Detect(events, cfg)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if decisions[3].Action != decision.ActionBlock {
		t.Errorf("4th session behind the shared NAT IP = %s, want BLOCK (known limitation: IP-based counting cannot tell sessions apart)", decisions[3].Action)
	}
}

func TestDetect_SlidingWindow_EventsLeaveWindow(t *testing.T) {
	ip := mustAddr("203.0.113.40")
	events := []event.Event{
		ev("r-1", ip, "/", 0),
		ev("r-2", ip, "/", 5*time.Second),
		ev("r-3", ip, "/", 9*time.Second),
		ev("r-4", ip, "/", 100*time.Second),
	}
	cfg := Config{MaxRequests: 3, Window: time.Minute, Mode: CountModeAll}

	decisions, err := Detect(events, cfg)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if decisions[3].Action != decision.ActionAllow {
		t.Errorf("r-4 = %s, want ALLOW (r-1..r-3 should have left the 60s window)", decisions[3].Action)
	}
}

func TestDetect_Determinism_SameInputSameOutput(t *testing.T) {
	ip := mustAddr("203.0.113.50")
	events := []event.Event{
		ev("r-1", ip, "/", 0),
		ev("r-2", ip, "/", 5*time.Second),
		ev("r-3", ip, "/", 10*time.Second),
		ev("r-4", ip, "/", 15*time.Second),
	}
	cfg := Config{MaxRequests: 2, Window: time.Minute, Mode: CountModeAll}

	first, err := Detect(events, cfg)
	if err != nil {
		t.Fatalf("Detect (1st run): %v", err)
	}
	second, err := Detect(events, cfg)
	if err != nil {
		t.Fatalf("Detect (2nd run): %v", err)
	}
	if !equalActions(actionsOf(first), actionsOf(second)) {
		t.Errorf("two runs over the same input produced different actions: %v vs %v", actionsOf(first), actionsOf(second))
	}
	for i := range first {
		if first[i].ConfidenceScore != second[i].ConfidenceScore {
			t.Errorf("decision %d: ConfidenceScore differs between runs: %v vs %v", i, first[i].ConfidenceScore, second[i].ConfidenceScore)
		}
	}
}

func TestDetect_AllModeVsAuthMode_CountDifferently(t *testing.T) {
	ip := mustAddr("203.0.113.60")
	buildEvents := func() []event.Event {
		return []event.Event{
			ev("r-1", ip, "/login", 0),
			ev("r-2", ip, "/home", 10*time.Second),
			ev("r-3", ip, "/login", 20*time.Second),
			ev("r-4", ip, "/home", 30*time.Second),
			ev("r-5", ip, "/login", 40*time.Second),
		}
	}

	all, err := Detect(buildEvents(), Config{MaxRequests: 2, Window: time.Minute, Mode: CountModeAll})
	if err != nil {
		t.Fatalf("Detect (all): %v", err)
	}
	wantAll := []decision.Action{
		decision.ActionAllow, decision.ActionAllow, decision.ActionBlock, decision.ActionBlock, decision.ActionBlock,
	}
	if got := actionsOf(all); !equalActions(got, wantAll) {
		t.Errorf("mode=all actions = %v, want %v (home requests get swept up too)", got, wantAll)
	}

	auth, err := Detect(buildEvents(), Config{MaxRequests: 2, Window: time.Minute, Mode: CountModeAuth})
	if err != nil {
		t.Fatalf("Detect (auth): %v", err)
	}
	wantAuth := []decision.Action{
		decision.ActionAllow, decision.ActionAllow, decision.ActionAllow, decision.ActionAllow, decision.ActionBlock,
	}
	if got := actionsOf(auth); !equalActions(got, wantAuth) {
		t.Errorf("mode=auth actions = %v, want %v (only the 3rd login attempt should block; /home is never touched)", got, wantAuth)
	}
}

func TestConfig_Validate_InvalidConfigurations(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want []error
	}{
		{"zero max requests", Config{MaxRequests: 0, Window: time.Minute, Mode: CountModeAll}, []error{ErrInvalidMaxRequests}},
		{"negative max requests", Config{MaxRequests: -1, Window: time.Minute, Mode: CountModeAll}, []error{ErrInvalidMaxRequests}},
		{"zero window", Config{MaxRequests: 10, Window: 0, Mode: CountModeAll}, []error{ErrInvalidWindow}},
		{"negative window", Config{MaxRequests: 10, Window: -time.Second, Mode: CountModeAll}, []error{ErrInvalidWindow}},
		{"invalid mode", Config{MaxRequests: 10, Window: time.Minute, Mode: "bogus"}, []error{ErrInvalidMode}},
		{"everything invalid at once", Config{MaxRequests: 0, Window: 0, Mode: "bogus"}, []error{ErrInvalidMaxRequests, ErrInvalidWindow, ErrInvalidMode}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			for _, want := range tc.want {
				if !errors.Is(err, want) {
					t.Errorf("Validate() = %v, want it to wrap %v", err, want)
				}
			}
		})
	}
}

func TestDetect_InvalidConfig_ReturnsErrorWithoutProcessing(t *testing.T) {
	ip := mustAddr("203.0.113.70")
	events := []event.Event{ev("r-1", ip, "/", 0)}

	_, err := Detect(events, Config{MaxRequests: 0, Window: time.Minute, Mode: CountModeAll})
	if !errors.Is(err, ErrInvalidMaxRequests) {
		t.Errorf("Detect() error = %v, want it to wrap ErrInvalidMaxRequests", err)
	}
}

func TestDetect_EventsOutOfOrder_ReturnsError(t *testing.T) {
	ip := mustAddr("203.0.113.80")
	events := []event.Event{
		ev("r-1", ip, "/", 10*time.Second),
		ev("r-2", ip, "/", 0),
	}
	cfg := Config{MaxRequests: 10, Window: time.Minute, Mode: CountModeAll}

	_, err := Detect(events, cfg)
	if !errors.Is(err, ErrEventsOutOfOrder) {
		t.Errorf("Detect() error = %v, want it to wrap ErrEventsOutOfOrder", err)
	}
}

func TestDetect_AllDecisionsPassContractValidation(t *testing.T) {
	ipA := mustAddr("203.0.113.90")
	ipB := mustAddr("203.0.113.91")
	events := []event.Event{
		ev("r-1", ipA, "/login", 0),
		ev("r-2", ipA, "/login", 5*time.Second),
		ev("r-3", ipA, "/login", 10*time.Second),
		ev("r-4", ipB, "/home", 15*time.Second),
		ev("r-5", ipB, "/home", 20*time.Second),
		ev("r-6", ipB, "/home", 25*time.Second),
	}

	for _, mode := range []CountMode{CountModeAll, CountModeAuth} {
		cfg := Config{MaxRequests: 2, Window: time.Minute, Mode: mode}
		decisions, err := Detect(events, cfg)
		if err != nil {
			t.Fatalf("Detect(mode=%s): %v", mode, err)
		}
		sawBlock := false
		for _, d := range decisions {
			if d.Action == decision.ActionBlock {
				sawBlock = true
			}
			if err := decision.Validate(d); err != nil {
				t.Errorf("mode=%s: decision.Validate(%+v) = %v, want nil", mode, d, err)
			}
		}
		if !sawBlock {
			t.Fatalf("mode=%s: test setup produced no BLOCK decisions, nothing meaningful was checked", mode)
		}
	}
}
