// Prueba la configuración y las señales del detector de escaneo lento.
package slowscan

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
)

var testBase = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

func ipFor(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + i%254)})
}

func ev(ip netip.Addr, offset time.Duration, path string, status int, hasReferer bool) event.Event {
	referer := ""
	if hasReferer {
		referer = "https://example.com/"
	}
	return event.Event{
		RequestID:  "r",
		Timestamp:  testBase.Add(offset),
		ClientIP:   ip,
		Method:     "GET",
		Path:       path,
		StatusCode: status,
		Referer:    referer,
	}
}

func evSession(ip netip.Addr, offset time.Duration, path string, status int, hasReferer bool, sessionID string) event.Event {
	e := ev(ip, offset, path, status, hasReferer)
	e.SessionID = sessionID
	return e
}

func sensitivePath(i int) string { return fmt.Sprintf("/sensitive-%d", i) }
func realPath(i int) string      { return fmt.Sprintf("/real-%d", i) }

func baseConfig() Config {
	return Config{
		Window:                  2 * time.Hour,
		MinRequests:             15,
		MinDistinctPaths:        10,
		MinNotFoundRatio:        0.6,
		MinRouteEntropy:         0.6,
		MinNovelPathRatio:       0.5,
		MaxVisitorsForNovelPath: 1,
		Weights:                 ScoreWeights{Requests: 1, Paths: 1, NotFound: 1, Entropy: 1, Novelty: 1, Referer: 1},
		ScoreFloor:              0.2,
	}
}

func newTestDetector(t *testing.T, cfg Config) *Detector {
	t.Helper()
	d, err := NewDetector(cfg)
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	return d
}

func observe(d *Detector, e event.Event) finding.Finding {
	d.Observe(e)
	return d.Evaluate(e)
}

func TestConfig_Validate_InvalidConfigurations(t *testing.T) {
	valid := baseConfig()
	tests := []struct {
		name   string
		break_ func(c Config) Config
		want   error
	}{
		{"zero window", func(c Config) Config { c.Window = 0; return c }, ErrInvalidWindow},
		{"zero min requests", func(c Config) Config { c.MinRequests = 0; return c }, ErrInvalidMinRequests},
		{"zero min distinct paths", func(c Config) Config { c.MinDistinctPaths = 0; return c }, ErrInvalidMinDistinctPaths},
		{"min not found ratio above 1", func(c Config) Config { c.MinNotFoundRatio = 1.1; return c }, ErrInvalidMinNotFoundRatio},
		{"negative min route entropy", func(c Config) Config { c.MinRouteEntropy = -0.1; return c }, ErrInvalidMinRouteEntropy},
		{"min novel path ratio above 1", func(c Config) Config { c.MinNovelPathRatio = 1.1; return c }, ErrInvalidMinNovelPathRatio},
		{"zero max visitors for novel path", func(c Config) Config { c.MaxVisitorsForNovelPath = 0; return c }, ErrInvalidMaxVisitorsForNovelPath},
		{"zero score floor", func(c Config) Config { c.ScoreFloor = 0; return c }, ErrInvalidScoreFloor},
		{"all weights zero", func(c Config) Config { c.Weights = ScoreWeights{}; return c }, ErrInvalidWeights},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.break_(valid).Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error wrapping %v", tc.want)
			}
		})
	}
}

func TestEvaluate_ClearSlowScan_Triggers(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		e := ev(ip, time.Duration(i)*time.Minute, sensitivePath(i), 404, false)
		last = observe(d, e)
	}

	if !last.Triggered {
		t.Fatal("Triggered = false, want true for a clear slow-scan pattern")
	}
	if last.AttackVector != decision.AttackVectorSlowScan {
		t.Errorf("AttackVector = %v, want slow_scan", last.AttackVector)
	}
	if last.RiskScore <= 0 || last.RiskScore >= 1 {
		t.Errorf("RiskScore = %v, want it in (0, 1)", last.RiskScore)
	}
	if len(last.ContributingSignals) != 6 {
		t.Errorf("ContributingSignals has %d entries, want 6", len(last.ContributingSignals))
	}
	wantEntityID := "ip:" + ipFor(0).String()
	if last.EntityID != wantEntityID {
		t.Errorf("EntityID = %q, want %q (no session on this traffic)", last.EntityID, wantEntityID)
	}
}

func TestEvaluate_ConcentratedSingleRoute_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		last = observe(d, ev(ip, time.Duration(i)*time.Minute, "/products", 200, true))
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — 20 requests to a single route is not scanning: %+v", last)
	}
}

func TestEvaluate_ManyLegitPathsLowNotFound_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		last = observe(d, ev(ip, time.Duration(i)*time.Minute, realPath(i), 200, true))
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — many real paths with 0%% not-found must not trigger: %+v", last)
	}
}

func TestEvaluate_ManyNotFoundFewPaths_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		path := sensitivePath(i % 3)
		last = observe(d, ev(ip, time.Duration(i)*time.Minute, path, 404, false))
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — only 3 distinct paths, below MinDistinctPaths: %+v", last)
	}
}

func TestEvaluate_StableAPIClientNoReferer_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		path := realPath(i % 5)
		last = observe(d, ev(ip, time.Duration(i)*time.Minute, path, 200, false))
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — a stable API client without Referer must not trigger by itself: %+v", last)
	}
}

func TestEvaluate_MissingRefererAlone_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 5; i++ {
		last = observe(d, ev(ip, time.Duration(i)*time.Minute, sensitivePath(i%3), 404, false))
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — missing Referer alone must never be sufficient: %+v", last)
	}
}

func TestEvaluate_SlowScanWithLargeGaps_AccumulatesWithinWindow(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		last = observe(d, ev(ip, time.Duration(i)*6*time.Minute, sensitivePath(i), 404, false))
	}

	if !last.Triggered {
		t.Fatal("Triggered = false, want true — the pattern should still accumulate within a wide enough window")
	}
}

func TestEvaluate_EventsOutsideWindow_StopContributing(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var trigger finding.Finding
	for i := 0; i < 20; i++ {
		trigger = observe(d, ev(ip, time.Duration(i)*time.Minute, sensitivePath(i), 404, false))
	}
	if !trigger.Triggered {
		t.Fatalf("first batch did not trigger, want it to (test setup issue): %+v", trigger)
	}

	late := ev(ip, 5*time.Hour, realPath(0), 200, true)
	after := observe(d, late)

	if after.Triggered {
		t.Errorf("Triggered = true after the window elapsed, want false: %+v", after)
	}
}

func TestEvaluate_OutOfOrder_SameResultAsChronological(t *testing.T) {
	build := func(order []int) *Detector {
		d := newTestDetector(t, baseConfig())
		ip := ipFor(0)
		for _, i := range order {
			d.Observe(ev(ip, time.Duration(i)*time.Minute, sensitivePath(i), 404, false))
		}
		return d
	}

	chronological := make([]int, 20)
	for i := range chronological {
		chronological[i] = i
	}
	shuffled := []int{19, 3, 7, 0, 15, 1, 12, 8, 4, 18, 2, 11, 9, 16, 5, 13, 6, 17, 10, 14}

	dChrono := build(chronological)
	dShuffled := build(shuffled)

	probe := ev(ipFor(0), 19*time.Minute, sensitivePath(19), 404, false)
	fChrono := dChrono.Evaluate(probe)
	fShuffled := dShuffled.Evaluate(probe)

	if fChrono.Triggered != fShuffled.Triggered {
		t.Fatalf("Triggered differs by arrival order: chronological=%v shuffled=%v", fChrono.Triggered, fShuffled.Triggered)
	}
	if fChrono.RiskScore != fShuffled.RiskScore {
		t.Errorf("RiskScore differs by arrival order: chronological=%v shuffled=%v", fChrono.RiskScore, fShuffled.RiskScore)
	}
}

func TestEvaluate_EventWithoutSessionID_FallsBackToIP(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		e := ev(ip, time.Duration(i)*time.Minute, sensitivePath(i), 404, false)
		last = observe(d, e)
	}

	if !last.Triggered {
		t.Fatal("Triggered = false, want true")
	}
	wantEntityID := "ip:" + ip.String()
	if last.EntityID != wantEntityID {
		t.Errorf("EntityID = %q, want %q when there is no session_id", last.EntityID, wantEntityID)
	}
}

func TestNormalizedEntropy_HandComputed(t *testing.T) {
	uniform := map[string]int{"/a": 1, "/b": 1, "/c": 1, "/d": 1}
	if got := normalizedEntropy(uniform, 4, 4); got < 0.999 || got > 1.001 {
		t.Errorf("normalizedEntropy(uniform) = %v, want ~1.0", got)
	}

	skewed := map[string]int{"/a": 17, "/b": 1, "/c": 1, "/d": 1}
	got := normalizedEntropy(skewed, 20, 4)
	want := 0.424
	if got < want-0.01 || got > want+0.01 {
		t.Errorf("normalizedEntropy(skewed) = %v, want ~%v", got, want)
	}

	if got := normalizedEntropy(map[string]int{"/a": 10}, 10, 1); got != 0 {
		t.Errorf("normalizedEntropy(single path) = %v, want 0", got)
	}
}

func TestNovelPathRatio_HandComputed(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	thisIP := ipFor(0)
	otherIP := ipFor(1)

	d.paths.observe("/", thisIP, testBase)
	d.paths.observe("/", otherIP, testBase.Add(time.Second))
	d.paths.observe("/wp-admin", thisIP, testBase.Add(2*time.Second))

	pathCounts := map[string]int{"/": 1, "/wp-admin": 1}
	got := d.novelPathRatio(pathCounts, 2)
	want := 0.5
	if got != want {
		t.Errorf("novelPathRatio = %v, want %v", got, want)
	}
}

func TestEvaluate_AllSignalsExactlyAtThreshold_TriggersWithPositiveScore(t *testing.T) {
	cfg := Config{
		Window:                  time.Hour,
		MinRequests:             10,
		MinDistinctPaths:        5,
		MinNotFoundRatio:        0.5,
		MinRouteEntropy:         1.0,
		MinNovelPathRatio:       0.6,
		MaxVisitorsForNovelPath: 1,
		Weights:                 ScoreWeights{Requests: 1, Paths: 1, NotFound: 1, Entropy: 1, Novelty: 1, Referer: 1},
		ScoreFloor:              0.2,
	}
	d := newTestDetector(t, cfg)
	ip := ipFor(0)
	other := ipFor(1)

	var last finding.Finding
	paths := []string{"/p1", "/p2", "/p3", "/p4", "/p5"}
	for i, p := range paths {
		last = observe(d, ev(ip, time.Duration(2*i)*time.Minute, p, 404, true))
		last = observe(d, ev(ip, time.Duration(2*i+1)*time.Minute, p, 200, true))
	}
	d.Observe(ev(other, 10*time.Minute, "/p4", 200, true))
	d.Observe(ev(other, 11*time.Minute, "/p5", 200, true))
	last = d.Evaluate(ev(ip, 9*time.Minute, "/p5", 200, true))

	if !last.Triggered {
		t.Fatal("Triggered = false, want true — all five gate signals are exactly at their configured threshold")
	}
	if last.RiskScore != cfg.ScoreFloor {
		t.Errorf("RiskScore = %v, want exactly ScoreFloor (%v) at the exact threshold with zero Referer contribution", last.RiskScore, cfg.ScoreFloor)
	}
}

func TestEvaluate_ScannerRotatingSessions_DetectedByIP(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for s := 0; s < 4; s++ {
		sessionID := fmt.Sprintf("s-%d", s)
		for j := 0; j < 5; j++ {
			path := fmt.Sprintf("/sensitive-%d-%d", s, j)
			e := evSession(ip, time.Duration(s*10+j)*time.Minute, path, 404, false, sessionID)
			last = observe(d, e)
		}
	}

	if !last.Triggered {
		t.Fatal("Triggered = false, want true — the IP-level aggregate across rotated sessions should trigger")
	}
	wantEntityID := "ip:" + ip.String()
	if last.EntityID != wantEntityID {
		t.Errorf("EntityID = %q, want %q (no single session should have triggered on its own)", last.EntityID, wantEntityID)
	}
}

func TestEvaluate_LegitNATMultipleSessions_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for s := 0; s < 3; s++ {
		sessionID := fmt.Sprintf("s-%d", s)
		for j := 0; j < 8; j++ {
			path := realPath(s*8 + j)
			e := evSession(ip, time.Duration(s*20+j)*time.Minute, path, 200, true, sessionID)
			last = observe(d, e)
		}
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — a legit NAT with normal browsing must not trigger by aggregation alone: %+v", last)
	}
}

func TestEvaluate_IPAndSessionBothTrigger_ReturnsSingleFinding(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)
	sessionID := "s-only"

	var last finding.Finding
	for i := 0; i < 20; i++ {
		e := evSession(ip, time.Duration(i)*time.Minute, sensitivePath(i), 404, false, sessionID)
		last = observe(d, e)
	}

	if !last.Triggered {
		t.Fatal("Triggered = false, want true")
	}
	if len(last.ContributingSignals) != 6 {
		t.Errorf("ContributingSignals has %d entries, want exactly 6 (a single evaluation, not two concatenated)", len(last.ContributingSignals))
	}
	wantEntityID := "session:" + sessionID
	if last.EntityID != wantEntityID {
		t.Errorf("EntityID = %q, want %q — on an exact tie, session must win", last.EntityID, wantEntityID)
	}
}

func TestObserve_ConcurrentWrites_SameIP(t *testing.T) {
	const n = 40
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			d.Observe(ev(ip, time.Duration(i)*time.Minute, sensitivePath(i), 404, false))
		}(i)
	}
	wg.Wait()

	probe := ev(ip, time.Duration(n)*time.Minute, sensitivePath(n), 404, false)
	f := observe(d, probe)

	if !f.Triggered {
		t.Fatalf("Triggered = false after %d concurrent requests across distinct sensitive paths, want true", n)
	}
	if f.RiskScore <= 0 || f.RiskScore >= 1 {
		t.Errorf("RiskScore = %v, want it in (0, 1)", f.RiskScore)
	}
}

func TestSweep_RemovesOnlyIdleState(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	idleIP := ipFor(0)
	activeIP := ipFor(1)

	d.Observe(ev(idleIP, 0, "/a", 200, true))
	d.Observe(ev(activeIP, 30*time.Minute, "/b", 200, true))

	now := testBase.Add(40 * time.Minute)
	removed := d.Sweep(now, 20*time.Minute)

	if removed == 0 {
		t.Fatal("Sweep removed 0 entries, want at least the idle IP's profile")
	}
}
