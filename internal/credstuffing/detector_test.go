// Prueba la configuración y las señales del detector de credential stuffing.
package credstuffing

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
)

var testBase = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

type fakeResolver map[netip.Addr]string

func (r fakeResolver) Resolve(ip netip.Addr) (string, bool) {
	group, ok := r[ip]
	return group, ok
}

func ipFor(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + i%254)})
}

const loginPath = "/login"

func authEvent(ip netip.Addr, offset time.Duration, accountHash string, status int) event.Event {
	return event.Event{
		RequestID:     "r",
		Timestamp:     testBase.Add(offset),
		ClientIP:      ip,
		Method:        "POST",
		Path:          loginPath,
		StatusCode:    status,
		LoginUserHash: accountHash,
	}
}

func nonAuthEvent(ip netip.Addr, offset time.Duration) event.Event {
	return event.Event{
		RequestID:  "r",
		Timestamp:  testBase.Add(offset),
		ClientIP:   ip,
		Method:     "GET",
		Path:       "/home",
		StatusCode: 200,
	}
}

func baseConfig(resolver NetworkResolver) Config {
	return Config{
		Window:              10 * time.Minute,
		MinDistinctIPs:      5,
		MinDistinctAccounts: 4,
		MinAttempts:         6,
		MinFailedRatio:      0.5,
		Weights:             ScoreWeights{IPs: 0.25, Accounts: 0.25, Attempts: 0.25, Ratio: 0.25},
		ScoreFloor:          0.2,
		Resolver:            resolver,
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
	valid := baseConfig(fakeResolver{})
	tests := []struct {
		name   string
		break_ func(c Config) Config
		want   error
	}{
		{"zero window", func(c Config) Config { c.Window = 0; return c }, ErrInvalidWindow},
		{"zero min distinct ips", func(c Config) Config { c.MinDistinctIPs = 0; return c }, ErrInvalidMinDistinctIPs},
		{"negative min distinct accounts", func(c Config) Config { c.MinDistinctAccounts = -1; return c }, ErrInvalidMinDistinctAccounts},
		{"zero min attempts", func(c Config) Config { c.MinAttempts = 0; return c }, ErrInvalidMinAttempts},
		{"negative min failed ratio", func(c Config) Config { c.MinFailedRatio = -0.1; return c }, ErrInvalidMinFailedRatio},
		{"min failed ratio above 1", func(c Config) Config { c.MinFailedRatio = 1.1; return c }, ErrInvalidMinFailedRatio},
		{"zero score floor", func(c Config) Config { c.ScoreFloor = 0; return c }, ErrInvalidScoreFloor},
		{"score floor of 1", func(c Config) Config { c.ScoreFloor = 1; return c }, ErrInvalidScoreFloor},
		{"all weights zero", func(c Config) Config { c.Weights = ScoreWeights{}; return c }, ErrInvalidWeights},
		{"negative weight", func(c Config) Config { c.Weights.IPs = -1; return c }, ErrInvalidWeights},
		{"nil resolver", func(c Config) Config { c.Resolver = nil; return c }, ErrNilResolver},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.break_(valid).Validate()
			if !errors.Is(err, tc.want) {
				t.Errorf("Validate() = %v, want it to wrap %v", err, tc.want)
			}
		})
	}
}

func TestNewDetector_InvalidConfig_ReturnsError(t *testing.T) {
	cfg := baseConfig(fakeResolver{})
	cfg.Window = 0
	if _, err := NewDetector(cfg); !errors.Is(err, ErrInvalidWindow) {
		t.Errorf("NewDetector() error = %v, want it to wrap ErrInvalidWindow", err)
	}
}

func TestEvaluate_DistributedCampaign_Triggers(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 20; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	for i := 0; i < 20; i++ {
		status := 401
		if i%10 == 0 {
			status = 200
		}
		account := "acct-" + string(rune('A'+i%15))
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, account, status)
		last = observe(d, e)
	}

	if !last.Triggered {
		t.Fatal("Triggered = false, want true for a clear distributed campaign")
	}
	if last.AttackVector != decision.AttackVectorCredentialStuffing {
		t.Errorf("AttackVector = %v, want credential_stuffing", last.AttackVector)
	}
	if last.RiskScore <= 0 || last.RiskScore >= 1 {
		t.Errorf("RiskScore = %v, want it in (0, 1)", last.RiskScore)
	}
	if len(last.ContributingSignals) != 4 {
		t.Errorf("ContributingSignals has %d entries, want 4", len(last.ContributingSignals))
	}
	if last.Explanation == "" {
		t.Error("Explanation is empty, want a deterministic message")
	}
	if last.EntityID != "network:asn:64512" {
		t.Errorf("EntityID = %q, want %q", last.EntityID, "network:asn:64512")
	}
}

func TestEvaluate_AllSignalsExactlyAtThreshold_TriggersWithPositiveScore(t *testing.T) {
	resolver := fakeResolver{
		ipFor(0): "asn:64512",
		ipFor(1): "asn:64512",
		ipFor(2): "asn:64512",
		ipFor(3): "asn:64512",
		ipFor(4): "asn:64512",
	}
	d := newTestDetector(t, baseConfig(resolver))

	events := []event.Event{
		authEvent(ipFor(0), 0*time.Second, "acct-A", 401),
		authEvent(ipFor(0), 1*time.Second, "acct-B", 200),
		authEvent(ipFor(1), 2*time.Second, "acct-C", 401),
		authEvent(ipFor(2), 3*time.Second, "acct-D", 200),
		authEvent(ipFor(3), 4*time.Second, "acct-D", 403),
		authEvent(ipFor(4), 5*time.Second, "acct-A", 200),
	}

	var last finding.Finding
	for _, e := range events {
		last = observe(d, e)
	}

	if !last.Triggered {
		t.Fatal("Triggered = false, want true — all four signals are exactly at their configured threshold")
	}
	if last.RiskScore <= 0 {
		t.Errorf("RiskScore = %v, want it strictly greater than 0 even at the exact threshold", last.RiskScore)
	}
	if last.RiskScore >= 1 {
		t.Errorf("RiskScore = %v, want it strictly less than 1", last.RiskScore)
	}
	if last.RiskScore != 0.2 {
		t.Errorf("RiskScore = %v, want exactly ScoreFloor (0.2) at the exact threshold", last.RiskScore)
	}
}

func TestEvaluate_SingleIP_ManyAttempts_DoesNotTrigger(t *testing.T) {
	ip := ipFor(0)
	resolver := fakeResolver{ip: "asn:64512"}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	for i := 0; i < 50; i++ {
		e := authEvent(ip, time.Duration(i)*time.Second, "acct-A", 401)
		last = observe(d, e)
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — a single IP flood must never satisfy MinDistinctIPs by itself: %+v", last)
	}
}

func TestEvaluate_LegitTenantSharingASNWithAttackers_DoesNotTrigger(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 30; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	for i := 0; i < 30; i++ {
		status := 200
		if i == 0 {
			status = 401
		}
		account := "acct-" + string(rune('A'+i%26))
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, account, status)
		last = observe(d, e)
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — legit traffic with a low failed-login ratio must not trigger: %+v", last)
	}
}

func TestEvaluate_ManyFailuresFewAccounts_DoesNotTrigger(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 20; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	for i := 0; i < 20; i++ {
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, "acct-single-target", 401)
		last = observe(d, e)
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — too few distinct accounts for the distributed-stuffing gate: %+v", last)
	}
}

func TestEvaluate_ManyAccountsFewFailures_DoesNotTrigger(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 20; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	for i := 0; i < 20; i++ {
		account := "acct-" + string(rune('A'+i%20))
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, account, 200)
		last = observe(d, e)
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — a 0%% failed ratio must not trigger regardless of IP/account diversity: %+v", last)
	}
}

func TestEvaluate_EventsOutsideWindow_StopCounting(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 6; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var trigger finding.Finding
	batch := []event.Event{
		authEvent(ipFor(0), 0*time.Second, "acct-A", 401),
		authEvent(ipFor(0), 1*time.Second, "acct-B", 200),
		authEvent(ipFor(1), 2*time.Second, "acct-C", 401),
		authEvent(ipFor(2), 3*time.Second, "acct-D", 200),
		authEvent(ipFor(3), 4*time.Second, "acct-D", 403),
		authEvent(ipFor(4), 5*time.Second, "acct-A", 200),
	}
	for _, e := range batch {
		trigger = observe(d, e)
	}
	if !trigger.Triggered {
		t.Fatalf("first batch did not trigger, want it to (test setup issue): %+v", trigger)
	}

	late := authEvent(ipFor(5), 30*time.Minute, "acct-E", 200)
	after := observe(d, late)

	if after.Triggered {
		t.Errorf("Triggered = true after the window elapsed, want false (the first batch should have expired): %+v", after)
	}
}

func TestObserve_UnresolvedIP_ExcludedFromCorrelation(t *testing.T) {
	knownIP := ipFor(0)
	resolver := fakeResolver{knownIP: "asn:64512"}
	d := newTestDetector(t, baseConfig(resolver))

	var lastUnresolved finding.Finding
	for i := 1; i <= 20; i++ {
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, "acct-X", 401)
		lastUnresolved = observe(d, e)
	}
	if lastUnresolved.Triggered {
		t.Errorf("Triggered = true for an unresolved IP, want false: %+v", lastUnresolved)
	}

	knownFinding := observe(d, authEvent(knownIP, 21*time.Second, "acct-Y", 401))
	if knownFinding.Triggered {
		t.Errorf("Triggered = true for the known group after only 1 attempt, want false (unresolved IPs must not have leaked into it): %+v", knownFinding)
	}
}

func TestEvaluate_MissingLoginUserHash_ExcludedFromAccountSet(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 6; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	for i := 0; i < 6; i++ {
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, "", 401)
		last = observe(d, e)
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — empty login_user_hash must never count toward DistinctAccounts: %+v", last)
	}
}

func TestObserveEvaluate_NonAuthEvent_NeverTriggers(t *testing.T) {
	ip := ipFor(0)
	resolver := fakeResolver{ip: "asn:64512"}
	d := newTestDetector(t, baseConfig(resolver))

	f := observe(d, nonAuthEvent(ip, 0))
	if f.Triggered {
		t.Errorf("Triggered = true for a non-auth event, want false: %+v", f)
	}
}

func TestObserve_ConcurrentWrites_SameGroup(t *testing.T) {
	const n = 60
	resolver := fakeResolver{}
	for i := 0; i < n; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			account := "acct-" + string(rune('A'+i%26))
			d.Observe(authEvent(ipFor(i), time.Duration(i)*time.Millisecond, account, 401))
		}(i)
	}
	wg.Wait()

	probe := authEvent(ipFor(0), time.Duration(n)*time.Millisecond, "acct-probe", 401)
	f := observe(d, probe)

	if !f.Triggered {
		t.Fatalf("Triggered = false after %d concurrent auth attempts across distinct IPs/accounts, want true: %+v", n, f)
	}
	if f.RiskScore <= 0 || f.RiskScore >= 1 {
		t.Errorf("RiskScore = %v, want it in (0, 1)", f.RiskScore)
	}
}

func TestSweep_RemovesOnlyIdleGroups(t *testing.T) {
	idleIP := ipFor(0)
	activeIP := ipFor(1)
	resolver := fakeResolver{idleIP: "idle-group", activeIP: "active-group"}
	d := newTestDetector(t, baseConfig(resolver))

	d.Observe(authEvent(idleIP, 0, "acct-A", 401))
	d.Observe(authEvent(activeIP, 30*time.Minute, "acct-B", 401))

	now := testBase.Add(40 * time.Minute)
	removed := d.Sweep(now, 20*time.Minute)

	if removed != 1 {
		t.Fatalf("Sweep removed %d groups, want 1", removed)
	}
}
