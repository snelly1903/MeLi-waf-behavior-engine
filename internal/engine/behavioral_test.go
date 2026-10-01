// Prueba la combinación de detectores, la selección del finding principal y la política del BehavioralDecider.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

var testBase = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

type fakeResolver map[netip.Addr]string

func (r fakeResolver) Resolve(ip netip.Addr) (string, bool) {
	g, ok := r[ip]
	return g, ok
}

func ipFor(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + i%254)})
}

func loginEvent(ip netip.Addr, offset time.Duration, account string, status int) event.Event {
	return event.Event{
		RequestID:     fmt.Sprintf("cs-%d", int(offset)),
		Timestamp:     testBase.Add(offset),
		ClientIP:      ip,
		Method:        "POST",
		Path:          "/login",
		StatusCode:    status,
		LoginUserHash: account,
		Referer:       "https://example.com/",
	}
}

func scanEvent(ip netip.Addr, offset time.Duration, path string, status int, hasReferer bool, sessionID string) event.Event {
	referer := ""
	if hasReferer {
		referer = "https://example.com/"
	}
	return event.Event{
		RequestID:  fmt.Sprintf("ss-%d", int(offset)),
		Timestamp:  testBase.Add(offset),
		ClientIP:   ip,
		SessionID:  sessionID,
		Method:     "GET",
		Path:       path,
		StatusCode: status,
		Referer:    referer,
	}
}

func csConfig(resolver credstuffing.NetworkResolver) credstuffing.Config {
	return credstuffing.Config{
		Window:              time.Hour,
		MinDistinctIPs:      5,
		MinDistinctAccounts: 4,
		MinAttempts:         6,
		MinFailedRatio:      0.5,
		Weights:             credstuffing.ScoreWeights{IPs: 0.25, Accounts: 0.25, Attempts: 0.25, Ratio: 0.25},
		ScoreFloor:          0.2,
		Resolver:            resolver,
	}
}

func ssConfig() slowscan.Config {
	return slowscan.Config{
		Window:                  time.Hour,
		MinRequests:             10,
		MinDistinctPaths:        8,
		MinNotFoundRatio:        0.5,
		MinRouteEntropy:         0.6,
		MinNovelPathRatio:       0.5,
		MaxVisitorsForNovelPath: 1,
		Weights:                 slowscan.ScoreWeights{Requests: 1, Paths: 1, NotFound: 1, Entropy: 1, Novelty: 1, Referer: 1},
		ScoreFloor:              0.2,
	}
}

func testPolicy() Policy {
	return Policy{ChallengeThreshold: 0.5, BlockThreshold: 0.8}
}

func inertAnomalyConfig() anomaly.Config {
	return anomaly.Config{
		Window:           time.Hour,
		MinSamples:       1_000_000,
		ZSaturation:      2.0,
		TriggerThreshold: 0.5,
		Weights:          anomaly.FeatureWeights{NotFound: 1, FailedAuth: 1, PathDiversity: 1, Referer: 1, AccountDiversity: 1},
		ScoreFloor:       0.2,
	}
}

func newTestDecider(t *testing.T, resolver credstuffing.NetworkResolver, ss slowscan.Config, policy Policy) *BehavioralDecider {
	t.Helper()
	return newTestDeciderFull(t, resolver, ss, inertAnomalyConfig(), policy)
}

func newTestDeciderFull(t *testing.T, resolver credstuffing.NetworkResolver, ss slowscan.Config, an anomaly.Config, policy Policy) *BehavioralDecider {
	t.Helper()
	cs, err := credstuffing.NewDetector(csConfig(resolver))
	if err != nil {
		t.Fatalf("credstuffing.NewDetector: %v", err)
	}
	ssDetector, err := slowscan.NewDetector(ss)
	if err != nil {
		t.Fatalf("slowscan.NewDetector: %v", err)
	}
	anDetector, err := anomaly.NewDetector(an)
	if err != nil {
		t.Fatalf("anomaly.NewDetector: %v", err)
	}
	d, err := NewBehavioralDecider(cs, ssDetector, anDetector, policy, nil)
	if err != nil {
		t.Fatalf("NewBehavioralDecider: %v", err)
	}
	return d
}

type fakeFindingsRecorder struct {
	calls         []string
	anomalyScores []float64
}

func (r *fakeFindingsRecorder) RecordFinding(detector string) {
	r.calls = append(r.calls, detector)
}

func (r *fakeFindingsRecorder) RecordAnomalyScore(score float64) {
	r.anomalyScores = append(r.anomalyScores, score)
}

func sensitivePath(i int) string { return fmt.Sprintf("/sensitive-%d", i) }

func TestPolicy_Validate_InvalidConfigurations(t *testing.T) {
	tests := []struct {
		name string
		p    Policy
	}{
		{"negative challenge", Policy{ChallengeThreshold: -0.1, BlockThreshold: 0.5}},
		{"challenge equal block", Policy{ChallengeThreshold: 0.5, BlockThreshold: 0.5}},
		{"challenge above block", Policy{ChallengeThreshold: 0.6, BlockThreshold: 0.5}},
		{"block above 1", Policy{ChallengeThreshold: 0.5, BlockThreshold: 1.1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.p.Validate(); !errors.Is(err, ErrInvalidPolicy) {
				t.Errorf("Validate() = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestPolicy_ActionFor_Boundaries(t *testing.T) {
	p := Policy{ChallengeThreshold: 0.5, BlockThreshold: 0.8}
	tests := []struct {
		score float64
		want  decision.Action
	}{
		{0.0, decision.ActionAllow},
		{0.49, decision.ActionAllow},
		{0.5, decision.ActionChallenge},
		{0.65, decision.ActionChallenge},
		{0.8, decision.ActionBlock},
		{0.95, decision.ActionBlock},
	}
	for _, tc := range tests {
		if got := p.actionFor(tc.score); got != tc.want {
			t.Errorf("actionFor(%v) = %v, want %v", tc.score, got, tc.want)
		}
	}
}

func TestPolicy_ActionFor_MatchesInternalRule(t *testing.T) {
	p := Policy{ChallengeThreshold: 0.5, BlockThreshold: 0.8}
	for _, score := range []float64{0.0, 0.49, 0.5, 0.65, 0.8, 0.95} {
		if got, want := p.ActionFor(score), p.actionFor(score); got != want {
			t.Errorf("ActionFor(%v) = %v, want %v (igual que actionFor)", score, got, want)
		}
	}
}

func TestNewBehavioralDecider_InvalidInputs(t *testing.T) {
	cs, err := credstuffing.NewDetector(csConfig(fakeResolver{}))
	if err != nil {
		t.Fatalf("credstuffing.NewDetector: %v", err)
	}
	ss, err := slowscan.NewDetector(ssConfig())
	if err != nil {
		t.Fatalf("slowscan.NewDetector: %v", err)
	}
	an, err := anomaly.NewDetector(inertAnomalyConfig())
	if err != nil {
		t.Fatalf("anomaly.NewDetector: %v", err)
	}

	if _, err := NewBehavioralDecider(nil, ss, an, testPolicy(), nil); !errors.Is(err, ErrNilCredentialStuffingDetector) {
		t.Errorf("nil credstuffing: error = %v, want ErrNilCredentialStuffingDetector", err)
	}
	if _, err := NewBehavioralDecider(cs, nil, an, testPolicy(), nil); !errors.Is(err, ErrNilSlowScanDetector) {
		t.Errorf("nil slowscan: error = %v, want ErrNilSlowScanDetector", err)
	}
	if _, err := NewBehavioralDecider(cs, ss, nil, testPolicy(), nil); !errors.Is(err, ErrNilAnomalyDetector) {
		t.Errorf("nil anomaly: error = %v, want ErrNilAnomalyDetector", err)
	}
	if _, err := NewBehavioralDecider(cs, ss, an, Policy{ChallengeThreshold: 0.8, BlockThreshold: 0.5}, nil); !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("invalid policy: error = %v, want ErrInvalidPolicy", err)
	}
}

func TestDecide_NoDetectorTriggers_ReturnsAllow(t *testing.T) {
	d := newTestDecider(t, fakeResolver{}, ssConfig(), testPolicy())
	ip := ipFor(0)
	e := scanEvent(ip, 0, "/", 200, true, "")

	got := d.Decide(context.Background(), e)

	if got.Action != decision.ActionAllow {
		t.Errorf("Action = %v, want ALLOW", got.Action)
	}
	if got.ConfidenceScore != 0 {
		t.Errorf("ConfidenceScore = %v, want 0", got.ConfidenceScore)
	}
	if got.AttackVector != decision.AttackVectorUnknown {
		t.Errorf("AttackVector = %v, want unknown", got.AttackVector)
	}
	wantEntityID := "ip:" + ip.String()
	if got.EntityID != wantEntityID {
		t.Errorf("EntityID = %q, want %q", got.EntityID, wantEntityID)
	}
	if err := decision.Validate(got); err != nil {
		t.Errorf("decision.Validate(%+v) = %v, want nil", got, err)
	}
}

func TestDecide_FindingBelowChallengeThreshold_StaysAllowButPreservesEvidence(t *testing.T) {
	resolver := fakeResolver{}
	d := newTestDecider(t, resolver, ssConfig(), testPolicy())

	group := "asn:below"
	ips := []netip.Addr{ipFor(0), ipFor(1), ipFor(2), ipFor(3), ipFor(4)}
	for _, ip := range ips {
		resolver[ip] = group
	}
	accounts := []string{"acct-A", "acct-B", "acct-C", "acct-D", "acct-D", "acct-A"}
	statuses := []int{401, 200, 401, 200, 403, 200}
	attemptIPs := []netip.Addr{ips[0], ips[0], ips[1], ips[2], ips[3], ips[4]}

	var last decision.Decision
	for i := range accounts {
		e := loginEvent(attemptIPs[i], time.Duration(i)*time.Second, accounts[i], statuses[i])
		last = d.Decide(context.Background(), e)
	}

	if last.Action != decision.ActionAllow {
		t.Fatalf("Action = %v, want ALLOW (score 0.2 is below ChallengeThreshold 0.5)", last.Action)
	}
	if last.AttackVector != decision.AttackVectorCredentialStuffing {
		t.Errorf("AttackVector = %v, want credential_stuffing (preserved even though Action=ALLOW)", last.AttackVector)
	}
	if last.ConfidenceScore != 0.2 {
		t.Errorf("ConfidenceScore = %v, want exactly 0.2 (ScoreFloor, at the exact gate threshold)", last.ConfidenceScore)
	}
	if last.EntityID != "network:"+group {
		t.Errorf("EntityID = %q, want %q", last.EntityID, "network:"+group)
	}
	if len(last.ContributingSignals) != 4 {
		t.Errorf("ContributingSignals has %d entries, want 4", len(last.ContributingSignals))
	}
	if !strings.Contains(last.Explanation, "below challenge threshold") {
		t.Errorf("Explanation = %q, want it to mention it is below the challenge threshold", last.Explanation)
	}
	if err := decision.Validate(last); err != nil {
		t.Errorf("decision.Validate(%+v) = %v, want nil", last, err)
	}
}

func TestDecide_FindingAboveChallengeThreshold_ReturnsChallenge(t *testing.T) {
	resolver := fakeResolver{}
	d := newTestDecider(t, resolver, ssConfig(), testPolicy())

	group := "asn:moderate"
	var last decision.Decision
	attemptIdx := 0
	sendAttempt := func(ip netip.Addr) {
		account := fmt.Sprintf("acct-%d", attemptIdx%10)
		status := 200
		if attemptIdx < 14 {
			status = 401
		}
		resolver[ip] = group
		e := loginEvent(ip, time.Duration(attemptIdx)*time.Second, account, status)
		last = d.Decide(context.Background(), e)
		attemptIdx++
	}
	for i := 0; i < 15; i++ {
		sendAttempt(ipFor(i))
	}
	for i := 0; i < 5; i++ {
		sendAttempt(ipFor(i))
	}

	if last.Action != decision.ActionChallenge {
		t.Fatalf("Action = %v, want CHALLENGE (score ~0.67, test setup: %+v)", last.Action, last)
	}
	if last.ConfidenceScore < 0.5 || last.ConfidenceScore >= 0.8 {
		t.Errorf("ConfidenceScore = %v, want it in [0.5, 0.8)", last.ConfidenceScore)
	}
	if last.AttackVector != decision.AttackVectorCredentialStuffing {
		t.Errorf("AttackVector = %v, want credential_stuffing", last.AttackVector)
	}
	if err := decision.Validate(last); err != nil {
		t.Errorf("decision.Validate(%+v) = %v, want nil", last, err)
	}
}

func TestDecide_FindingAboveBlockThreshold_ReturnsBlock(t *testing.T) {
	d := newTestDecider(t, fakeResolver{}, ssConfig(), testPolicy())
	ip := ipFor(0)

	var last decision.Decision
	for i := 0; i < 50; i++ {
		e := scanEvent(ip, time.Duration(i)*time.Second, sensitivePath(i), 404, false, "")
		last = d.Decide(context.Background(), e)
	}

	if last.Action != decision.ActionBlock {
		t.Fatalf("Action = %v, want BLOCK (score should be well above 0.8): %+v", last.Action, last)
	}
	if last.ConfidenceScore < 0.8 {
		t.Errorf("ConfidenceScore = %v, want >= 0.8", last.ConfidenceScore)
	}
	if last.AttackVector != decision.AttackVectorSlowScan {
		t.Errorf("AttackVector = %v, want slow_scan", last.AttackVector)
	}
	wantEntityID := "ip:" + ip.String()
	if last.EntityID != wantEntityID {
		t.Errorf("EntityID = %q, want %q", last.EntityID, wantEntityID)
	}
	if err := decision.Validate(last); err != nil {
		t.Errorf("decision.Validate(%+v) = %v, want nil", last, err)
	}
}

func TestDecide_EntityID_ForSession(t *testing.T) {
	d := newTestDecider(t, fakeResolver{}, ssConfig(), testPolicy())
	ip := ipFor(0)
	sessionID := "s-only"

	var last decision.Decision
	for i := 0; i < 50; i++ {
		e := scanEvent(ip, time.Duration(i)*time.Second, sensitivePath(i), 404, false, sessionID)
		last = d.Decide(context.Background(), e)
	}

	if last.Action == decision.ActionAllow {
		t.Fatalf("Action = ALLOW, want CHALLENGE or BLOCK: %+v", last)
	}
	wantEntityID := "session:" + sessionID
	if last.EntityID != wantEntityID {
		t.Errorf("EntityID = %q, want %q (the whole IP belongs to one session, session wins)", last.EntityID, wantEntityID)
	}
}

func TestDecide_CredentialStuffingIsPrincipal(t *testing.T) {
	resolver := fakeResolver{}
	d := newTestDecider(t, resolver, ssConfig(), testPolicy())
	group := "asn:cs-principal"
	ips := []netip.Addr{ipFor(0), ipFor(1), ipFor(2), ipFor(3), ipFor(4)}
	for _, ip := range ips {
		resolver[ip] = group
	}
	accounts := []string{"acct-A", "acct-B", "acct-C", "acct-D", "acct-D", "acct-A"}
	statuses := []int{401, 200, 401, 200, 403, 200}
	attemptIPs := []netip.Addr{ips[0], ips[0], ips[1], ips[2], ips[3], ips[4]}

	var last decision.Decision
	for i := range accounts {
		last = d.Decide(context.Background(), loginEvent(attemptIPs[i], time.Duration(i)*time.Second, accounts[i], statuses[i]))
	}

	if last.AttackVector != decision.AttackVectorCredentialStuffing {
		t.Errorf("AttackVector = %v, want credential_stuffing", last.AttackVector)
	}
	if !strings.HasPrefix(last.EntityID, "network:") {
		t.Errorf("EntityID = %q, want it to start with \"network:\"", last.EntityID)
	}
}

func TestDecide_SlowScanIsPrincipal(t *testing.T) {
	d := newTestDecider(t, fakeResolver{}, ssConfig(), testPolicy())
	ip := ipFor(0)

	var last decision.Decision
	for i := 0; i < 20; i++ {
		last = d.Decide(context.Background(), scanEvent(ip, time.Duration(i)*time.Second, sensitivePath(i), 404, false, ""))
	}

	if last.AttackVector != decision.AttackVectorSlowScan {
		t.Errorf("AttackVector = %v, want slow_scan", last.AttackVector)
	}
	if !strings.HasPrefix(last.EntityID, "ip:") {
		t.Errorf("EntityID = %q, want it to start with \"ip:\"", last.EntityID)
	}
}

func TestDecide_BothTrigger_HigherScoreWins(t *testing.T) {
	resolver := fakeResolver{}
	d := newTestDecider(t, resolver, ssConfig(), testPolicy())

	group := "asn:winner-test"
	ip0 := ipFor(0)
	other := []netip.Addr{ipFor(1), ipFor(2), ipFor(3), ipFor(4)}
	for _, ip := range append(other, ip0) {
		resolver[ip] = group
	}

	accounts := []string{"acct-A", "acct-C", "acct-D", "acct-D", "acct-A", "acct-B"}
	statuses := []int{401, 401, 200, 403, 200, 200}
	ips := []netip.Addr{other[0], other[1], other[2], other[3], ip0}
	for i := 0; i < 4; i++ {
		d.Decide(context.Background(), loginEvent(ips[i], time.Duration(i)*time.Second, accounts[i], statuses[i]))
	}
	d.Decide(context.Background(), loginEvent(ip0, 4*time.Second, accounts[4], statuses[4]))

	for i := 0; i < 50; i++ {
		d.Decide(context.Background(), scanEvent(ip0, time.Duration(10+i)*time.Second, sensitivePath(i), 404, false, ""))
	}

	final := d.Decide(context.Background(), loginEvent(ip0, 5*time.Second, accounts[5], statuses[5]))

	if final.AttackVector != decision.AttackVectorSlowScan {
		t.Fatalf("AttackVector = %v, want slow_scan (its score should be much higher than credential_stuffing's 0.2): %+v", final.AttackVector, final)
	}
	if final.ConfidenceScore <= 0.2 {
		t.Errorf("ConfidenceScore = %v, want it clearly above 0.2 (credential_stuffing's score)", final.ConfidenceScore)
	}
	if err := decision.Validate(final); err != nil {
		t.Errorf("decision.Validate(%+v) = %v, want nil", final, err)
	}
}

func TestDecide_RecordsFindingForEveryTriggeredDetector_NotJustPrincipal(t *testing.T) {
	resolver := fakeResolver{}
	recorder := &fakeFindingsRecorder{}

	cs, err := credstuffing.NewDetector(csConfig(resolver))
	if err != nil {
		t.Fatalf("credstuffing.NewDetector: %v", err)
	}
	ss, err := slowscan.NewDetector(ssConfig())
	if err != nil {
		t.Fatalf("slowscan.NewDetector: %v", err)
	}
	an, err := anomaly.NewDetector(inertAnomalyConfig())
	if err != nil {
		t.Fatalf("anomaly.NewDetector: %v", err)
	}
	d, err := NewBehavioralDecider(cs, ss, an, testPolicy(), recorder)
	if err != nil {
		t.Fatalf("NewBehavioralDecider: %v", err)
	}

	group := "asn:findings-test"
	ip0 := ipFor(0)
	other := []netip.Addr{ipFor(1), ipFor(2), ipFor(3), ipFor(4)}
	for _, ip := range append(other, ip0) {
		resolver[ip] = group
	}

	accounts := []string{"acct-A", "acct-C", "acct-D", "acct-D", "acct-A", "acct-B"}
	statuses := []int{401, 401, 200, 403, 200, 200}
	ips := []netip.Addr{other[0], other[1], other[2], other[3], ip0}
	for i := 0; i < 4; i++ {
		d.Decide(context.Background(), loginEvent(ips[i], time.Duration(i)*time.Second, accounts[i], statuses[i]))
	}
	d.Decide(context.Background(), loginEvent(ip0, 4*time.Second, accounts[4], statuses[4]))

	for i := 0; i < 50; i++ {
		d.Decide(context.Background(), scanEvent(ip0, time.Duration(10+i)*time.Second, sensitivePath(i), 404, false, ""))
	}

	recorder.calls = nil
	final := d.Decide(context.Background(), loginEvent(ip0, 5*time.Second, accounts[5], statuses[5]))

	if final.AttackVector != decision.AttackVectorSlowScan {
		t.Fatalf("setup inválido: AttackVector = %v, want slow_scan (mismo escenario que TestDecide_BothTrigger_HigherScoreWins)", final.AttackVector)
	}

	want := []string{"credential_stuffing", "slow_scan"}
	if !reflect.DeepEqual(recorder.calls, want) {
		t.Errorf("RecordFinding calls = %v, want %v (los dos detectores dispararon, aunque solo slow_scan quedó como principal)", recorder.calls, want)
	}
}

func TestDecide_RecordsAnomalyScoreOnEveryEvaluation_EvenWhenNotTriggered(t *testing.T) {
	recorder := &fakeFindingsRecorder{}
	cs, err := credstuffing.NewDetector(csConfig(fakeResolver{}))
	if err != nil {
		t.Fatalf("credstuffing.NewDetector: %v", err)
	}
	ss, err := slowscan.NewDetector(ssConfig())
	if err != nil {
		t.Fatalf("slowscan.NewDetector: %v", err)
	}
	an, err := anomaly.NewDetector(inertAnomalyConfig())
	if err != nil {
		t.Fatalf("anomaly.NewDetector: %v", err)
	}
	d, err := NewBehavioralDecider(cs, ss, an, testPolicy(), recorder)
	if err != nil {
		t.Fatalf("NewBehavioralDecider: %v", err)
	}

	for i := 0; i < 3; i++ {
		d.Decide(context.Background(), scanEvent(ipFor(i), time.Duration(i)*time.Second, "/normal", 200, true, ""))
	}

	if len(recorder.anomalyScores) != 3 {
		t.Fatalf("anomalyScores recorded = %d calls, want 3 (una por Decide, dispare o no)", len(recorder.anomalyScores))
	}
	for i, score := range recorder.anomalyScores {
		if score != 0 {
			t.Errorf("anomalyScores[%d] = %v, want 0 (anomaly inerte, nunca dispara en este test)", i, score)
		}
	}
}

func TestDecide_RecordsAnomalyScore_MatchesTriggeredFindingRiskScore(t *testing.T) {
	recorder := &fakeFindingsRecorder{}
	ssInert := ssConfig()
	ssInert.MinRequests = 1000

	an := anomaly.Config{
		Window:           time.Hour,
		MinSamples:       5,
		ZSaturation:      2.0,
		TriggerThreshold: 0.1,
		Weights:          anomaly.FeatureWeights{NotFound: 1, FailedAuth: 1, PathDiversity: 1, Referer: 1, AccountDiversity: 1},
		ScoreFloor:       0.2,
	}
	cs, err := credstuffing.NewDetector(csConfig(fakeResolver{}))
	if err != nil {
		t.Fatalf("credstuffing.NewDetector: %v", err)
	}
	ss, err := slowscan.NewDetector(ssInert)
	if err != nil {
		t.Fatalf("slowscan.NewDetector: %v", err)
	}
	anDetector, err := anomaly.NewDetector(an)
	if err != nil {
		t.Fatalf("anomaly.NewDetector: %v", err)
	}
	d, err := NewBehavioralDecider(cs, ss, anDetector, testPolicy(), recorder)
	if err != nil {
		t.Fatalf("NewBehavioralDecider: %v", err)
	}

	for i := 10; i < 15; i++ {
		ip := ipFor(i)
		for j := 0; j < 20; j++ {
			status := 200
			if j%10 == 0 {
				status = 404
			}
			d.Decide(context.Background(), scanEvent(ip, time.Duration(i*30+j)*time.Second, "/normal", status, true, ""))
		}
	}

	anomalousIP := ipFor(4)
	var last decision.Decision
	for j := 0; j < 20; j++ {
		status := 200
		if j < 18 {
			status = 404
		}
		last = d.Decide(context.Background(), scanEvent(anomalousIP, time.Duration(1000+j)*time.Second, "/normal", status, true, ""))
	}

	if last.AttackVector != decision.AttackVectorUnknown {
		t.Fatalf("setup inválido: AttackVector = %v, want unknown (solo statistical_anomaly dispara, nunca es un vector específico)", last.AttackVector)
	}
	if last.ConfidenceScore <= 0 {
		t.Fatalf("setup inválido: ConfidenceScore = %v, want > 0 (statistical_anomaly debería haber disparado)", last.ConfidenceScore)
	}
	if len(recorder.anomalyScores) == 0 {
		t.Fatal("anomalyScores no se registró ninguna vez")
	}
	gotLast := recorder.anomalyScores[len(recorder.anomalyScores)-1]
	if gotLast != last.ConfidenceScore {
		t.Errorf("anomalyScores[último] = %v, want %v (debe coincidir con el RiskScore del Finding disparado, sin recalcularse aparte)", gotLast, last.ConfidenceScore)
	}
	if gotLast <= 0 {
		t.Errorf("anomalyScores[último] = %v, want > 0 (statistical_anomaly disparó en esta request)", gotLast)
	}
}

func TestDecide_ExactTie_CredentialStuffingWins(t *testing.T) {
	resolver := fakeResolver{}
	strictSlowScan := slowscan.Config{
		Window:                  time.Hour,
		MinRequests:             10,
		MinDistinctPaths:        5,
		MinNotFoundRatio:        0.5,
		MinRouteEntropy:         1.0,
		MinNovelPathRatio:       0.6,
		MaxVisitorsForNovelPath: 1,
		Weights:                 slowscan.ScoreWeights{Requests: 1, Paths: 1, NotFound: 1, Entropy: 1, Novelty: 1, Referer: 1},
		ScoreFloor:              0.2,
	}
	d := newTestDecider(t, resolver, strictSlowScan, testPolicy())

	group := "asn:tie"
	ip0, ip1, ip2, ip3, ip4, other := ipFor(0), ipFor(1), ipFor(2), ipFor(3), ipFor(4), ipFor(5)
	for _, ip := range []netip.Addr{ip0, ip1, ip2, ip3, ip4} {
		resolver[ip] = group
	}

	d.Decide(context.Background(), loginEvent(ip0, 0, "acct-A", 401))
	d.Decide(context.Background(), loginEvent(ip1, 1*time.Second, "acct-C", 401))
	d.Decide(context.Background(), loginEvent(ip2, 2*time.Second, "acct-D", 200))
	d.Decide(context.Background(), loginEvent(ip3, 3*time.Second, "acct-D", 403))
	d.Decide(context.Background(), loginEvent(ip4, 4*time.Second, "acct-A", 200))

	d.Decide(context.Background(), scanEvent(ip0, 5*time.Second, "/p2", 404, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 6*time.Second, "/p2", 200, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 7*time.Second, "/p3", 404, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 8*time.Second, "/p3", 200, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 9*time.Second, "/p4", 404, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 10*time.Second, "/p4", 200, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 11*time.Second, "/p5", 404, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 12*time.Second, "/p5", 404, true, ""))
	d.Decide(context.Background(), scanEvent(other, 13*time.Second, "/p2", 200, true, ""))

	final := d.Decide(context.Background(), loginEvent(ip0, 14*time.Second, "acct-B", 200))

	if final.AttackVector != decision.AttackVectorCredentialStuffing {
		t.Fatalf("AttackVector = %v, want credential_stuffing (exact tie, credential_stuffing must win): %+v", final.AttackVector, final)
	}
	if final.ConfidenceScore != 0.2 {
		t.Errorf("ConfidenceScore = %v, want exactly 0.2 (both findings hit their own ScoreFloor exactly)", final.ConfidenceScore)
	}
	if final.EntityID != "network:"+group {
		t.Errorf("EntityID = %q, want %q", final.EntityID, "network:"+group)
	}
	if final.Action != decision.ActionAllow {
		t.Errorf("Action = %v, want ALLOW (0.2 is below ChallengeThreshold 0.5)", final.Action)
	}
	if err := decision.Validate(final); err != nil {
		t.Errorf("decision.Validate(%+v) = %v, want nil", final, err)
	}
}

func TestDecide_AnomalyFindingCanBePrincipal_WhenHigherScore(t *testing.T) {
	ss := ssConfig()
	ss.MinRequests = 1000

	an := anomaly.Config{
		Window:           time.Hour,
		MinSamples:       5,
		ZSaturation:      2.0,
		TriggerThreshold: 0.1,
		Weights:          anomaly.FeatureWeights{NotFound: 1, FailedAuth: 1, PathDiversity: 1, Referer: 1, AccountDiversity: 1},
		ScoreFloor:       0.2,
	}
	d := newTestDeciderFull(t, fakeResolver{}, ss, an, testPolicy())

	var last decision.Decision
	for i := 0; i < 5; i++ {
		ip := ipFor(i)
		for j := 0; j < 20; j++ {
			status := 200
			if j%10 == 0 {
				status = 404
			}
			e := scanEvent(ip, time.Duration(i*30+j)*time.Second, "/normal", status, true, "")
			last = d.Decide(context.Background(), e)
		}
	}

	anomalousIP := ipFor(50)
	for j := 0; j < 20; j++ {
		status := 200
		if j < 18 {
			status = 404
		}
		e := scanEvent(anomalousIP, time.Duration(1000+j)*time.Second, "/normal", status, true, "")
		last = d.Decide(context.Background(), e)
	}

	if last.AttackVector != decision.AttackVectorUnknown {
		t.Fatalf("AttackVector = %v, want unknown (the statistical anomaly detector should be principal here — neither of the other two can trigger by construction): %+v", last.AttackVector, last)
	}
	if last.ConfidenceScore <= 0 {
		t.Errorf("ConfidenceScore = %v, want it > 0 (evidence preserved even if Action stays ALLOW below ChallengeThreshold)", last.ConfidenceScore)
	}
	if !strings.HasPrefix(last.EntityID, "ip:") {
		t.Errorf("EntityID = %q, want it to start with \"ip:\"", last.EntityID)
	}
	if err := decision.Validate(last); err != nil {
		t.Errorf("decision.Validate(%+v) = %v, want nil", last, err)
	}
}

func TestDecide_OtherDetectorStaysPrincipal_OverAnomaly(t *testing.T) {
	an := anomaly.Config{
		Window:           time.Hour,
		MinSamples:       5,
		ZSaturation:      2.0,
		TriggerThreshold: 0.1,
		Weights:          anomaly.FeatureWeights{NotFound: 1, FailedAuth: 1, PathDiversity: 1, Referer: 1, AccountDiversity: 1},
		ScoreFloor:       0.2,
	}
	d := newTestDeciderFull(t, fakeResolver{}, ssConfig(), an, testPolicy())

	for i := 0; i < 5; i++ {
		ip := ipFor(i)
		for j := 0; j < 20; j++ {
			status := 200
			if j%10 == 0 {
				status = 404
			}
			d.Decide(context.Background(), scanEvent(ip, time.Duration(i*30+j)*time.Second, "/normal", status, true, ""))
		}
	}

	ip := ipFor(0)
	var last decision.Decision
	for i := 0; i < 50; i++ {
		last = d.Decide(context.Background(), scanEvent(ip, time.Duration(2000+i)*time.Second, sensitivePath(i), 404, false, ""))
	}

	if last.AttackVector != decision.AttackVectorSlowScan {
		t.Fatalf("AttackVector = %v, want slow_scan (its score must stay higher than the anomaly detector's): %+v", last.AttackVector, last)
	}
	if err := decision.Validate(last); err != nil {
		t.Errorf("decision.Validate(%+v) = %v, want nil", last, err)
	}
}

func specificFinding(vector decision.AttackVector, riskScore float64, priority int) triggeredFinding {
	return triggeredFinding{finding: finding.Finding{Triggered: true, AttackVector: vector, RiskScore: riskScore}, priority: priority}
}

func anomalyFinding(riskScore float64) triggeredFinding {
	return specificFinding(decision.AttackVectorUnknown, riskScore, anomalyPriority)
}

func TestSelectAttribution_PrefersSpecific_EvenWithLowerScore(t *testing.T) {
	triggered := []triggeredFinding{
		specificFinding(decision.AttackVectorCredentialStuffing, 0.3, 0),
		anomalyFinding(0.9),
	}

	attribution, secondaries := selectAttribution(triggered)
	if attribution == nil || attribution.AttackVector != decision.AttackVectorCredentialStuffing {
		t.Fatalf("selectAttribution = %+v, want credential_stuffing (específico gana aunque anomaly tenga mayor score)", attribution)
	}
	if attribution.RiskScore != 0.3 {
		t.Errorf("attribution.RiskScore = %v, want 0.3 (el score PROPIO del específico, no el de anomaly)", attribution.RiskScore)
	}
	if len(secondaries) != 1 || secondaries[0].AttackVector != decision.AttackVectorUnknown {
		t.Errorf("secondaries = %+v, want [statistical_anomaly]", secondaries)
	}

	principal, _ := selectPrincipal(triggered)
	if principal == nil || principal.RiskScore != 0.9 {
		t.Fatalf("selectPrincipal = %+v, want RiskScore 0.9 (el mayor score entre TODOS, sin preferencia por específico)", principal)
	}
}

func TestSelectAttribution_BothSpecific_HighestScoreWins(t *testing.T) {
	triggered := []triggeredFinding{
		specificFinding(decision.AttackVectorCredentialStuffing, 0.3, 0),
		specificFinding(decision.AttackVectorSlowScan, 0.7, 1),
	}
	attribution, _ := selectAttribution(triggered)
	if attribution == nil || attribution.AttackVector != decision.AttackVectorSlowScan {
		t.Errorf("selectAttribution = %+v, want slow_scan (mayor score entre los dos específicos)", attribution)
	}
}

func TestSelectAttribution_ExactTie_SpecificPriorityBreaksTie(t *testing.T) {
	triggered := []triggeredFinding{
		specificFinding(decision.AttackVectorSlowScan, 0.5, 1),
		specificFinding(decision.AttackVectorCredentialStuffing, 0.5, 0),
	}
	attribution, _ := selectAttribution(triggered)
	if attribution == nil || attribution.AttackVector != decision.AttackVectorCredentialStuffing {
		t.Errorf("selectAttribution = %+v, want credential_stuffing (empate exacto, prioridad menor gana)", attribution)
	}
}

func TestSelectAttribution_AnomalyOnly_ReturnsUnknown(t *testing.T) {
	triggered := []triggeredFinding{anomalyFinding(0.6)}
	attribution, secondaries := selectAttribution(triggered)
	if attribution == nil || attribution.AttackVector != decision.AttackVectorUnknown {
		t.Errorf("selectAttribution = %+v, want unknown (solo anomaly disparó)", attribution)
	}
	if len(secondaries) != 0 {
		t.Errorf("secondaries = %+v, want vacío", secondaries)
	}
}

func TestSelectAttribution_Empty_ReturnsNil(t *testing.T) {
	attribution, secondaries := selectAttribution(nil)
	if attribution != nil || secondaries != nil {
		t.Errorf("selectAttribution(nil) = (%+v, %+v), want (nil, nil)", attribution, secondaries)
	}
}

func TestDecide_AttributionPrefersSpecific_ButConfidenceScoreStaysMax(t *testing.T) {
	buildCredentialStuffingSequence := func(d *BehavioralDecider, resolver fakeResolver, group string) decision.Decision {
		ips := []netip.Addr{ipFor(0), ipFor(1), ipFor(2), ipFor(3), ipFor(4)}
		for _, ip := range ips {
			resolver[ip] = group
		}
		accounts := []string{"acct-A", "acct-B", "acct-C", "acct-D", "acct-D", "acct-A"}
		statuses := []int{401, 200, 401, 200, 403, 200}
		attemptIPs := []netip.Addr{ips[0], ips[0], ips[1], ips[2], ips[3], ips[4]}
		var last decision.Decision
		for i := range accounts {
			last = d.Decide(context.Background(), loginEvent(attemptIPs[i], time.Duration(i)*time.Second, accounts[i], statuses[i]))
		}
		return last
	}

	csOnlyResolver := fakeResolver{}
	csOnly := newTestDecider(t, csOnlyResolver, ssConfig(), testPolicy())
	csOnlyFinal := buildCredentialStuffingSequence(csOnly, csOnlyResolver, "asn:cs-only")
	if csOnlyFinal.AttackVector != decision.AttackVectorCredentialStuffing || csOnlyFinal.ConfidenceScore != 0.2 {
		t.Fatalf("setup inválido (csOnly): AttackVector=%v ConfidenceScore=%v, want credential_stuffing/0.2", csOnlyFinal.AttackVector, csOnlyFinal.ConfidenceScore)
	}

	ss := ssConfig()
	ss.MinRequests = 1000

	an := anomaly.Config{
		Window:           time.Hour,
		MinSamples:       5,
		ZSaturation:      2.0,
		TriggerThreshold: 0.1,
		Weights:          anomaly.FeatureWeights{NotFound: 1, FailedAuth: 1, PathDiversity: 1, Referer: 1, AccountDiversity: 1},
		ScoreFloor:       0.2,
	}
	resolver := fakeResolver{}
	d := newTestDeciderFull(t, resolver, ss, an, testPolicy())

	for i := 10; i < 15; i++ {
		ip := ipFor(i)
		for j := 0; j < 20; j++ {
			status := 200
			if j%10 == 0 {
				status = 404
			}
			d.Decide(context.Background(), scanEvent(ip, time.Duration(i*30+j)*time.Second, "/normal", status, true, ""))
		}
	}

	anomalousIP := ipFor(4)
	for j := 0; j < 20; j++ {
		status := 200
		if j < 18 {
			status = 404
		}
		d.Decide(context.Background(), scanEvent(anomalousIP, time.Duration(1000+j)*time.Second, "/normal", status, true, ""))
	}

	final := buildCredentialStuffingSequence(d, resolver, "asn:mixed")

	if final.AttackVector != decision.AttackVectorCredentialStuffing {
		t.Fatalf("AttackVector = %v, want credential_stuffing (attribution debe preferir el específico aunque anomaly tenga mayor score): %+v", final.AttackVector, final)
	}
	if !strings.HasPrefix(final.EntityID, "network:") {
		t.Errorf("EntityID = %q, want empezar con \"network:\" (viene del finding específico, no del de anomaly)", final.EntityID)
	}
	if final.ConfidenceScore <= csOnlyFinal.ConfidenceScore {
		t.Errorf("ConfidenceScore = %v, want > %v (Action/ConfidenceScore siguen usando el score MÁS ALTO entre todos, no el propio de credential_stuffing)", final.ConfidenceScore, csOnlyFinal.ConfidenceScore)
	}
	if err := decision.Validate(final); err != nil {
		t.Errorf("decision.Validate(%+v) = %v, want nil", final, err)
	}
}

func TestDecide_Concurrent_NoRaces(t *testing.T) {
	const n = 50
	d := newTestDecider(t, fakeResolver{}, ssConfig(), testPolicy())

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			ip := ipFor(i)
			e := scanEvent(ip, time.Duration(i)*time.Second, "/", 200, true, "")
			got := d.Decide(context.Background(), e)
			if err := decision.Validate(got); err != nil {
				t.Errorf("decision.Validate(%+v) = %v, want nil", got, err)
			}
		}(i)
	}
	wg.Wait()
}
