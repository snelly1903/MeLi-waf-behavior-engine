package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

var testBase = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

// fakeResolver es un NetworkResolver determinista, exclusivamente
// para estos tests — nunca código de producción (ver
// credstuffing.UnavailableNetworkResolver para el equivalente real).
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

// csConfig son los umbrales de credential stuffing usados en la
// mayoría de estos tests — valores de prueba para poder calcularlos a
// mano, nunca umbrales finales de calibración.
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

// ssConfig son los umbrales de slow scan usados en la mayoría de
// estos tests — deliberadamente laxos (MinRouteEntropy=0.6, no 1.0)
// para que agregar tráfico extra a una IP (por ejemplo, sus propios
// intentos de login) no rompa el gate. El test de empate exacto usa
// su propia configuración más estricta (ver
// TestDecide_ExactTie_CredentialStuffingWins).
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

// inertAnomalyConfig tiene un MinSamples tan alto que el detector
// estadístico nunca termina de calentar (nunca dispara) dentro de
// estos tests — usado por defecto en newTestDecider para que los
// escenarios de credential_stuffing/slow_scan ya probados en la tarea
// 1.5 sigan funcionando exactamente igual con un tercer detector
// agregado. Los tests que sí ejercitan el detector estadístico usan
// newTestDeciderFull con su propia anomaly.Config activa.
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
	d, err := NewBehavioralDecider(cs, ssDetector, anDetector, policy)
	if err != nil {
		t.Fatalf("NewBehavioralDecider: %v", err)
	}
	return d
}

func sensitivePath(i int) string { return fmt.Sprintf("/sensitive-%d", i) }

// --- Policy -----------------------------------------------------------

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

// TestPolicy_ActionFor_Boundaries cubre directamente los dos bordes
// exactos pedidos: score exactamente en ChallengeThreshold y
// exactamente en BlockThreshold — probado sobre la función pura, sin
// necesidad de construir un escenario de detector que dé ese score
// exacto.
func TestPolicy_ActionFor_Boundaries(t *testing.T) {
	p := Policy{ChallengeThreshold: 0.5, BlockThreshold: 0.8}
	tests := []struct {
		score float64
		want  decision.Action
	}{
		{0.0, decision.ActionAllow},
		{0.49, decision.ActionAllow},
		{0.5, decision.ActionChallenge}, // exactamente en ChallengeThreshold
		{0.65, decision.ActionChallenge},
		{0.8, decision.ActionBlock}, // exactamente en BlockThreshold
		{0.95, decision.ActionBlock},
	}
	for _, tc := range tests {
		if got := p.actionFor(tc.score); got != tc.want {
			t.Errorf("actionFor(%v) = %v, want %v", tc.score, got, tc.want)
		}
	}
}

// --- NewBehavioralDecider ----------------------------------------------

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

	if _, err := NewBehavioralDecider(nil, ss, an, testPolicy()); !errors.Is(err, ErrNilCredentialStuffingDetector) {
		t.Errorf("nil credstuffing: error = %v, want ErrNilCredentialStuffingDetector", err)
	}
	if _, err := NewBehavioralDecider(cs, nil, an, testPolicy()); !errors.Is(err, ErrNilSlowScanDetector) {
		t.Errorf("nil slowscan: error = %v, want ErrNilSlowScanDetector", err)
	}
	if _, err := NewBehavioralDecider(cs, ss, nil, testPolicy()); !errors.Is(err, ErrNilAnomalyDetector) {
		t.Errorf("nil anomaly: error = %v, want ErrNilAnomalyDetector", err)
	}
	if _, err := NewBehavioralDecider(cs, ss, an, Policy{ChallengeThreshold: 0.8, BlockThreshold: 0.5}); !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("invalid policy: error = %v, want ErrInvalidPolicy", err)
	}
}

// --- Caso base: nadie dispara --------------------------------------------

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

// --- Finding disparado pero bajo ChallengeThreshold: sigue en ALLOW -----

// TestDecide_FindingBelowChallengeThreshold_StaysAllowButPreservesEvidence
// construye la campaña de credential stuffing EXACTAMENTE en su
// umbral (RiskScore = ScoreFloor = 0.2, por debajo de
// ChallengeThreshold = 0.5) y confirma que, aunque Action quede en
// ALLOW, la Decision preserva AttackVector, ConfidenceScore, EntityID,
// señales y explicación — nunca los tira porque no se actuó.
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
	attemptIPs := []netip.Addr{ips[0], ips[0], ips[1], ips[2], ips[3], ips[4]} // ips[0] hace 2 intentos

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

// --- Finding sobre ChallengeThreshold: CHALLENGE --------------------------

func TestDecide_FindingAboveChallengeThreshold_ReturnsChallenge(t *testing.T) {
	resolver := fakeResolver{}
	d := newTestDecider(t, resolver, ssConfig(), testPolicy())

	group := "asn:moderate"
	// 15 IPs distintas (5 con 2 intentos, 10 con 1 = 20 intentos
	// totales), 10 cuentas distintas, 14/20 fallos (ratio 0.7).
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
	for i := 0; i < 5; i++ { // 5 IPs repiten
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

// --- Finding sobre BlockThreshold: BLOCK (y slow scan como principal) ----

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

// --- EntityID correcto para sesión -----------------------------------------

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

// --- credential_stuffing como principal (aislado) -------------------------

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

// --- slow_scan como principal (aislado) ------------------------------------

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

// --- Ambos disparan, gana el mayor score ----------------------------------

// TestDecide_BothTrigger_HigherScoreWins hace que credential_stuffing
// dispare apenas (score exacto en su umbral, 0.2) mientras la MISMA
// IP también corre un escaneo lento claro (score muy por encima de
// 0.8) — el resultado final tiene que reflejar slow_scan, con score
// mucho mayor que 0.2.
func TestDecide_BothTrigger_HigherScoreWins(t *testing.T) {
	resolver := fakeResolver{}
	d := newTestDecider(t, resolver, ssConfig(), testPolicy())

	group := "asn:winner-test"
	ip0 := ipFor(0)
	other := []netip.Addr{ipFor(1), ipFor(2), ipFor(3), ipFor(4)}
	for _, ip := range append(other, ip0) {
		resolver[ip] = group
	}

	// Campaña de credential stuffing exactamente en su umbral: 6
	// intentos, 5 IPs (ip0 hace 2), 4 cuentas, 3/6 fallos.
	accounts := []string{"acct-A", "acct-C", "acct-D", "acct-D", "acct-A", "acct-B"}
	statuses := []int{401, 401, 200, 403, 200, 200}
	ips := []netip.Addr{other[0], other[1], other[2], other[3], ip0}
	for i := 0; i < 4; i++ {
		d.Decide(context.Background(), loginEvent(ips[i], time.Duration(i)*time.Second, accounts[i], statuses[i]))
	}
	d.Decide(context.Background(), loginEvent(ip0, 4*time.Second, accounts[4], statuses[4]))

	// ip0 también corre un escaneo lento claro, con 50 rutas
	// sensibles distintas.
	for i := 0; i < 50; i++ {
		d.Decide(context.Background(), scanEvent(ip0, time.Duration(10+i)*time.Second, sensitivePath(i), 404, false, ""))
	}

	// Probe final: el segundo intento de login de ip0 — necesario
	// para que credstuffing.Evaluate tenga algo que evaluar (solo
	// mira rutas de autenticación).
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

// --- Empate exacto: gana credential_stuffing ------------------------------

// TestDecide_ExactTie_CredentialStuffingWins es el test más delicado:
// arma, a mano, un evento tal que credential_stuffing y slow_scan
// disparan con EXACTAMENTE el mismo RiskScore (0.2, el ScoreFloor de
// los dos, con las cinco/cuatro señales de cada gate exactamente en su
// umbral) — y confirma que gana credential_stuffing, la regla de
// desempate documentada.
func TestDecide_ExactTie_CredentialStuffingWins(t *testing.T) {
	resolver := fakeResolver{}
	// slow scan necesita, acá sí, la configuración estricta
	// (MinRouteEntropy=1.0) para que el ejemplo dé un empate exacto.
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

	// credential stuffing: 6 intentos, 5 IPs (ip0 hace 2), 4 cuentas,
	// ratio de fallo exacto 0.5.
	d.Decide(context.Background(), loginEvent(ip0, 0, "acct-A", 401))
	d.Decide(context.Background(), loginEvent(ip1, 1*time.Second, "acct-C", 401))
	d.Decide(context.Background(), loginEvent(ip2, 2*time.Second, "acct-D", 200))
	d.Decide(context.Background(), loginEvent(ip3, 3*time.Second, "acct-D", 403))
	d.Decide(context.Background(), loginEvent(ip4, 4*time.Second, "acct-A", 200))

	// slow scan de ip0: además de sus 2 logins (path "/login", ya
	// contados arriba), 8 requests más sobre 4 rutas nuevas — 5 rutas
	// distintas en total (login,p2,p3,p4,p5), 2 visitas cada una,
	// entropía exacta 1.0.
	d.Decide(context.Background(), scanEvent(ip0, 5*time.Second, "/p2", 404, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 6*time.Second, "/p2", 200, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 7*time.Second, "/p3", 404, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 8*time.Second, "/p3", 200, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 9*time.Second, "/p4", 404, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 10*time.Second, "/p4", 200, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 11*time.Second, "/p5", 404, true, ""))
	d.Decide(context.Background(), scanEvent(ip0, 12*time.Second, "/p5", 404, true, ""))
	// "other" visita /p2 también, para que quede 3 rutas "novel"
	// (p3,p4,p5) de 5 -> NovelPathRatio exacto 0.6.
	d.Decide(context.Background(), scanEvent(other, 13*time.Second, "/p2", 200, true, ""))

	// Probe final: la segunda petición de login de ip0.
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

// --- El detector estadístico como tercera fuente de Finding ---------------

// TestDecide_AnomalyFindingCanBePrincipal_WhenHigherScore confirma que
// el Finding del detector estadístico puede llegar a ser el principal
// de la Decision — no solo credential_stuffing/slow_scan. Usa un
// resolver vacío (credential stuffing nunca resuelve ningún grupo,
// estructuralmente inerte) y un slowscan.Config con MinRequests muy
// alto (nunca se alcanza con estos lotes, estructuralmente inerte
// también), así que la única fuente de evidencia posible es
// internal/anomaly.
func TestDecide_AnomalyFindingCanBePrincipal_WhenHigherScore(t *testing.T) {
	ss := ssConfig()
	ss.MinRequests = 1000 // nunca se alcanza acá: slow_scan queda inerte

	an := anomaly.Config{
		Window:           time.Hour,
		MinSamples:       5,
		ZSaturation:      2.0,
		TriggerThreshold: 0.1,
		Weights:          anomaly.FeatureWeights{NotFound: 1, FailedAuth: 1, PathDiversity: 1, Referer: 1, AccountDiversity: 1},
		ScoreFloor:       0.2,
	}
	d := newTestDeciderFull(t, fakeResolver{}, ss, an, testPolicy())

	// Tráfico "normal" de cinco entidades: mayormente 200, un puñado
	// de 404 ocasionales — calienta el baseline estadístico.
	var last decision.Decision
	for i := 0; i < 5; i++ {
		ip := ipFor(i)
		for j := 0; j < 20; j++ {
			status := 200
			if j%10 == 0 { // ~10% not-found
				status = 404
			}
			e := scanEvent(ip, time.Duration(i*30+j)*time.Second, "/normal", status, true, "")
			last = d.Decide(context.Background(), e)
		}
	}

	// Una entidad claramente anómala: 90% not-found.
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

// TestDecide_OtherDetectorStaysPrincipal_OverAnomaly confirma lo
// contrario: aunque el detector estadístico también dispare, un
// detector con un score claramente mayor (acá, slow_scan, con un
// escaneo lento evidente) sigue siendo el principal — el estadístico
// no "gana" solo por existir.
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

	// Calienta el baseline estadístico con tráfico modesto de otras
	// entidades, antes del escaneo lento real.
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

	// Escaneo lento real y evidente — score muy por encima de lo que
	// puede dar el detector estadístico con una sola señal dominante.
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

// --- Concurrencia ------------------------------------------------------------

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
