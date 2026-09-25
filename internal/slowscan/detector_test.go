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

// ipFor arma una dirección determinista y distinta para el índice i,
// dentro de 203.0.113.0/24 (RFC 5737, documentación).
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

// --- Config.Validate ------------------------------------------------------

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

// --- El caso central: escaneo lento claro que dispara ---------------------

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

// --- Mismo volumen concentrado en una sola ruta: NO es scanning -----------

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

// --- Muchas rutas legítimas con pocos 404: crawler/SPA ---------------------

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

// --- Muchos 404 sobre pocas rutas repetidas: NO deben bastar ---------------

func TestEvaluate_ManyNotFoundFewPaths_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		path := sensitivePath(i % 3) // solo 3 rutas distintas, repetidas
		last = observe(d, ev(ip, time.Duration(i)*time.Minute, path, 404, false))
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — only 3 distinct paths, below MinDistinctPaths: %+v", last)
	}
}

// --- Cliente API sin Referer, navegación estable: NO dispara ---------------

func TestEvaluate_StableAPIClientNoReferer_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		path := realPath(i % 5) // 5 endpoints estables, repetidos
		last = observe(d, ev(ip, time.Duration(i)*time.Minute, path, 200, false))
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — a stable API client without Referer must not trigger by itself: %+v", last)
	}
}

// --- Ausencia de Referer sola no dispara -----------------------------------

func TestEvaluate_MissingRefererAlone_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	// Volumen y diversidad deliberadamente muy por debajo del gate —
	// lo único "sospechoso" acá es que no hay Referer en ningún caso.
	for i := 0; i < 5; i++ {
		last = observe(d, ev(ip, time.Duration(i)*time.Minute, sensitivePath(i%3), 404, false))
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — missing Referer alone must never be sufficient: %+v", last)
	}
}

// --- Escaneo con intervalos grandes que sí se acumula en la ventana -------

func TestEvaluate_SlowScanWithLargeGaps_AccumulatesWithinWindow(t *testing.T) {
	d := newTestDetector(t, baseConfig()) // Window = 2h
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		// Gaps de 6 minutos: 20 requests caen en ~114 minutos, dentro
		// de la ventana de 2 horas, pero muy por debajo de cualquier
		// rate limit tradicional.
		last = observe(d, ev(ip, time.Duration(i)*6*time.Minute, sensitivePath(i), 404, false))
	}

	if !last.Triggered {
		t.Fatal("Triggered = false, want true — the pattern should still accumulate within a wide enough window")
	}
}

// --- Eventos fuera de ventana dejan de contribuir --------------------------

func TestEvaluate_EventsOutsideWindow_StopContributing(t *testing.T) {
	d := newTestDetector(t, baseConfig()) // Window = 2h
	ip := ipFor(0)

	var trigger finding.Finding
	for i := 0; i < 20; i++ {
		trigger = observe(d, ev(ip, time.Duration(i)*time.Minute, sensitivePath(i), 404, false))
	}
	if !trigger.Triggered {
		t.Fatalf("first batch did not trigger, want it to (test setup issue): %+v", trigger)
	}

	// 5 horas después (Window=2h): todo el primer lote ya expiró.
	late := ev(ip, 5*time.Hour, realPath(0), 200, true)
	after := observe(d, late)

	if after.Triggered {
		t.Errorf("Triggered = true after the window elapsed, want false: %+v", after)
	}
}

// --- Eventos fuera de orden: invariancia --------------------------------

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

// --- Evento sin session_id: cae a evaluación por IP ------------------------

func TestEvaluate_EventWithoutSessionID_FallsBackToIP(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for i := 0; i < 20; i++ {
		e := ev(ip, time.Duration(i)*time.Minute, sensitivePath(i), 404, false) // SessionID == ""
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

// --- Entropía calculada a mano ---------------------------------------------

func TestNormalizedEntropy_HandComputed(t *testing.T) {
	// 4 rutas, 1 visita cada una: máxima diversidad posible con 4
	// rutas distintas -> entropía normalizada = 1.0.
	uniform := map[string]int{"/a": 1, "/b": 1, "/c": 1, "/d": 1}
	if got := normalizedEntropy(uniform, 4, 4); got < 0.999 || got > 1.001 {
		t.Errorf("normalizedEntropy(uniform) = %v, want ~1.0", got)
	}

	// 4 rutas, muy concentrado: {17,1,1,1} sobre 20 -> H≈0.848 bits,
	// max=log2(4)=2 -> normalizada ≈ 0.424.
	skewed := map[string]int{"/a": 17, "/b": 1, "/c": 1, "/d": 1}
	got := normalizedEntropy(skewed, 20, 4)
	want := 0.424
	if got < want-0.01 || got > want+0.01 {
		t.Errorf("normalizedEntropy(skewed) = %v, want ~%v", got, want)
	}

	// Una sola ruta: sin diversidad, entropía 0 por definición.
	if got := normalizedEntropy(map[string]int{"/a": 10}, 10, 1); got != 0 {
		t.Errorf("normalizedEntropy(single path) = %v, want 0", got)
	}
}

// --- Novedad de rutas calculada a mano --------------------------------------

func TestNovelPathRatio_HandComputed(t *testing.T) {
	d := newTestDetector(t, baseConfig()) // MaxVisitorsForNovelPath = 1
	thisIP := ipFor(0)
	otherIP := ipFor(1)

	// "/" la piden esta IP y otra más (2 visitantes distintos: no es
	// "novel"). "/wp-admin" la pide únicamente esta IP (1 visitante:
	// sí es "novel").
	d.paths.observe("/", thisIP, testBase)
	d.paths.observe("/", otherIP, testBase.Add(time.Second))
	d.paths.observe("/wp-admin", thisIP, testBase.Add(2*time.Second))

	pathCounts := map[string]int{"/": 1, "/wp-admin": 1}
	got := d.novelPathRatio(pathCounts, 2)
	want := 0.5 // 1 de 2 rutas es novel
	if got != want {
		t.Errorf("novelPathRatio = %v, want %v", got, want)
	}
}

// --- RiskScore nunca cero cuando Triggered es true --------------------------

// TestEvaluate_AllSignalsExactlyAtThreshold_TriggersWithPositiveScore arma,
// a mano, un caso donde las cinco señales del gate caen EXACTO en su
// umbral configurado, y confirma Triggered=true con RiskScore
// exactamente igual a ScoreFloor (con Referer en 0 para que el
// promedio de las seis componentes dé exactamente 0).
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

	// 5 rutas (/p1../p5), 2 requests cada una (uniforme -> entropía
	// exacta 1.0), 1 de cada 2 es 404 (ratio exacto 0.5), todas con
	// Referer (para que el componente de Referer dé 0). /p1,/p2,/p3
	// solo las visita esta IP (novel); /p4,/p5 también las visita
	// "other" (no novel) -> 3 de 5 son novel = 0.6 exacto.
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

// --- Los tres tests nuevos de IP + sesión -----------------------------------

// TestEvaluate_ScannerRotatingSessions_DetectedByIP es el caso central
// de la corrección: un atacante que rota session_id para que cada
// sesión, individualmente, se quede por debajo de los umbrales —
// mientras el agregado de la IP sí representa un escaneo claro.
func TestEvaluate_ScannerRotatingSessions_DetectedByIP(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for s := 0; s < 4; s++ {
		sessionID := fmt.Sprintf("s-%d", s)
		for j := 0; j < 5; j++ {
			path := fmt.Sprintf("/sensitive-%d-%d", s, j) // 5 rutas por sesión, 20 en total, todas distintas
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

// TestEvaluate_LegitNATMultipleSessions_DoesNotTrigger confirma que un
// NAT legítimo con varias sesiones navegando normalmente no dispara —
// ni por sesión ni por IP — porque el gate completo (en particular,
// NotFoundRatio) sigue exigiendo el patrón real de escaneo, no solo
// diversidad de rutas agregada.
func TestEvaluate_LegitNATMultipleSessions_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var last finding.Finding
	for s := 0; s < 3; s++ {
		sessionID := fmt.Sprintf("s-%d", s)
		for j := 0; j < 8; j++ {
			path := realPath(s*8 + j) // rutas reales, todas distintas entre sesiones
			e := evSession(ip, time.Duration(s*20+j)*time.Minute, path, 200, true, sessionID)
			last = observe(d, e)
		}
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — a legit NAT with normal browsing must not trigger by aggregation alone: %+v", last)
	}
}

// TestEvaluate_IPAndSessionBothTrigger_ReturnsSingleFinding fuerza un
// empate exacto (toda la IP pertenece a una única sesión, así que las
// dos perspectivas calculan sobre los mismos datos) y confirma que se
// devuelve un único Finding, y que en un empate exacto gana sesión.
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

// --- Concurrencia ------------------------------------------------------------

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
	d := newTestDetector(t, baseConfig()) // Window = 2h
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
