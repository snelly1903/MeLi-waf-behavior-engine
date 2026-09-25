package anomaly

import (
	"fmt"
	"math"
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

// buildEvents arma total eventos de una entidad, con conteos exactos
// para cada señal — así las ratios resultantes (NotFoundRatio,
// FailedAuthRatio, PathDiversityRatio, WithoutRefererRatio,
// AccountDiversityRatio) quedan bajo control total, sin depender de
// ningún sorteo aleatorio.
func buildEvents(ip netip.Addr, total, notFound, failedAuth, distinctPaths, withoutReferer, distinctAccounts int, offsetBase time.Duration) []event.Event {
	events := make([]event.Event, total)
	for i := 0; i < total; i++ {
		status := 200
		switch {
		case i < notFound:
			status = 404
		case i < notFound+failedAuth:
			status = 401
		}
		path := "/p-0"
		if distinctPaths > 0 {
			path = fmt.Sprintf("/p-%d", i%distinctPaths)
		}
		referer := "https://example.com/"
		if i < withoutReferer {
			referer = ""
		}
		account := ""
		if distinctAccounts > 0 {
			account = fmt.Sprintf("acct-%d", i%distinctAccounts)
		}
		events[i] = event.Event{
			RequestID:     fmt.Sprintf("r-%d", i),
			Timestamp:     testBase.Add(offsetBase + time.Duration(i)*time.Second),
			ClientIP:      ip,
			Method:        "GET",
			Path:          path,
			StatusCode:    status,
			Referer:       referer,
			LoginUserHash: account,
		}
	}
	return events
}

// evaluateBatch observa todos los eventos del lote (así el snapshot
// de profile.Store queda completo) y recién entonces llama Evaluate
// UNA sola vez, con el último evento — para que cada entidad aporte
// exactamente UNA muestra al baseline global, no una por cada evento
// parcial del lote.
func evaluateBatch(d *Detector, events []event.Event) finding.Finding {
	for _, e := range events {
		d.Observe(e)
	}
	return d.Evaluate(events[len(events)-1])
}

func testConfig() Config {
	return Config{
		Window:           time.Hour,
		MinSamples:       10,
		ZSaturation:      2.0,
		TriggerThreshold: 0.1,
		Weights:          FeatureWeights{NotFound: 1, FailedAuth: 1, PathDiversity: 1, Referer: 1, AccountDiversity: 1},
		ScoreFloor:       0.2,
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

// warmupBatch arma un lote "normal" con variación leve entre
// entidades (idx), para que el baseline termine con varianza
// distinta de cero en las cinco features — sin esto, cualquier
// desviación posterior daría z=0 por la guarda de varianza cero, y no
// probaría nada.
func warmupBatch(ip netip.Addr, idx int, offsetBase time.Duration) []event.Event {
	total := 20
	notFound := 1 + idx%4      // ratio .05–.20
	failedAuth := idx % 3      // ratio 0–.10
	distinctPaths := 3 + idx%3 // ratio .15–.25
	withoutReferer := 1 + idx%3
	distinctAccounts := idx % 2
	return buildEvents(ip, total, notFound, failedAuth, distinctPaths, withoutReferer, distinctAccounts, offsetBase)
}

// --- Config.Validate ------------------------------------------------------

func TestConfig_Validate_InvalidConfigurations(t *testing.T) {
	valid := testConfig()
	tests := []struct {
		name   string
		modify func(c Config) Config
	}{
		{"zero window", func(c Config) Config { c.Window = 0; return c }},
		{"min samples below 2", func(c Config) Config { c.MinSamples = 1; return c }},
		{"zero z saturation", func(c Config) Config { c.ZSaturation = 0; return c }},
		{"zero trigger threshold", func(c Config) Config { c.TriggerThreshold = 0; return c }},
		{"trigger threshold at 1", func(c Config) Config { c.TriggerThreshold = 1; return c }},
		{"zero score floor", func(c Config) Config { c.ScoreFloor = 0; return c }},
		{"all weights zero", func(c Config) Config { c.Weights = FeatureWeights{}; return c }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.modify(valid).Validate(); err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
		})
	}
}

func TestNewDetector_InvalidConfig_ReturnsError(t *testing.T) {
	cfg := testConfig()
	cfg.Window = 0
	if _, err := NewDetector(cfg); err == nil {
		t.Fatal("NewDetector() error = nil, want an error")
	}
}

// --- Welford: media y varianza calculadas a mano --------------------------

// TestBaseline_Welford_HandComputed alimenta el baseline con la
// secuencia [1,2,3,4,5] (replicada en las cinco features) y confirma
// mean=3, varianza muestral=2.5 (M2/(n-1) = 10/4), calculado a mano:
// desviaciones respecto a la media final (3): (-2,-1,0,1,2) al
// cuadrado suman 4+1+0+1+4=10.
func TestBaseline_Welford_HandComputed(t *testing.T) {
	b := &baseline{}
	for _, x := range []float64{1, 2, 3, 4, 5} {
		var sample [featureCount]float64
		for i := range sample {
			sample[i] = x
		}
		b.update(sample)
	}

	snap := b.snapshot()
	if snap.n != 5 {
		t.Fatalf("n = %d, want 5", snap.n)
	}
	for i, s := range snap.stats {
		if math.Abs(s.mean-3) > 1e-9 {
			t.Errorf("feature %d: mean = %v, want 3", i, s.mean)
		}
		if math.Abs(s.m2-10) > 1e-9 {
			t.Errorf("feature %d: m2 = %v, want 10", i, s.m2)
		}
		variance := s.m2 / float64(snap.n-1)
		if math.Abs(variance-2.5) > 1e-9 {
			t.Errorf("feature %d: variance = %v, want 2.5", i, variance)
		}
	}
}

// --- Z-score calculado a mano, y contra el baseline PREVIO -----------------

// TestEvaluateFeatures_ZScore_HandComputed construye a mano un
// baselineSnapshot con mean=3, m2=10 (n=5, mismo baseline del test
// anterior) y puntúa x=8: z = (8-3)/sqrt(2.5) ≈ 3.1623. Como el
// snapshot se arma ANTES de llamar evaluateFeatures y evaluateFeatures
// nunca lo modifica, este mismo test prueba a la vez que la
// puntuación usa el baseline previo, no uno que ya incluya la
// observación actual.
func TestEvaluateFeatures_ZScore_HandComputed(t *testing.T) {
	d := newTestDetector(t, testConfig())
	bl := baselineSnapshot{n: 5}
	for i := range bl.stats {
		bl.stats[i] = featureStats{mean: 3, m2: 10}
	}

	var x [featureCount]float64
	for i := range x {
		x[i] = 8
	}

	f := d.evaluateFeatures(x, bl, scope{label: "ip", key: "203.0.113.1"})

	wantZ := (8.0 - 3.0) / math.Sqrt(2.5)
	if !f.Triggered {
		t.Fatalf("Triggered = false, want true (z ≈ %.4f on every feature)", wantZ)
	}
	if len(f.ContributingSignals) != int(featureCount) {
		t.Fatalf("ContributingSignals has %d entries, want %d", len(f.ContributingSignals), featureCount)
	}
	for _, sig := range f.ContributingSignals {
		if math.Abs(sig.Value-wantZ) > 1e-6 {
			t.Errorf("%s: z = %v, want ≈ %v", sig.Name, sig.Value, wantZ)
		}
	}
}

// --- Varianza cero: sin NaN/Inf ---------------------------------------------

func TestEvaluateFeatures_ZeroVariance_NoNaNOrInf(t *testing.T) {
	d := newTestDetector(t, testConfig())
	// n=5, m2=0 en las cinco features: varianza (todavía) cero.
	bl := baselineSnapshot{n: 5}
	for i := range bl.stats {
		bl.stats[i] = featureStats{mean: 0.1, m2: 0}
	}
	var x [featureCount]float64
	for i := range x {
		x[i] = 0.9 // se aleja del mean, pero la varianza sigue en 0
	}

	f := d.evaluateFeatures(x, bl, scope{label: "ip", key: "203.0.113.2"})

	// z tiene que quedar en 0 para cada feature (no NaN, no Inf) — no
	// se puede afirmar "cuántos desvíos estándar" de algo sin desvío
	// todavía.
	for _, sig := range f.ContributingSignals {
		if math.IsNaN(sig.Value) || math.IsInf(sig.Value, 0) {
			t.Fatalf("%s: z = %v, want a finite number (0)", sig.Name, sig.Value)
		}
		if sig.Value != 0 {
			t.Errorf("%s: z = %v, want exactly 0 with zero variance", sig.Name, sig.Value)
		}
	}
	if f.Triggered {
		t.Error("Triggered = true, want false (every z is 0, combined score must be 0)")
	}
}

// --- RiskScore siempre en [0,1] ---------------------------------------------

func TestEvaluateFeatures_RiskScore_AlwaysInBounds(t *testing.T) {
	d := newTestDetector(t, testConfig())
	bl := baselineSnapshot{n: 100}
	for i := range bl.stats {
		bl.stats[i] = featureStats{mean: 0.1, m2: 1}
	}

	for _, magnitude := range []float64{0.1, 1, 10, 1000, 1e9} {
		var x [featureCount]float64
		for i := range x {
			x[i] = magnitude
		}
		f := d.evaluateFeatures(x, bl, scope{label: "ip", key: "203.0.113.3"})
		if !f.Triggered {
			continue
		}
		if f.RiskScore < 0 || f.RiskScore >= 1 {
			t.Errorf("magnitude=%v: RiskScore = %v, want it in [0, 1)", magnitude, f.RiskScore)
		}
	}
}

// --- Warm-up: nunca dispara, sin importar el valor -------------------------

func TestEvaluate_DuringWarmUp_NeverTriggers(t *testing.T) {
	d := newTestDetector(t, testConfig()) // MinSamples = 10
	for i := 0; i < 10; i++ {
		// Valores deliberadamente extremos — ni así puede disparar
		// durante el warm-up.
		events := buildEvents(ipFor(i), 20, 18, 5, 1, 20, 1, time.Duration(i)*time.Minute)
		f := evaluateBatch(d, events)
		if f.Triggered {
			t.Fatalf("sample %d (still warming up): Triggered = true, want false", i)
		}
	}
}

// --- Tráfico estable no dispara ---------------------------------------------

func TestEvaluate_StableTraffic_DoesNotTrigger(t *testing.T) {
	d := newTestDetector(t, testConfig())
	for i := 0; i < 10; i++ {
		evaluateBatch(d, warmupBatch(ipFor(i), i, time.Duration(i)*time.Minute))
	}

	// Una entidad más, con valores típicos del rango ya visto
	// (notFound=2/20=.10, failedAuth=1/20=.05, etc.).
	events := buildEvents(ipFor(20), 20, 2, 1, 4, 2, 0, 20*time.Minute)
	f := evaluateBatch(d, events)

	if f.Triggered {
		t.Errorf("Triggered = true, want false — this looks like normal traffic: %+v", f)
	}
}

// --- Desviación clara dispara ------------------------------------------------

func TestEvaluate_ClearDeviation_Triggers(t *testing.T) {
	d := newTestDetector(t, testConfig())
	for i := 0; i < 10; i++ {
		evaluateBatch(d, warmupBatch(ipFor(i), i, time.Duration(i)*time.Minute))
	}

	// 90% not-found — muy por encima de cualquier valor visto en el
	// warm-up (.05–.20).
	events := buildEvents(ipFor(21), 20, 18, 0, 4, 2, 0, 21*time.Minute)
	f := evaluateBatch(d, events)

	if !f.Triggered {
		t.Fatal("Triggered = false, want true (90% not-found is far outside the learned baseline)")
	}
	if f.AttackVector != decision.AttackVectorUnknown {
		t.Errorf("AttackVector = %v, want unknown", f.AttackVector)
	}
	if f.RiskScore <= 0 || f.RiskScore >= 1 {
		t.Errorf("RiskScore = %v, want it in (0, 1)", f.RiskScore)
	}
}

// --- Anomalía por 404 y por errores de autenticación, por separado --------

func TestEvaluate_AnomalyByNotFoundRatio_Triggers(t *testing.T) {
	d := newTestDetector(t, testConfig())
	for i := 0; i < 10; i++ {
		evaluateBatch(d, warmupBatch(ipFor(i), i, time.Duration(i)*time.Minute))
	}
	events := buildEvents(ipFor(22), 20, 19, 0, 4, 2, 0, 22*time.Minute) // 95% not-found
	f := evaluateBatch(d, events)
	if !f.Triggered {
		t.Fatal("Triggered = false, want true for a clear not-found spike")
	}
}

func TestEvaluate_AnomalyByFailedAuthRatio_Triggers(t *testing.T) {
	d := newTestDetector(t, testConfig())
	for i := 0; i < 10; i++ {
		evaluateBatch(d, warmupBatch(ipFor(i), i, time.Duration(i)*time.Minute))
	}
	events := buildEvents(ipFor(23), 20, 0, 18, 4, 2, 0, 23*time.Minute) // 90% 401
	f := evaluateBatch(d, events)
	if !f.Triggered {
		t.Fatal("Triggered = false, want true for a clear failed-auth spike")
	}
}

// --- Entidad nueva: puntuada contra un baseline ya calentado --------------

func TestEvaluate_NewEntity_ScoredAgainstAlreadyWarmBaseline(t *testing.T) {
	d := newTestDetector(t, testConfig())
	for i := 0; i < 10; i++ {
		evaluateBatch(d, warmupBatch(ipFor(i), i, time.Duration(i)*time.Minute))
	}

	// ipFor(99) nunca apareció antes — su PRIMERA observación ya se
	// puede puntuar, sin esperar historia propia.
	events := buildEvents(ipFor(99), 20, 18, 0, 4, 2, 0, 99*time.Minute)
	f := evaluateBatch(d, events)

	if !f.Triggered {
		t.Fatal("Triggered = false, want true — a brand-new entity's first observation must still be scored against the already-warm population baseline")
	}
}

// --- Anti-contaminación: una muestra disparada no se agrega al baseline --

func TestEvaluate_TriggeredSampleExcludedFromBaseline(t *testing.T) {
	d := newTestDetector(t, testConfig())
	for i := 0; i < 10; i++ {
		evaluateBatch(d, warmupBatch(ipFor(i), i, time.Duration(i)*time.Minute))
	}

	extreme := func(ip netip.Addr, offset time.Duration) []event.Event {
		return buildEvents(ip, 20, 18, 0, 4, 2, 0, offset)
	}

	first := evaluateBatch(d, extreme(ipFor(30), 30*time.Minute))
	if !first.Triggered {
		t.Fatal("first extreme sample did not trigger (test setup issue)")
	}

	// Si la primera muestra extrema se hubiera agregado al baseline,
	// la media/varianza ya se habrían movido hacia ella, y esta
	// segunda muestra IDÉNTICA daría un z-score (y por lo tanto un
	// RiskScore) notablemente MENOR.
	second := evaluateBatch(d, extreme(ipFor(31), 31*time.Minute))
	if !second.Triggered {
		t.Fatal("second identical extreme sample did not trigger")
	}
	if math.Abs(first.RiskScore-second.RiskScore) > 1e-9 {
		t.Errorf("RiskScore changed between two identical extreme samples: first=%v second=%v — the first one must have leaked into the baseline", first.RiskScore, second.RiskScore)
	}
}

// --- EntityID correcto -------------------------------------------------------

func TestEvaluate_EntityID_ForIP(t *testing.T) {
	d := newTestDetector(t, testConfig())
	for i := 0; i < 10; i++ {
		evaluateBatch(d, warmupBatch(ipFor(i), i, time.Duration(i)*time.Minute))
	}
	ip := ipFor(40)
	events := buildEvents(ip, 20, 18, 0, 4, 2, 0, 40*time.Minute)
	f := evaluateBatch(d, events)

	want := "ip:" + ip.String()
	if f.EntityID != want {
		t.Errorf("EntityID = %q, want %q", f.EntityID, want)
	}
}

func TestEvaluate_EntityID_ForSession(t *testing.T) {
	d := newTestDetector(t, testConfig())
	for i := 0; i < 10; i++ {
		evaluateBatch(d, warmupBatch(ipFor(i), i, time.Duration(i)*time.Minute))
	}
	ip := ipFor(41)
	sessionID := "s-only"
	events := buildEvents(ip, 20, 18, 0, 4, 2, 0, 41*time.Minute)
	for i := range events {
		events[i].SessionID = sessionID
	}
	f := evaluateBatch(d, events)

	// Toda la IP pertenece a una única sesión: en empate, gana
	// sesión — mismo criterio que internal/slowscan (tarea 1.4).
	want := "session:" + sessionID
	if f.EntityID != want {
		t.Errorf("EntityID = %q, want %q", f.EntityID, want)
	}
}

// --- Concurrencia ------------------------------------------------------------

func TestEvaluate_ConcurrentWrites_NoRaces(t *testing.T) {
	d := newTestDetector(t, testConfig())
	// Warm-up en serie, antes de la parte concurrente.
	for i := 0; i < 10; i++ {
		evaluateBatch(d, warmupBatch(ipFor(i), i, time.Duration(i)*time.Minute))
	}

	const n = 30
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			events := buildEvents(ipFor(100+i), 20, 2, 1, 4, 2, 0, time.Duration(100+i)*time.Minute)
			f := evaluateBatch(d, events)
			if f.Triggered && (f.RiskScore < 0 || f.RiskScore >= 1) {
				t.Errorf("RiskScore = %v, want it in [0, 1)", f.RiskScore)
			}
		}(i)
	}
	wg.Wait()
}
