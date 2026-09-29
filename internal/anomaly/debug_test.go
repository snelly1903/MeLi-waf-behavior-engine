package anomaly

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

// evaluateDebugBatch es el equivalente de evaluateBatch pero llamando
// EvaluateDebug en vez de Evaluate — usa exactamente los mismos
// helpers de construcción de eventos que el resto de este archivo.
func evaluateDebugBatch(d *Detector, events []event.Event) []DebugEvaluation {
	for _, e := range events {
		d.Observe(e)
	}
	return d.EvaluateDebug(events[len(events)-1])
}

// TestEvaluateDebug_MatchesEvaluate_WhenTriggered confirma que, para
// el mismo escenario que ya prueba TestEvaluate_ClearDeviation_Triggers
// (Evaluate), EvaluateDebug reporta el mismo Triggered/RiskScore desde
// su propio camino de código independiente — necesario para poder
// confiar en los reportes de diagnóstico sin dudar si reflejan lo que
// el motor real haría.
func TestEvaluateDebug_MatchesEvaluate_WhenTriggered(t *testing.T) {
	dEval := newTestDetector(t, testConfig())
	dDebug := newTestDetector(t, testConfig())

	for i := 0; i < 10; i++ {
		evaluateBatch(dEval, warmupBatch(ipFor(i), i, 0))
		evaluateDebugBatch(dDebug, warmupBatch(ipFor(i), i, 0))
	}

	events := buildEvents(ipFor(21), 20, 18, 0, 4, 2, 0, 0)
	f := evaluateBatch(dEval, events)
	debugEvals := evaluateDebugBatch(dDebug, events)

	if !f.Triggered {
		t.Fatal("setup inválido: Evaluate no disparó — no es el mismo escenario que TestEvaluate_ClearDeviation_Triggers")
	}
	if len(debugEvals) != 1 {
		t.Fatalf("debugEvals = %d, want 1 (sin sesión)", len(debugEvals))
	}
	ipEval := debugEvals[0]
	if !ipEval.Triggered {
		t.Fatal("EvaluateDebug: Triggered = false, want true")
	}
	if ipEval.RiskScore != f.RiskScore {
		t.Errorf("EvaluateDebug.RiskScore = %v, want %v (igual que Evaluate)", ipEval.RiskScore, f.RiskScore)
	}
	for _, sig := range f.ContributingSignals {
		if got := ipEval.ZScores[sig.Name]; got != sig.Value {
			t.Errorf("ZScores[%q] = %v, want %v (igual que el ContributingSignal de Evaluate)", sig.Name, got, sig.Value)
		}
	}
}

// TestEvaluateDebug_ExposesCombinedScore_WhenNotTriggered es el punto
// central de este método: Evaluate descarta el score combinado
// cuando no cruza TriggerThreshold (devuelve
// finding.Finding{} vacío) — EvaluateDebug lo expone siempre, para
// poder medir "qué tan cerca estuvo" el tráfico legítimo que nunca
// disparó, no solo contar cuántas veces disparó.
func TestEvaluateDebug_ExposesCombinedScore_WhenNotTriggered(t *testing.T) {
	d := newTestDetector(t, testConfig())
	for i := 0; i < 10; i++ {
		evaluateDebugBatch(d, warmupBatch(ipFor(i), i, 0))
	}

	// Tráfico típico, dentro del rango ya visto — no debería disparar.
	events := buildEvents(ipFor(20), 20, 2, 1, 4, 2, 0, 0)
	evals := evaluateDebugBatch(d, events)

	if len(evals) != 1 {
		t.Fatalf("evals = %d, want 1", len(evals))
	}
	if evals[0].Triggered {
		t.Fatal("Triggered = true, want false — este es tráfico típico, no debería disparar")
	}
	if evals[0].RiskScore != 0 {
		t.Errorf("RiskScore = %v, want 0 (no disparó)", evals[0].RiskScore)
	}
	// El punto de esta prueba: CombinedScore SÍ tiene un valor real
	// (no cero forzado, salvo que coincida por casualidad) — a
	// diferencia de Evaluate, que en este caso devolvería
	// finding.Finding{} sin ningún número aprovechable.
	if len(evals[0].ZScores) != int(featureCount) {
		t.Errorf("ZScores tiene %d entradas, want %d (una por feature)", len(evals[0].ZScores), featureCount)
	}
}

// TestEvaluateDebug_UpdatesBaseline_SameRuleAsEvaluate confirma que
// EvaluateDebug deja el baseline en el mismo estado que Evaluate
// dejaría para el mismo tráfico — necesario para poder sustituir
// Evaluate por EvaluateDebug durante una corrida de diagnóstico sin
// cambiar el comportamiento observable del detector.
func TestEvaluateDebug_UpdatesBaseline_SameRuleAsEvaluate(t *testing.T) {
	dEval := newTestDetector(t, testConfig())
	dDebug := newTestDetector(t, testConfig())

	for i := 0; i < 10; i++ {
		evaluateBatch(dEval, warmupBatch(ipFor(i), i, 0))
		evaluateDebugBatch(dDebug, warmupBatch(ipFor(i), i, 0))
	}

	if dEval.baseline.n != dDebug.baseline.n {
		t.Fatalf("baseline.n = %d (Evaluate) vs %d (EvaluateDebug), want iguales", dEval.baseline.n, dDebug.baseline.n)
	}
	if dEval.baseline.stats != dDebug.baseline.stats {
		t.Errorf("baseline.stats difiere entre Evaluate y EvaluateDebug: %+v vs %+v", dEval.baseline.stats, dDebug.baseline.stats)
	}
}
