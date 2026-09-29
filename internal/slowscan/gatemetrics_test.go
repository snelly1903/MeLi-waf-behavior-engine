package slowscan

import (
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
)

// TestEvaluateGateMetrics_MatchesEvaluate_WhenTriggered confirma que,
// para el mismo escenario que TestEvaluate_ClearSlowScan_Triggers,
// EvaluateGateMetrics reporta los mismos números crudos que ya
// terminan en el Finding real de Evaluate — necesario para confiar en
// el diagnóstico.
func TestEvaluateGateMetrics_MatchesEvaluate_WhenTriggered(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var lastFinding finding.Finding
	var lastGates []GateMetrics
	for i := 0; i < 20; i++ {
		e := ev(ip, time.Duration(i)*time.Minute, sensitivePath(i), 404, false)
		d.Observe(e)
		lastFinding = d.Evaluate(e)
		lastGates = d.EvaluateGateMetrics(e)
	}

	if !lastFinding.Triggered {
		t.Fatal("setup inválido: Evaluate no disparó")
	}
	if len(lastGates) != 1 {
		t.Fatalf("gates = %d, want 1 (sin sesión)", len(lastGates))
	}
	g := lastGates[0]
	if !g.Triggered {
		t.Error("GateMetrics.Triggered = false, want true (mismo tráfico que ya dispara en Evaluate)")
	}
	if g.TotalRequests != 20 {
		t.Errorf("TotalRequests = %d, want 20", g.TotalRequests)
	}
	if g.DistinctPaths != 20 {
		t.Errorf("DistinctPaths = %d, want 20 (una ruta sensible distinta por request)", g.DistinctPaths)
	}
	if g.NotFoundRatio != 1.0 {
		t.Errorf("NotFoundRatio = %v, want 1.0 (todos 404)", g.NotFoundRatio)
	}
	// Los mismos números crudos que Evaluate ya expone en
	// ContributingSignals — confirmando que no hay una segunda
	// fórmula divergente.
	for _, sig := range lastFinding.ContributingSignals {
		switch sig.Name {
		case "distinct_paths":
			if float64(g.DistinctPaths) != sig.Value {
				t.Errorf("DistinctPaths = %v, ContributingSignal = %v, want iguales", g.DistinctPaths, sig.Value)
			}
		case "route_entropy_normalized":
			if g.RouteEntropy != sig.Value {
				t.Errorf("RouteEntropy = %v, ContributingSignal = %v, want iguales", g.RouteEntropy, sig.Value)
			}
		case "novel_path_ratio":
			if g.NovelPathRatio != sig.Value {
				t.Errorf("NovelPathRatio = %v, ContributingSignal = %v, want iguales", g.NovelPathRatio, sig.Value)
			}
		}
	}
}

// TestEvaluateGateMetrics_ExposesRawNumbers_WhenNotTriggered es el
// punto central de este método: Evaluate descarta los cinco números
// del gate cuando no dispara (devuelve finding.Finding{}) —
// EvaluateGateMetrics los expone siempre, para poder ver cuál
// condición seguía sin cumplirse.
func TestEvaluateGateMetrics_ExposesRawNumbers_WhenNotTriggered(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)

	var lastGates []GateMetrics
	for i := 0; i < 20; i++ {
		e := ev(ip, time.Duration(i)*time.Minute, "/products", 200, true)
		d.Observe(e)
		lastGates = d.EvaluateGateMetrics(e)
	}

	if len(lastGates) != 1 {
		t.Fatalf("gates = %d, want 1", len(lastGates))
	}
	g := lastGates[0]
	if g.Triggered {
		t.Fatal("Triggered = true, want false — 20 requests a una sola ruta no es scanning")
	}
	if g.TotalRequests != 20 {
		t.Errorf("TotalRequests = %d, want 20 (expuesto aunque no disparó)", g.TotalRequests)
	}
	if g.DistinctPaths != 1 {
		t.Errorf("DistinctPaths = %d, want 1", g.DistinctPaths)
	}
	if g.NotFoundRatio != 0 {
		t.Errorf("NotFoundRatio = %v, want 0 (todos 200)", g.NotFoundRatio)
	}
}

// TestEvaluateGateMetrics_NeverMutatesState confirma que llamar
// EvaluateGateMetrics no tiene ningún efecto secundario — a
// diferencia de anomaly.Detector.EvaluateDebug, este método es una
// lectura pura, así que se puede llamar cualquier cantidad de veces
// para el mismo evento sin cambiar ningún resultado futuro.
func TestEvaluateGateMetrics_NeverMutatesState(t *testing.T) {
	d := newTestDetector(t, baseConfig())
	ip := ipFor(0)
	e := ev(ip, 0, "/a", 200, true)
	d.Observe(e)

	first := d.EvaluateGateMetrics(e)
	second := d.EvaluateGateMetrics(e)
	third := d.Evaluate(e) // Evaluate después de EvaluateGateMetrics, sin cambios de comportamiento

	if first[0] != second[0] {
		t.Errorf("dos llamadas seguidas de EvaluateGateMetrics dieron resultados distintos: %+v vs %+v", first[0], second[0])
	}
	if third.Triggered {
		t.Error("Evaluate disparó después de llamar EvaluateGateMetrics dos veces — no debería haber ningún efecto secundario")
	}
}
