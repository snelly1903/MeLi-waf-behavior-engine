package tuning

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
)

func TestWinningAnomalyEval_PicksHigherRiskScore(t *testing.T) {
	evals := []anomaly.DebugEvaluation{
		{Scope: "ip:1", Triggered: true, RiskScore: 0.3},
		{Scope: "session:1", Triggered: true, RiskScore: 0.6},
	}
	got, ok := winningAnomalyEval(evals)
	if !ok || got.Scope != "session:1" {
		t.Errorf("winner = %+v, want session:1 (mayor RiskScore)", got)
	}
}

func TestWinningAnomalyEval_TieBreaksToSession(t *testing.T) {
	evals := []anomaly.DebugEvaluation{
		{Scope: "ip:1", Triggered: true, RiskScore: 0.5},
		{Scope: "session:1", Triggered: true, RiskScore: 0.5},
	}
	got, ok := winningAnomalyEval(evals)
	if !ok || got.Scope != "session:1" {
		t.Errorf("winner = %+v, want session:1 (empate exacto, gana sesión)", got)
	}
}

func TestWinningAnomalyEval_OnlyIPTriggered(t *testing.T) {
	evals := []anomaly.DebugEvaluation{
		{Scope: "ip:1", Triggered: true, RiskScore: 0.4},
		{Scope: "session:1", Triggered: false, RiskScore: 0},
	}
	got, ok := winningAnomalyEval(evals)
	if !ok || got.Scope != "ip:1" {
		t.Errorf("winner = %+v, want ip:1 (el único que disparó)", got)
	}
}

func TestWinningAnomalyEval_NoneTriggered_ReturnsFirstAsIs(t *testing.T) {
	evals := []anomaly.DebugEvaluation{
		{Scope: "ip:1", Triggered: false, CombinedScore: 0.2},
	}
	got, ok := winningAnomalyEval(evals)
	if !ok {
		t.Fatal("ok = false, want true (evals no está vacío)")
	}
	if got.Triggered {
		t.Error("Triggered = true, want false")
	}
}

func TestWinningAnomalyEval_Empty_ReturnsFalse(t *testing.T) {
	if _, ok := winningAnomalyEval(nil); ok {
		t.Error("ok = true, want false para evals vacío")
	}
}

// TestRunDiagnostics_ConsistentWithRunScenario corre ambos sobre el
// mismo escenario y candidate, y confirma que: (a) RunDiagnostics
// exige la misma cantidad de decisiones que eventos, (b) cuando la
// Decision real fue de statistical_anomaly (AttackVector=unknown y
// Triggered), el ganador de anomaly en el diagnóstico reproduce
// exactamente el mismo RiskScore que ConfidenceScore de esa Decision
// — la prueba de que la corrida paralela de diagnóstico ve
// EXACTAMENTE lo mismo que vería el detector real dentro de
// BehavioralDecider.
func TestRunDiagnostics_ConsistentWithRunScenario(t *testing.T) {
	scenario := datagen.BuildScenario(datagen.DefaultScenarioConfig(999, 0.10))
	resolver := datagen.NewSimulatedASNResolver()
	candidate := BaselineCandidate()

	runResult, err := RunScenario(scenario, candidate, resolver)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}

	diagnostics, err := RunDiagnostics(scenario, candidate, resolver, runResult.Decisions)
	if err != nil {
		t.Fatalf("RunDiagnostics: %v", err)
	}
	if len(diagnostics) != len(scenario.Events) {
		t.Fatalf("len(diagnostics) = %d, want %d", len(diagnostics), len(scenario.Events))
	}

	checked := 0
	for i, d := range diagnostics {
		positive := d.Decision.Action == decision.ActionChallenge || d.Decision.Action == decision.ActionBlock
		if d.Decision.AttackVector != "unknown" || !positive {
			continue
		}
		winner, ok := winningAnomalyEval(d.Anomaly)
		if !ok || !winner.Triggered {
			t.Errorf("evento %d: Decision fue unknown/positiva pero el diagnóstico de anomaly no coincide (winner=%+v)", i, winner)
			continue
		}
		if winner.RiskScore != d.Decision.ConfidenceScore {
			t.Errorf("evento %d: winner.RiskScore=%v != Decision.ConfidenceScore=%v", i, winner.RiskScore, d.Decision.ConfidenceScore)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("este escenario/seed no produjo ninguna Decision de statistical_anomaly triggered — nada que cruzar (no es un fallo, solo esta semilla no lo generó)")
	}
}
