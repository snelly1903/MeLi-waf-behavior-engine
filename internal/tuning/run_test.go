// Prueba la reproducibilidad y las métricas de RunScenario.
package tuning

import (
	"reflect"
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
)

func TestRunScenario_Reproducible_SameSeedSameResult(t *testing.T) {
	cfg := datagen.DefaultScenarioConfig(555, 0.10)
	scenario1 := datagen.BuildScenario(cfg)
	scenario2 := datagen.BuildScenario(cfg)

	resolver := datagen.NewSimulatedASNResolver()

	got1, err := RunScenario(scenario1, BaselineCandidate(), resolver)
	if err != nil {
		t.Fatalf("RunScenario (1ra corrida): %v", err)
	}
	got2, err := RunScenario(scenario2, BaselineCandidate(), resolver)
	if err != nil {
		t.Fatalf("RunScenario (2da corrida): %v", err)
	}

	if len(got1.Decisions) != len(got2.Decisions) {
		t.Fatalf("len(Decisions) = %d vs %d", len(got1.Decisions), len(got2.Decisions))
	}
	for i := range got1.Decisions {
		d1, d2 := got1.Decisions[i], got2.Decisions[i]
		if d1.RequestID != d2.RequestID || d1.Action != d2.Action || d1.AttackVector != d2.AttackVector || d1.EntityID != d2.EntityID {
			t.Fatalf("decision %d no fue reproducible: %+v vs %+v", i, d1, d2)
		}
	}

	if !reflect.DeepEqual(got1.Eval, got2.Eval) {
		t.Error("Eval no fue reproducible entre dos corridas con la misma semilla")
	}
	if !reflect.DeepEqual(got1.Delay, got2.Delay) {
		t.Error("Delay no fue reproducible entre dos corridas con la misma semilla")
	}
}

func TestRunScenario_DifferentSeed_TypicallyDiffersInVolume(t *testing.T) {
	scenario1 := datagen.BuildScenario(datagen.DefaultScenarioConfig(101, 0.10))
	scenario2 := datagen.BuildScenario(datagen.DefaultScenarioConfig(102, 0.10))

	if reflect.DeepEqual(scenario1.Events, scenario2.Events) {
		t.Error("dos semillas distintas produjeron exactamente los mismos eventos — la semilla no está siendo usada")
	}
}

func TestRunScenario_ZeroPercentMalicious_RecallIsNA(t *testing.T) {
	scenario := datagen.BuildScenario(datagen.DefaultScenarioConfig(42, 0))
	resolver := datagen.NewSimulatedASNResolver()

	got, err := RunScenario(scenario, BaselineCandidate(), resolver)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}

	if got.Eval.Strict.Metrics.Recall.Defined {
		t.Error("Strict.Recall.Defined = true, want false (0% malicious: no hay positivos reales)")
	}
	if got.Eval.Broad.Metrics.Recall.Defined {
		t.Error("Broad.Recall.Defined = true, want false")
	}
	for _, v := range got.Eval.ByAttackVector {
		if v.Recall.Defined {
			t.Errorf("recall de %s .Defined = true, want false (0%% malicious)", v.Vector)
		}
	}
	if !got.Eval.Strict.Metrics.FPR.Defined {
		t.Error("Strict.FPR.Defined = false, want true (siempre hay negativos reales en un escenario de 0%)")
	}

	if len(got.Delay) != 0 {
		t.Errorf("Delay = %d campañas, want 0 (0%% malicious)", len(got.Delay))
	}
}

func TestRunScenario_StrictAndBroad_AreConsistentlyComputed(t *testing.T) {
	scenario := datagen.BuildScenario(datagen.DefaultScenarioConfig(777, 0.30))
	resolver := datagen.NewSimulatedASNResolver()

	got, err := RunScenario(scenario, BaselineCandidate(), resolver)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}

	if got.Eval.Strict.Matrix.Total() != got.Eval.Broad.Matrix.Total() {
		t.Errorf("Strict.Total()=%d != Broad.Total()=%d", got.Eval.Strict.Matrix.Total(), got.Eval.Broad.Matrix.Total())
	}
	if got.Eval.Broad.Matrix.TP < got.Eval.Strict.Matrix.TP {
		t.Errorf("Broad.TP=%d < Strict.TP=%d, want Broad >= Strict (CHALLENGE nunca puede restar TP)", got.Eval.Broad.Matrix.TP, got.Eval.Strict.Matrix.TP)
	}
	if !got.Eval.Issues.Clean() {
		t.Errorf("Issues no está limpio en una corrida sin ningún problema de integridad: %+v", got.Eval.Issues)
	}
}
