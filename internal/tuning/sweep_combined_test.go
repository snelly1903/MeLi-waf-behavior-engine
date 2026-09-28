package tuning

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
)

// TestComputeCombinedSweepRow_PullsFromRealRunResult confirma que
// ComputeCombinedSweepRow no recalcula nada por su cuenta: los
// valores que reporta coinciden exactamente con los que ya trae
// RunResult.Eval para el mismo candidato/seed/ratio.
func TestComputeCombinedSweepRow_PullsFromRealRunResult(t *testing.T) {
	resolver := datagen.NewSimulatedASNResolver()
	candidate := BaselineCandidate()

	resultsByRatio := make(map[int]RunResult)
	diagnosticsByRatio := make(map[int][]EventDiagnostic)
	for _, ratio := range []int{0, 10, 30} {
		scenario := datagen.BuildScenario(datagen.DefaultScenarioConfig(555, float64(ratio)/100))
		result, err := RunScenario(scenario, candidate, resolver)
		if err != nil {
			t.Fatalf("RunScenario ratio=%d: %v", ratio, err)
		}
		resultsByRatio[ratio] = result

		if ratio != 0 {
			diagnostics, err := RunDiagnostics(scenario, candidate, resolver, result.Decisions)
			if err != nil {
				t.Fatalf("RunDiagnostics ratio=%d: %v", ratio, err)
			}
			diagnosticsByRatio[ratio] = diagnostics
		}
	}

	row := ComputeCombinedSweepRow("C0-baseline", 555, resultsByRatio, diagnosticsByRatio)

	if row.FPAt0 != resultsByRatio[0].Eval.Broad.Matrix.FP {
		t.Errorf("FPAt0 = %d, want %d", row.FPAt0, resultsByRatio[0].Eval.Broad.Matrix.FP)
	}
	if row.BroadRecallAt30 != resultsByRatio[30].Eval.Broad.Metrics.Recall {
		t.Errorf("BroadRecallAt30 = %+v, want %+v", row.BroadRecallAt30, resultsByRatio[30].Eval.Broad.Metrics.Recall)
	}
	if row.AttributionSSAt30.Mitigated == 0 {
		t.Error("AttributionSSAt30.Mitigated = 0, want > 0 (a 30% siempre hay campañas de slow_scan mitigadas)")
	}
	// DetectorOnly + WithAnomalyAssist + AnomalyOnly + Neither tiene
	// que sumar exactamente Mitigated -- ninguna categoría se pierde.
	a := row.AttributionSSAt30
	if a.DetectorOnly+a.WithAnomalyAssist+a.AnomalyOnly+a.Neither != a.Mitigated {
		t.Errorf("las categorías de atribución no suman Mitigated: %+v", a)
	}
}

func TestAggregateCombinedSweepRows_SumsAttributionAcrossSeeds(t *testing.T) {
	rows := []CombinedSweepRow{
		{Candidate: "C0", Seed: 101, AttributionSSAt30: MitigationAttribution{Mitigated: 5, DetectorOnly: 3, WithAnomalyAssist: 2}},
		{Candidate: "C0", Seed: 102, AttributionSSAt30: MitigationAttribution{Mitigated: 7, DetectorOnly: 4, WithAnomalyAssist: 3}},
	}
	agg := AggregateCombinedSweepRows(rows)
	if agg.AttributionSSAt30.Mitigated != 12 {
		t.Errorf("Mitigated = %d, want 12 (suma entre seeds)", agg.AttributionSSAt30.Mitigated)
	}
}
