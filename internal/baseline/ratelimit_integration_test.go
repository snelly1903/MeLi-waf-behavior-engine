// Verifica que las decisiones de la línea base se puedan evaluar con el paquete eval.
package baseline

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
)

func TestDetect_IntegratesWithEval(t *testing.T) {
	cfg := datagen.DefaultScenarioConfig(999, 0.10)
	scenario := datagen.BuildScenario(cfg)

	dir := t.TempDir()
	if err := datagen.WriteScenario(dir, scenario); err != nil {
		t.Fatalf("WriteScenario: %v", err)
	}

	events, err := LoadEvents(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) != len(scenario.Events) {
		t.Fatalf("LoadEvents returned %d events, want %d", len(events), len(scenario.Events))
	}

	decisions, err := Detect(events, Config{MaxRequests: 100, Window: time.Minute, Mode: CountModeAll})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(decisions) != len(events) {
		t.Fatalf("Detect returned %d decisions, want %d (one per event)", len(decisions), len(events))
	}

	decisionsPath := filepath.Join(dir, "decisions.jsonl")
	if err := WriteDecisions(decisionsPath, decisions); err != nil {
		t.Fatalf("WriteDecisions: %v", err)
	}

	labelsResult, err := eval.LoadLabels(filepath.Join(dir, "labels.jsonl"))
	if err != nil {
		t.Fatalf("LoadLabels: %v", err)
	}
	decisionsResult, err := eval.LoadDecisions(decisionsPath)
	if err != nil {
		t.Fatalf("eval.LoadDecisions: %v", err)
	}

	result := eval.EvaluateDecisions(labelsResult, decisionsResult)

	if !result.Issues.Clean() {
		t.Fatalf("Issues not clean on a self-consistent dataset: %+v", result.Issues)
	}
	if result.TotalJoined != len(scenario.Events) {
		t.Fatalf("TotalJoined = %d, want %d", result.TotalJoined, len(scenario.Events))
	}

	t.Logf("baseline (mode=all, max-requests=100, window=60s) sobre %d eventos (10%% malicioso objetivo): estricta=%+v amplia=%+v",
		result.TotalJoined, result.Strict.Matrix, result.Broad.Matrix)
}
