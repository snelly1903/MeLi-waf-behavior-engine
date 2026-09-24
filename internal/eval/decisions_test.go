package eval

import (
	"os"
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
)

// testdata/eval/decisions_sample.jsonl contiene, a propósito:
//
//	r-d1  ALLOW válida
//	r-d2  BLOCK válida (con explanation y contributing_signals)
//	línea 3  JSON corrupto
//	línea 4  JSON válido pero request_id vacío
//	r-d5  BLOCK sin explanation ni contributing_signals (inválida para decision.Validate)
func TestLoadDecisions_SampleFile(t *testing.T) {
	result, err := LoadDecisions("../../testdata/eval/decisions_sample.jsonl")
	if err != nil {
		t.Fatalf("LoadDecisions: %v", err)
	}

	if len(result.Decisions) != 2 {
		t.Fatalf("Decisions has %d entries, want 2: %+v", len(result.Decisions), result.Decisions)
	}
	if result.Decisions[0].RequestID != "r-d1" || result.Decisions[0].Action != decision.ActionAllow {
		t.Errorf("Decisions[0] = %+v, want r-d1 ALLOW", result.Decisions[0])
	}
	if result.Decisions[1].RequestID != "r-d2" || result.Decisions[1].Action != decision.ActionBlock {
		t.Errorf("Decisions[1] = %+v, want r-d2 BLOCK", result.Decisions[1])
	}

	if len(result.InvalidIDs) != 1 || result.InvalidIDs[0] != "r-d5" {
		t.Errorf("InvalidIDs = %v, want [r-d5]", result.InvalidIDs)
	}

	// Línea 3 (JSON corrupto) y línea 4 (request_id vacío) van a
	// CorruptLines, en ese orden.
	if len(result.CorruptLines) != 2 || result.CorruptLines[0] != 3 || result.CorruptLines[1] != 4 {
		t.Errorf("CorruptLines = %v, want [3 4]", result.CorruptLines)
	}
}

func TestLoadDecisions_MissingFile(t *testing.T) {
	if _, err := LoadDecisions("../../testdata/eval/does-not-exist.jsonl"); err == nil {
		t.Fatal("LoadDecisions on a missing file returned nil error")
	}
}

func TestLoadDecisions_EmptyLinesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/decisions.jsonl"
	content := "\n{\"request_id\":\"r-1\",\"timestamp\":\"2026-09-24T10:00:00Z\",\"entity_id\":\"ip:203.0.113.1\",\"action\":\"ALLOW\",\"confidence_score\":0.1,\"attack_vector\":\"unknown\"}\n\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	result, err := LoadDecisions(path)
	if err != nil {
		t.Fatalf("LoadDecisions: %v", err)
	}
	if len(result.Decisions) != 1 {
		t.Fatalf("Decisions has %d entries, want 1: %+v", len(result.Decisions), result.Decisions)
	}
	if len(result.CorruptLines) != 0 {
		t.Errorf("CorruptLines = %v, want none (blank lines must not count as corrupt)", result.CorruptLines)
	}
}
