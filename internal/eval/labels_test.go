package eval

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// testdata/eval/labels_sample.jsonl contiene, a propósito:
//
//	r-1  legit                  (válida)
//	r-2  credential_stuffing    (válida, primera aparición)
//	r-3  slow_scan              (válida)
//	r-2  credential_stuffing    (duplicada — mismo request_id de nuevo)
//	r-4  unknown_attack         (etiqueta desconocida)
func TestLoadLabels_SampleFile(t *testing.T) {
	result, err := LoadLabels("../../testdata/eval/labels_sample.jsonl")
	if err != nil {
		t.Fatalf("LoadLabels: %v", err)
	}

	wantLabels := map[string]groundtruth.Label{
		"r-1": groundtruth.LabelLegit,
		"r-2": groundtruth.LabelCredentialStuffing,
		"r-3": groundtruth.LabelSlowScan,
	}
	if len(result.Labels) != len(wantLabels) {
		t.Fatalf("Labels has %d entries, want %d: %v", len(result.Labels), len(wantLabels), result.Labels)
	}
	for id, want := range wantLabels {
		if got := result.Labels[id]; got != want {
			t.Errorf("Labels[%q] = %q, want %q", id, got, want)
		}
	}

	if len(result.DuplicateIDs) != 1 || result.DuplicateIDs[0] != "r-2" {
		t.Errorf("DuplicateIDs = %v, want [r-2]", result.DuplicateIDs)
	}
	if len(result.UnknownLabelIDs) != 1 || result.UnknownLabelIDs[0] != "r-4" {
		t.Errorf("UnknownLabelIDs = %v, want [r-4]", result.UnknownLabelIDs)
	}

	// La etiqueta desconocida nunca debe terminar en el mapa utilizable.
	if _, exists := result.Labels["r-4"]; exists {
		t.Error("r-4 (unknown_attack) must not be present in Labels")
	}
}

func TestLoadLabels_MissingFile(t *testing.T) {
	if _, err := LoadLabels("../../testdata/eval/does-not-exist.jsonl"); err == nil {
		t.Fatal("LoadLabels on a missing file returned nil error")
	}
}
