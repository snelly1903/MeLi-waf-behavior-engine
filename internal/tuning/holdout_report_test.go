// Prueba la estabilidad por capa de detector entre seeds.
package tuning

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
)

func TestComputeDetectorLayerStability_RangeAcrossSeeds(t *testing.T) {
	rows := []DetectorLayerRow{
		{Candidate: "Final", Ratio: 30, RecallBroad: eval.Ratio{Value: 0.80, Defined: true}, CSRecallDetector: eval.Ratio{Value: 0.90, Defined: true}},
		{Candidate: "Final", Ratio: 30, RecallBroad: eval.Ratio{Value: 0.60, Defined: true}, CSRecallDetector: eval.Ratio{Defined: false}},
		{Candidate: "Final", Ratio: 30, RecallBroad: eval.Ratio{Value: 0.70, Defined: true}, CSRecallDetector: eval.Ratio{Value: 0.70, Defined: true}},
	}
	s := ComputeDetectorLayerStability(rows)

	if diff := s.BroadRecallRange - 0.20; diff > 0.0001 || diff < -0.0001 {
		t.Errorf("BroadRecallRange = %.4f, want 0.20 (0.80-0.60)", s.BroadRecallRange)
	}
	if diff := s.CSRecallDetectorRange - 0.20; diff > 0.0001 || diff < -0.0001 {
		t.Errorf("CSRecallDetectorRange = %.4f, want 0.20 (0.90-0.70, ignorando el N/A)", s.CSRecallDetectorRange)
	}
}

func TestComputeDetectorLayerStability_EmptyRows_ReturnsZeroValue(t *testing.T) {
	s := ComputeDetectorLayerStability(nil)
	if s != (DetectorLayerStability{}) {
		t.Errorf("s = %+v, want zero value", s)
	}
}
