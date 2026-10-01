// Construye el reporte agregado de evaluación sobre los escenarios de holdout.
package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
)

type DetectorLayerStability struct {
	Candidate string
	Ratio     int

	BroadRecallRange            float64
	StrictRecallRange           float64
	FPRBroadRange               float64
	CSRecallDetectorRange       float64
	SlowScanRecallDetectorRange float64
}

func ComputeDetectorLayerStability(rows []DetectorLayerRow) DetectorLayerStability {
	if len(rows) == 0 {
		return DetectorLayerStability{}
	}
	s := DetectorLayerStability{Candidate: rows[0].Candidate, Ratio: rows[0].Ratio}

	definedValues := func(f func(DetectorLayerRow) eval.Ratio) []float64 {
		var vs []float64
		for _, r := range rows {
			if v := f(r); v.Defined {
				vs = append(vs, v.Value)
			}
		}
		return vs
	}

	s.BroadRecallRange = rangeOf(definedValues(func(r DetectorLayerRow) eval.Ratio { return r.RecallBroad }))
	s.StrictRecallRange = rangeOf(definedValues(func(r DetectorLayerRow) eval.Ratio { return r.RecallStrict }))
	s.FPRBroadRange = rangeOf(definedValues(func(r DetectorLayerRow) eval.Ratio { return r.FPRBroad }))
	s.CSRecallDetectorRange = rangeOf(definedValues(func(r DetectorLayerRow) eval.Ratio { return r.CSRecallDetector }))
	s.SlowScanRecallDetectorRange = rangeOf(definedValues(func(r DetectorLayerRow) eval.Ratio { return r.SlowScanRecallDetector }))

	return s
}

func renderStabilityTable(candidateName string, rowsByRatio map[int][]DetectorLayerRow) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("### Estabilidad entre seeds — %s\n\n", candidateName)
	w("| Ratio | BroadRecall Range | StrictRecall Range | FPRBroad Range | CS RecallDetector Range | SlowScan RecallDetector Range |\n")
	w("|---|---|---|---|---|---|\n")
	for _, ratio := range detectorLayerRatios {
		s := ComputeDetectorLayerStability(rowsByRatio[ratio])
		w("| %d%% | %.4f | %.4f | %.4f | %.4f | %.4f |\n", ratio, s.BroadRecallRange, s.StrictRecallRange, s.FPRBroadRange, s.CSRecallDetectorRange, s.SlowScanRecallDetectorRange)
	}
	w("\n")
	return string(b)
}

func renderActionDistributionTable(candidateName string, actionsByRatio map[int]ActionDistribution) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("### Action distribution — %s (pooled entre seeds)\n\n", candidateName)
	w("| Ratio | LegitAllow | LegitChallenge | LegitBlock | MaliciousAllow | MaliciousChallenge | MaliciousBlock | FalseChallengeRate | FalseBlockRate |\n")
	w("|---|---|---|---|---|---|---|---|---|\n")
	for _, ratio := range detectorLayerRatios {
		a := actionsByRatio[ratio]
		w("| %d%% | %d | %d | %d | %d | %d | %d | %s | %s |\n",
			ratio, a.LegitAllow, a.LegitChallenge, a.LegitBlock,
			a.MaliciousAllow, a.MaliciousChallenge, a.MaliciousBlock,
			formatRatio(a.FalseChallengeRate()), formatRatio(a.FalseBlockRate()),
		)
	}
	w("\n")
	return string(b)
}

type HoldoutDatasetReport struct {
	Label string

	Baseline DetectorLayerCandidateReport
	Final    DetectorLayerCandidateReport

	BaselineActions map[int]ActionDistribution
	FinalActions    map[int]ActionDistribution
}

func RenderHoldoutReport(tuningReport, holdoutReport HoldoutDatasetReport) string {
	var b []byte
	w := func(s string) { b = append(b, []byte(s)...) }

	for _, ds := range []HoldoutDatasetReport{tuningReport, holdoutReport} {
		w(fmt.Sprintf("# ===== Dataset: %s =====\n\n", ds.Label))
		w(renderDetectorLayerCandidateSection(ds.Baseline))
		w(renderDetectorLayerCandidateSection(ds.Final))
		w(renderDetectorLayerSideBySide(fmt.Sprintf("Baseline vs. Final — %s", ds.Label), ds.Baseline, ds.Final))
		w(renderActionDistributionTable(ds.Baseline.Candidate, ds.BaselineActions))
		w(renderActionDistributionTable(ds.Final.Candidate, ds.FinalActions))
		w(renderStabilityTable(ds.Baseline.Candidate, ds.Baseline.RowsByRatio))
		w(renderStabilityTable(ds.Final.Candidate, ds.Final.RowsByRatio))
	}

	w("# ===== Generalización: tuning vs. holdout (candidato Final) =====\n\n")
	w(renderDetectorLayerSideBySide("Final — tuning vs. holdout", tuningReport.Final, holdoutReport.Final))
	w("# ===== Generalización: tuning vs. holdout (candidato Baseline) =====\n\n")
	w(renderDetectorLayerSideBySide("Baseline — tuning vs. holdout", tuningReport.Baseline, holdoutReport.Baseline))

	return string(b)
}

func rangeOf(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	min, max := values[0], values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return max - min
}
