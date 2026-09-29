package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// DetectorLayerRow es, para UN candidato (D0/D1), UN seed y UN ratio,
// la fila de la validación combinada final de la detector layer: las
// matrices de confusión Strict/Broad y sus métricas derivadas (nunca
// recalculadas a mano — vienen tal cual de RunResult.Eval, mismo
// criterio que el resto de internal/tuning), el recall
// detector-específico (request-level, sobre el gate propio, nunca la
// Decision final) de credential_stuffing y slow_scan, y la detección
// eventual/delay por vector — policy-level (Decision-based), ya
// vector-específica por diseño desde ComputeDetectionDelay (red
// simulada para credential_stuffing, sesión/IP para slow_scan).
type DetectorLayerRow struct {
	Candidate string
	Seed      uint64
	Ratio     int

	Strict eval.ConfusionMatrix
	Broad  eval.ConfusionMatrix

	PrecisionBroad eval.Ratio
	RecallBroad    eval.Ratio
	RecallStrict   eval.Ratio
	FPRBroad       eval.Ratio
	FNRBroad       eval.Ratio
	F1Broad        eval.Ratio

	CSRecallDetector       eval.Ratio
	SlowScanRecallDetector eval.Ratio

	DelayByVector []DelaySummary
}

// slowScanDetectorRecall es el equivalente de
// credentialStuffingDetectorRecall para slow_scan: la fracción de
// eventos etiquetados slow_scan cuyo SlowScan.Triggered fue true —
// request-level, sobre el gate propio, nunca la Decision final.
func slowScanDetectorRecall(diagnostics []EventDiagnostic) eval.Ratio {
	var total, triggered int
	for _, d := range diagnostics {
		if d.Label != groundtruth.LabelSlowScan {
			continue
		}
		total++
		if d.SlowScan.Triggered {
			triggered++
		}
	}
	return ratioOf(triggered, total)
}

// ComputeDetectorLayerRow arma la fila de un candidato/seed/ratio a
// partir de result (de RunScenario) y diagnostics (de RunDiagnostics,
// mismo scenario/candidate — puede ser nil si ratio=0 y no se
// corrieron diagnósticos, en cuyo caso CSRecallDetector y
// SlowScanRecallDetector quedan N/A, nunca en 0 disimulado).
func ComputeDetectorLayerRow(candidateName string, result RunResult, diagnostics []EventDiagnostic) DetectorLayerRow {
	row := DetectorLayerRow{
		Candidate: candidateName, Seed: result.Seed, Ratio: result.Ratio,
		Strict: result.Eval.Strict.Matrix,
		Broad:  result.Eval.Broad.Matrix,

		PrecisionBroad: result.Eval.Broad.Metrics.Precision,
		RecallBroad:    result.Eval.Broad.Metrics.Recall,
		RecallStrict:   result.Eval.Strict.Metrics.Recall,
		FPRBroad:       result.Eval.Broad.Metrics.FPR,
		FNRBroad:       result.Eval.Broad.Metrics.FNR,
		F1Broad:        result.Eval.Broad.Metrics.F1,

		DelayByVector: result.DelaySummary,
	}
	if diagnostics != nil {
		row.CSRecallDetector = credentialStuffingDetectorRecall(diagnostics)
		row.SlowScanRecallDetector = slowScanDetectorRecall(diagnostics)
	}
	return row
}

func sumMatrix(ms []eval.ConfusionMatrix) eval.ConfusionMatrix {
	var m eval.ConfusionMatrix
	for _, x := range ms {
		m.TP += x.TP
		m.FP += x.FP
		m.FN += x.FN
		m.TN += x.TN
	}
	return m
}

// AggregateDetectorLayerRows agrupa varias filas del MISMO
// candidato/ratio (una por seed) sumando sus matrices de confusión
// CRUDAS (pooled, no promedio de ratios ya calculados — evita el
// sesgo de tratar 3 seeds de distinto tamaño como si pesaran igual) y
// recalculando Precision/Recall/FPR/FNR/F1 sobre esa matriz pooled.
// pooledDelays son los CampaignDelay crudos de los 3 seeds (de
// RunResult.Delay, no DelaySummary) para que DelayByVector salga de
// SummarizeDelay sobre el pool real de campañas, nunca de promediar
// promedios.
func AggregateDetectorLayerRows(rows []DetectorLayerRow, pooledDelays []CampaignDelay) DetectorLayerRow {
	if len(rows) == 0 {
		return DetectorLayerRow{}
	}
	agg := DetectorLayerRow{Candidate: rows[0].Candidate, Ratio: rows[0].Ratio}

	strictMatrices := make([]eval.ConfusionMatrix, len(rows))
	broadMatrices := make([]eval.ConfusionMatrix, len(rows))
	for i, r := range rows {
		strictMatrices[i] = r.Strict
		broadMatrices[i] = r.Broad
	}
	agg.Strict = sumMatrix(strictMatrices)
	agg.Broad = sumMatrix(broadMatrices)

	broadMetrics := agg.Broad.Metrics()
	agg.PrecisionBroad = broadMetrics.Precision
	agg.RecallBroad = broadMetrics.Recall
	agg.FPRBroad = broadMetrics.FPR
	agg.FNRBroad = broadMetrics.FNR
	agg.F1Broad = broadMetrics.F1
	agg.RecallStrict = agg.Strict.Metrics().Recall

	agg.CSRecallDetector = meanRatio(extract(rows, func(r DetectorLayerRow) eval.Ratio { return r.CSRecallDetector }))
	agg.SlowScanRecallDetector = meanRatio(extract(rows, func(r DetectorLayerRow) eval.Ratio { return r.SlowScanRecallDetector }))

	agg.DelayByVector = SummarizeDelay(pooledDelays)

	return agg
}

// SumMitigationAttribution suma, campo a campo, varios
// MitigationAttribution del MISMO vector (uno por seed) — conteos
// enteros, nunca ratios, así que sumar es exacto, sin ningún sesgo de
// tamaño de seed.
func SumMitigationAttribution(items []MitigationAttribution) MitigationAttribution {
	if len(items) == 0 {
		return MitigationAttribution{}
	}
	sum := MitigationAttribution{Vector: items[0].Vector}
	for _, a := range items {
		sum.Mitigated += a.Mitigated
		sum.DetectorOnly += a.DetectorOnly
		sum.WithAnomalyAssist += a.WithAnomalyAssist
		sum.AnomalyOnly += a.AnomalyOnly
		sum.Neither += a.Neither
	}
	return sum
}

// DetectorLayerCandidateReport agrupa todo lo calculado para UN
// candidato (D0 o D1): filas por seed y ratio, agregadas por ratio
// (pooled entre los 3 seeds), atribución pooled por ratio, y la
// distribución de RiskScore pooled sobre TODO el tráfico (los 3
// seeds, los 3 ratios) — mismo criterio que cmd/diagnose.
type DetectorLayerCandidateReport struct {
	Candidate string

	RowsByRatio map[int][]DetectorLayerRow
	AggByRatio  map[int]DetectorLayerRow

	AttributionByRatio map[int][]MitigationAttribution

	RiskBuckets []RiskScoreBucket
}

var detectorLayerRatios = []int{0, 10, 30}

// renderDetectorLayerCandidateSection arma, para UN
// DetectorLayerCandidateReport, todas sus tablas (confusión, recall
// detector-específico, delay por vector, atribución, RiskScore) —
// extraído de RenderDetectorLayerComparison para poder reutilizarlo
// también en el reporte de holdout, que necesita más de dos reportes
// (baseline/final x tuning/holdout).
func renderDetectorLayerCandidateSection(rep DetectorLayerCandidateReport) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("# %s\n\n", rep.Candidate)

	w("## Matrices de confusión y métricas derivadas (por seed y agregado pooled entre seeds)\n\n")
	w("| Ratio | Seed | Strict TP/FP/FN/TN | Broad TP/FP/FN/TN | Precision | BroadRecall | StrictRecall | FPR | FNR | F1 |\n")
	w("|---|---|---|---|---|---|---|---|---|---|\n")
	for _, ratio := range detectorLayerRatios {
		for _, r := range rep.RowsByRatio[ratio] {
			w("| %d%% | %d | %d/%d/%d/%d | %d/%d/%d/%d | %s | %s | %s | %s | %s | %s |\n",
				r.Ratio, r.Seed,
				r.Strict.TP, r.Strict.FP, r.Strict.FN, r.Strict.TN,
				r.Broad.TP, r.Broad.FP, r.Broad.FN, r.Broad.TN,
				formatRatio(r.PrecisionBroad), formatRatio(r.RecallBroad), formatRatio(r.RecallStrict),
				formatRatio(r.FPRBroad), formatRatio(r.FNRBroad), formatRatio(r.F1Broad),
			)
		}
		a := rep.AggByRatio[ratio]
		w("| %d%% | **POOLED** | %d/%d/%d/%d | %d/%d/%d/%d | %s | %s | %s | %s | %s | %s |\n",
			a.Ratio,
			a.Strict.TP, a.Strict.FP, a.Strict.FN, a.Strict.TN,
			a.Broad.TP, a.Broad.FP, a.Broad.FN, a.Broad.TN,
			formatRatio(a.PrecisionBroad), formatRatio(a.RecallBroad), formatRatio(a.RecallStrict),
			formatRatio(a.FPRBroad), formatRatio(a.FNRBroad), formatRatio(a.F1Broad),
		)
	}
	w("\n")

	w("## Recall detector-específico (request-level, gate propio) — agregado por ratio\n\n")
	w("| Ratio | CS RecallDetector | SlowScan RecallDetector |\n")
	w("|---|---|---|\n")
	for _, ratio := range detectorLayerRatios {
		a := rep.AggByRatio[ratio]
		w("| %d%% | %s | %s |\n", ratio, formatRatio(a.CSRecallDetector), formatRatio(a.SlowScanRecallDetector))
	}
	w("\n")

	w("## Detección eventual de campaña y delay por vector (policy-level, Decision-based, pooled entre seeds)\n\n")
	w("| Ratio | Vector | Campañas | Detectadas | EventualDetectionRate | Requests medio a detección | Tiempo medio a detección |\n")
	w("|---|---|---|---|---|---|---|\n")
	for _, ratio := range detectorLayerRatios {
		for _, d := range rep.AggByRatio[ratio].DelayByVector {
			w("| %d%% | %s | %d | %d | %s | %s | %s |\n",
				ratio, d.Vector, d.Campaigns, d.DetectedCampaigns, formatRatio(d.EventualDetectionRate),
				formatOptionalFloat(d.MeanRequestsToDetection), formatOptionalDurationSeconds(d.MeanTimeToDetection),
			)
		}
	}
	w("\n")

	if len(rep.AttributionByRatio) > 0 {
		w("## Atribución (detector-only / anomaly-assist / anomaly-only / neither), pooled entre seeds\n\n")
		w("| Ratio | Vector | Mitigated | DetectorOnly | WithAnomalyAssist | AnomalyOnly | Neither |\n")
		w("|---|---|---|---|---|---|---|\n")
		for _, ratio := range []int{10, 30} {
			for _, a := range rep.AttributionByRatio[ratio] {
				w("| %d%% | %s | %d | %d | %d | %d | %d |\n", ratio, a.Vector, a.Mitigated, a.DetectorOnly, a.WithAnomalyAssist, a.AnomalyOnly, a.Neither)
			}
		}
		w("\n")
	}

	if len(rep.RiskBuckets) > 0 {
		w(RenderRiskScoreDistributions(rep.RiskBuckets))
	}

	return string(b)
}

// renderDetectorLayerSideBySide arma una tabla-resumen lado a lado
// entre DOS DetectorLayerCandidateReport (cualquiera, no solo D0/D1 —
// reutilizada por el reporte de holdout para comparar baseline vs.
// final y tuning vs. holdout), para las métricas más importantes en
// cada ratio.
func renderDetectorLayerSideBySide(title string, a, b DetectorLayerCandidateReport) string {
	var buf []byte
	w := func(format string, args ...any) { buf = append(buf, []byte(fmt.Sprintf(format, args...))...) }

	w("# %s\n\n", title)
	w("| Ratio | Métrica | %s | %s |\n", a.Candidate, b.Candidate)
	w("|---|---|---|---|\n")
	for _, ratio := range detectorLayerRatios {
		ra, rb := a.AggByRatio[ratio], b.AggByRatio[ratio]
		w("| %d%% | FPR (broad) | %s | %s |\n", ratio, formatRatio(ra.FPRBroad), formatRatio(rb.FPRBroad))
		w("| %d%% | Precision (broad) | %s | %s |\n", ratio, formatRatio(ra.PrecisionBroad), formatRatio(rb.PrecisionBroad))
		w("| %d%% | Recall (broad) | %s | %s |\n", ratio, formatRatio(ra.RecallBroad), formatRatio(rb.RecallBroad))
		w("| %d%% | Recall (strict/BLOCK) | %s | %s |\n", ratio, formatRatio(ra.RecallStrict), formatRatio(rb.RecallStrict))
		w("| %d%% | F1 (broad) | %s | %s |\n", ratio, formatRatio(ra.F1Broad), formatRatio(rb.F1Broad))
		w("| %d%% | CS RecallDetector | %s | %s |\n", ratio, formatRatio(ra.CSRecallDetector), formatRatio(rb.CSRecallDetector))
		w("| %d%% | SlowScan RecallDetector | %s | %s |\n", ratio, formatRatio(ra.SlowScanRecallDetector), formatRatio(rb.SlowScanRecallDetector))
	}
	w("\n")
	return string(buf)
}

// RenderDetectorLayerComparison arma el reporte en Markdown de la
// validación combinada final: una sección por candidato (D0, D1) con
// todas sus tablas, seguida de una tabla-resumen D0 vs. D1 lado a
// lado para las métricas más importantes en cada ratio.
func RenderDetectorLayerComparison(reports []DetectorLayerCandidateReport) string {
	var b []byte
	w := func(s string) { b = append(b, []byte(s)...) }

	for _, rep := range reports {
		w(renderDetectorLayerCandidateSection(rep))
	}
	if len(reports) == 2 {
		w(renderDetectorLayerSideBySide(fmt.Sprintf("%s vs. %s — resumen lado a lado", reports[0].Candidate, reports[1].Candidate), reports[0], reports[1]))
	}
	return string(b)
}
