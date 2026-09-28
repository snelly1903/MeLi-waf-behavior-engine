package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// CombinedSweepRow es, para UN candidato combinado (slow_scan +
// statistical_anomaly a la vez) y UN seed, todas las métricas pedidas
// para comparar C0-C3 (tarea 1.9). Reutiliza directamente lo que ya
// calcula RunScenario (Eval, DelaySummary) — nunca vuelve a correr
// ninguna evaluación por su cuenta — más ComputeMitigationAttribution
// sobre los diagnósticos de 10%/30%.
type CombinedSweepRow struct {
	Candidate string
	Seed      uint64

	FPAt0  int
	FPRAt0 eval.Ratio

	BroadRecallAt10    eval.Ratio
	BroadRecallAt30    eval.Ratio
	StrictRecallAt10   eval.Ratio // secundaria
	StrictRecallAt30   eval.Ratio // secundaria
	BroadPrecisionAt10 eval.Ratio
	BroadPrecisionAt30 eval.Ratio
	BroadF1At10        eval.Ratio
	BroadF1At30        eval.Ratio

	RecallCSAt10 eval.Ratio
	RecallCSAt30 eval.Ratio
	RecallSSAt10 eval.Ratio
	RecallSSAt30 eval.Ratio

	// EventualDetection*/MeanRequestsToDetection* vienen de
	// RunResult.DelaySummary — nivel POLICY (cualquier detector),
	// coherente con el resto de esta tarea.
	EventualDetectionCSAt10 eval.Ratio
	EventualDetectionCSAt30 eval.Ratio
	EventualDetectionSSAt10 eval.Ratio
	EventualDetectionSSAt30 eval.Ratio

	MeanRequestsToDetectionCSAt10 OptionalFloat
	MeanRequestsToDetectionCSAt30 OptionalFloat
	MeanRequestsToDetectionSSAt10 OptionalFloat
	MeanRequestsToDetectionSSAt30 OptionalFloat

	AttributionCSAt10 MitigationAttribution
	AttributionCSAt30 MitigationAttribution
	AttributionSSAt10 MitigationAttribution
	AttributionSSAt30 MitigationAttribution
}

func attributionFor(attrs []MitigationAttribution, vector groundtruth.Label) MitigationAttribution {
	for _, a := range attrs {
		if a.Vector == vector {
			return a
		}
	}
	return MitigationAttribution{Vector: vector}
}

// ComputeCombinedSweepRow arma la fila de un candidato/seed.
// resultsByRatio: un RunResult por ratio (0/10/30). diagnosticsByRatio:
// el detalle crudo por evento en 10% y 30% (0% no hace falta acá,
// FP/FPR ya salen de resultsByRatio[0].Eval).
func ComputeCombinedSweepRow(candidateName string, seed uint64, resultsByRatio map[int]RunResult, diagnosticsByRatio map[int][]EventDiagnostic) CombinedSweepRow {
	row := CombinedSweepRow{Candidate: candidateName, Seed: seed}

	if r, ok := resultsByRatio[0]; ok {
		row.FPAt0 = r.Eval.Broad.Matrix.FP
		row.FPRAt0 = r.Eval.Broad.Metrics.FPR
	}
	if r, ok := resultsByRatio[10]; ok {
		row.BroadRecallAt10 = r.Eval.Broad.Metrics.Recall
		row.StrictRecallAt10 = r.Eval.Strict.Metrics.Recall
		row.BroadPrecisionAt10 = r.Eval.Broad.Metrics.Precision
		row.BroadF1At10 = r.Eval.Broad.Metrics.F1
		row.RecallCSAt10 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelCredentialStuffing)
		row.RecallSSAt10 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelSlowScan)

		csDelay := delaySummaryFor(r.DelaySummary, groundtruth.LabelCredentialStuffing)
		ssDelay := delaySummaryFor(r.DelaySummary, groundtruth.LabelSlowScan)
		row.EventualDetectionCSAt10 = csDelay.EventualDetectionRate
		row.EventualDetectionSSAt10 = ssDelay.EventualDetectionRate
		row.MeanRequestsToDetectionCSAt10 = csDelay.MeanRequestsToDetection
		row.MeanRequestsToDetectionSSAt10 = ssDelay.MeanRequestsToDetection
	}
	if r, ok := resultsByRatio[30]; ok {
		row.BroadRecallAt30 = r.Eval.Broad.Metrics.Recall
		row.StrictRecallAt30 = r.Eval.Strict.Metrics.Recall
		row.BroadPrecisionAt30 = r.Eval.Broad.Metrics.Precision
		row.BroadF1At30 = r.Eval.Broad.Metrics.F1
		row.RecallCSAt30 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelCredentialStuffing)
		row.RecallSSAt30 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelSlowScan)

		csDelay := delaySummaryFor(r.DelaySummary, groundtruth.LabelCredentialStuffing)
		ssDelay := delaySummaryFor(r.DelaySummary, groundtruth.LabelSlowScan)
		row.EventualDetectionCSAt30 = csDelay.EventualDetectionRate
		row.EventualDetectionSSAt30 = ssDelay.EventualDetectionRate
		row.MeanRequestsToDetectionCSAt30 = csDelay.MeanRequestsToDetection
		row.MeanRequestsToDetectionSSAt30 = ssDelay.MeanRequestsToDetection
	}

	if d, ok := diagnosticsByRatio[10]; ok {
		attrs := ComputeMitigationAttribution(d, eval.PolicyBroad)
		row.AttributionCSAt10 = attributionFor(attrs, groundtruth.LabelCredentialStuffing)
		row.AttributionSSAt10 = attributionFor(attrs, groundtruth.LabelSlowScan)
	}
	if d, ok := diagnosticsByRatio[30]; ok {
		attrs := ComputeMitigationAttribution(d, eval.PolicyBroad)
		row.AttributionCSAt30 = attributionFor(attrs, groundtruth.LabelCredentialStuffing)
		row.AttributionSSAt30 = attributionFor(attrs, groundtruth.LabelSlowScan)
	}

	return row
}

// AggregateCombinedSweepRows promedia (solo sobre valores definidos,
// nunca tratando N/A como 0) varias filas del mismo candidato.
func AggregateCombinedSweepRows(rows []CombinedSweepRow) CombinedSweepRow {
	if len(rows) == 0 {
		return CombinedSweepRow{}
	}
	agg := CombinedSweepRow{Candidate: rows[0].Candidate}

	r := func(f func(CombinedSweepRow) eval.Ratio) eval.Ratio { return meanRatio(extract(rows, f)) }
	of := func(f func(CombinedSweepRow) OptionalFloat) OptionalFloat {
		return meanOptionalFloat(extractOF(rows, f))
	}

	agg.FPRAt0 = r(func(x CombinedSweepRow) eval.Ratio { return x.FPRAt0 })
	agg.BroadRecallAt10 = r(func(x CombinedSweepRow) eval.Ratio { return x.BroadRecallAt10 })
	agg.BroadRecallAt30 = r(func(x CombinedSweepRow) eval.Ratio { return x.BroadRecallAt30 })
	agg.StrictRecallAt10 = r(func(x CombinedSweepRow) eval.Ratio { return x.StrictRecallAt10 })
	agg.StrictRecallAt30 = r(func(x CombinedSweepRow) eval.Ratio { return x.StrictRecallAt30 })
	agg.BroadPrecisionAt10 = r(func(x CombinedSweepRow) eval.Ratio { return x.BroadPrecisionAt10 })
	agg.BroadPrecisionAt30 = r(func(x CombinedSweepRow) eval.Ratio { return x.BroadPrecisionAt30 })
	agg.BroadF1At10 = r(func(x CombinedSweepRow) eval.Ratio { return x.BroadF1At10 })
	agg.BroadF1At30 = r(func(x CombinedSweepRow) eval.Ratio { return x.BroadF1At30 })
	agg.RecallCSAt10 = r(func(x CombinedSweepRow) eval.Ratio { return x.RecallCSAt10 })
	agg.RecallCSAt30 = r(func(x CombinedSweepRow) eval.Ratio { return x.RecallCSAt30 })
	agg.RecallSSAt10 = r(func(x CombinedSweepRow) eval.Ratio { return x.RecallSSAt10 })
	agg.RecallSSAt30 = r(func(x CombinedSweepRow) eval.Ratio { return x.RecallSSAt30 })
	agg.EventualDetectionCSAt10 = r(func(x CombinedSweepRow) eval.Ratio { return x.EventualDetectionCSAt10 })
	agg.EventualDetectionCSAt30 = r(func(x CombinedSweepRow) eval.Ratio { return x.EventualDetectionCSAt30 })
	agg.EventualDetectionSSAt10 = r(func(x CombinedSweepRow) eval.Ratio { return x.EventualDetectionSSAt10 })
	agg.EventualDetectionSSAt30 = r(func(x CombinedSweepRow) eval.Ratio { return x.EventualDetectionSSAt30 })
	agg.MeanRequestsToDetectionCSAt10 = of(func(x CombinedSweepRow) OptionalFloat { return x.MeanRequestsToDetectionCSAt10 })
	agg.MeanRequestsToDetectionCSAt30 = of(func(x CombinedSweepRow) OptionalFloat { return x.MeanRequestsToDetectionCSAt30 })
	agg.MeanRequestsToDetectionSSAt10 = of(func(x CombinedSweepRow) OptionalFloat { return x.MeanRequestsToDetectionSSAt10 })
	agg.MeanRequestsToDetectionSSAt30 = of(func(x CombinedSweepRow) OptionalFloat { return x.MeanRequestsToDetectionSSAt30 })

	agg.AttributionCSAt10.Vector = groundtruth.LabelCredentialStuffing
	agg.AttributionCSAt30.Vector = groundtruth.LabelCredentialStuffing
	agg.AttributionSSAt10.Vector = groundtruth.LabelSlowScan
	agg.AttributionSSAt30.Vector = groundtruth.LabelSlowScan

	for _, row := range rows {
		agg.AttributionCSAt10.Mitigated += row.AttributionCSAt10.Mitigated
		agg.AttributionCSAt10.DetectorOnly += row.AttributionCSAt10.DetectorOnly
		agg.AttributionCSAt10.WithAnomalyAssist += row.AttributionCSAt10.WithAnomalyAssist
		agg.AttributionCSAt10.AnomalyOnly += row.AttributionCSAt10.AnomalyOnly
		agg.AttributionCSAt10.Neither += row.AttributionCSAt10.Neither

		agg.AttributionCSAt30.Mitigated += row.AttributionCSAt30.Mitigated
		agg.AttributionCSAt30.DetectorOnly += row.AttributionCSAt30.DetectorOnly
		agg.AttributionCSAt30.WithAnomalyAssist += row.AttributionCSAt30.WithAnomalyAssist
		agg.AttributionCSAt30.AnomalyOnly += row.AttributionCSAt30.AnomalyOnly
		agg.AttributionCSAt30.Neither += row.AttributionCSAt30.Neither

		agg.AttributionSSAt10.Mitigated += row.AttributionSSAt10.Mitigated
		agg.AttributionSSAt10.DetectorOnly += row.AttributionSSAt10.DetectorOnly
		agg.AttributionSSAt10.WithAnomalyAssist += row.AttributionSSAt10.WithAnomalyAssist
		agg.AttributionSSAt10.AnomalyOnly += row.AttributionSSAt10.AnomalyOnly
		agg.AttributionSSAt10.Neither += row.AttributionSSAt10.Neither

		agg.AttributionSSAt30.Mitigated += row.AttributionSSAt30.Mitigated
		agg.AttributionSSAt30.DetectorOnly += row.AttributionSSAt30.DetectorOnly
		agg.AttributionSSAt30.WithAnomalyAssist += row.AttributionSSAt30.WithAnomalyAssist
		agg.AttributionSSAt30.AnomalyOnly += row.AttributionSSAt30.AnomalyOnly
		agg.AttributionSSAt30.Neither += row.AttributionSSAt30.Neither
	}

	return agg
}

// RenderCombinedSweep arma el reporte en Markdown de rowsByCandidate,
// en tres tablas (core, detección/delay, atribución) para que cada
// una quede legible.
func RenderCombinedSweep(rowsByCandidate map[string][]CombinedSweepRow, order []string) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("# Sweep combinado (tuning, seeds 101/102/103, ratios 0/10/30%%)\n\n")

	w("## Core: FP, recall, precision, F1\n\n")
	w("| Candidato | Seed | FP@0%% | FPR@0%% | BroadRecall@10%% | BroadRecall@30%% | StrictRecall@10%% | StrictRecall@30%% | Precision@10%% | Precision@30%% | F1@10%% | F1@30%% |\n")
	w("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, name := range order {
		rows := rowsByCandidate[name]
		for _, x := range rows {
			w("| %s | %d | %d | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
				x.Candidate, x.Seed, x.FPAt0, formatRatio(x.FPRAt0),
				formatRatio(x.BroadRecallAt10), formatRatio(x.BroadRecallAt30),
				formatRatio(x.StrictRecallAt10), formatRatio(x.StrictRecallAt30),
				formatRatio(x.BroadPrecisionAt10), formatRatio(x.BroadPrecisionAt30),
				formatRatio(x.BroadF1At10), formatRatio(x.BroadF1At30),
			)
		}
		agg := AggregateCombinedSweepRows(rows)
		w("| %s | **PROMEDIO** | - | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			agg.Candidate, formatRatio(agg.FPRAt0),
			formatRatio(agg.BroadRecallAt10), formatRatio(agg.BroadRecallAt30),
			formatRatio(agg.StrictRecallAt10), formatRatio(agg.StrictRecallAt30),
			formatRatio(agg.BroadPrecisionAt10), formatRatio(agg.BroadPrecisionAt30),
			formatRatio(agg.BroadF1At10), formatRatio(agg.BroadF1At30),
		)
	}
	w("\n")

	w("## Recall por vector, detección eventual y requests-a-detección (nivel policy)\n\n")
	w("| Candidato | Seed | Recall CS@10%%/30%% | Recall SS@10%%/30%% | EventualDet CS@10%%/30%% | EventualDet SS@10%%/30%% | Req.medio CS@10%%/30%% | Req.medio SS@10%%/30%% |\n")
	w("|---|---|---|---|---|---|---|---|\n")
	for _, name := range order {
		rows := rowsByCandidate[name]
		for _, x := range rows {
			w("| %s | %d | %s/%s | %s/%s | %s/%s | %s/%s | %.2f/%.2f | %.2f/%.2f |\n",
				x.Candidate, x.Seed,
				formatRatio(x.RecallCSAt10), formatRatio(x.RecallCSAt30),
				formatRatio(x.RecallSSAt10), formatRatio(x.RecallSSAt30),
				formatRatio(x.EventualDetectionCSAt10), formatRatio(x.EventualDetectionCSAt30),
				formatRatio(x.EventualDetectionSSAt10), formatRatio(x.EventualDetectionSSAt30),
				x.MeanRequestsToDetectionCSAt10.Value, x.MeanRequestsToDetectionCSAt30.Value,
				x.MeanRequestsToDetectionSSAt10.Value, x.MeanRequestsToDetectionSSAt30.Value,
			)
		}
		agg := AggregateCombinedSweepRows(rows)
		w("| %s | **PROMEDIO** | %s/%s | %s/%s | %s/%s | %s/%s | %.2f/%.2f | %.2f/%.2f |\n",
			agg.Candidate,
			formatRatio(agg.RecallCSAt10), formatRatio(agg.RecallCSAt30),
			formatRatio(agg.RecallSSAt10), formatRatio(agg.RecallSSAt30),
			formatRatio(agg.EventualDetectionCSAt10), formatRatio(agg.EventualDetectionCSAt30),
			formatRatio(agg.EventualDetectionSSAt10), formatRatio(agg.EventualDetectionSSAt30),
			agg.MeanRequestsToDetectionCSAt10.Value, agg.MeanRequestsToDetectionCSAt30.Value,
			agg.MeanRequestsToDetectionSSAt10.Value, agg.MeanRequestsToDetectionSSAt30.Value,
		)
	}
	w("\n")

	w("## Atribución de la mitigación (detector propio vs. asistido por anomaly)\n\n")
	w("Mitigated = total de eventos de ese vector con Decision positiva (broad). DetectorOnly = disparó su propio detector, anomaly no. WithAnomalyAssist = los dos dispararon. AnomalyOnly = solo anomaly disparó (sin él, no se habría mitigado). Neither = señal cruzada (residual, se muestra siempre, nunca se esconde).\n\n")
	w("| Candidato | Ratio | Vector | Mitigated | DetectorOnly | WithAnomalyAssist | AnomalyOnly | Neither |\n")
	w("|---|---|---|---|---|---|---|---|\n")
	for _, name := range order {
		agg := AggregateCombinedSweepRows(rowsByCandidate[name])
		for _, entry := range []struct {
			ratio int
			attr  MitigationAttribution
		}{
			{10, agg.AttributionCSAt10}, {30, agg.AttributionCSAt30},
			{10, agg.AttributionSSAt10}, {30, agg.AttributionSSAt30},
		} {
			w("| %s | %d%% | %s | %d | %d | %d | %d | %d |\n",
				name, entry.ratio, entry.attr.Vector, entry.attr.Mitigated,
				entry.attr.DetectorOnly, entry.attr.WithAnomalyAssist, entry.attr.AnomalyOnly, entry.attr.Neither,
			)
		}
	}
	w("\n")

	return string(b)
}
