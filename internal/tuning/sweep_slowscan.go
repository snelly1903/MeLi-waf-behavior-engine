package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// SlowScanSweepRow es, para UN candidato y UN seed, todas las
// métricas pedidas explícitamente en el sweep de slow_scan (tarea
// 1.9): FPR@0%, recall broad y de slow_scan a 10%/30%, detección
// eventual de campaña (usando el gate PROPIO de slowscan —
// AnalyzeSlowScanCampaigns, no la Decision final combinada, porque es
// lo que estos candidatos realmente cambian) y requests-a-detección
// media/mediana, más strict recall como dato secundario.
type SlowScanSweepRow struct {
	Candidate string
	Seed      uint64

	FPRAt0 eval.Ratio

	BroadRecallAt10 eval.Ratio
	BroadRecallAt30 eval.Ratio

	SlowScanRecallAt10 eval.Ratio
	SlowScanRecallAt30 eval.Ratio

	// EventualDetection* y *RequestsToDetection* usan el gate PROPIO
	// de slowscan.Detector (SlowScan.Triggered), no la Decision final
	// — ver AnalyzeSlowScanCampaigns.
	EventualDetectionAt10 eval.Ratio
	EventualDetectionAt30 eval.Ratio

	MeanRequestsToDetectionAt10   OptionalFloat
	MedianRequestsToDetectionAt10 OptionalFloat
	MeanRequestsToDetectionAt30   OptionalFloat
	MedianRequestsToDetectionAt30 OptionalFloat

	// StrictRecallAt10/30 son dato SECUNDARIO — pedido explícitamente
	// como tal, nunca el criterio principal.
	StrictRecallAt10 eval.Ratio
	StrictRecallAt30 eval.Ratio
}

// requestsToDetectionStats calcula mean/mediana de "a qué request se
// detectó" entre las campañas de campaigns que SÍ se detectaron
// (nunca promedia sobre las no detectadas — no tendría sentido
// numérico, ver CampaignGateAnalysis).
func requestsToDetectionStats(campaigns []CampaignGateAnalysis) (mean, median OptionalFloat) {
	var values []float64
	for _, c := range campaigns {
		if c.DetectedEventually {
			values = append(values, float64(c.FirstDetectionRequestIndex))
		}
	}
	if len(values) == 0 {
		return OptionalFloat{}, OptionalFloat{}
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	s := Summarize(values)
	return OptionalFloat{Value: sum / float64(len(values)), Defined: true}, OptionalFloat{Value: s.P50, Defined: true}
}

// ComputeSlowScanSweepRow arma la fila de un candidato/seed a partir
// de resultsByRatio (un RunResult por ratio 0/10/30, del MISMO
// candidato y seed) y campaigns (las campañas de slow_scan de ese
// candidato/seed, de AnalyzeSlowScanCampaigns, con eventos de
// cualquier ratio mezclados — se filtran acá por Ratio).
func ComputeSlowScanSweepRow(candidateName string, seed uint64, resultsByRatio map[int]RunResult, campaigns []CampaignGateAnalysis) SlowScanSweepRow {
	row := SlowScanSweepRow{Candidate: candidateName, Seed: seed}

	if r, ok := resultsByRatio[0]; ok {
		row.FPRAt0 = r.Eval.Broad.Metrics.FPR
	}
	if r, ok := resultsByRatio[10]; ok {
		row.BroadRecallAt10 = r.Eval.Broad.Metrics.Recall
		row.SlowScanRecallAt10 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelSlowScan)
		row.StrictRecallAt10 = r.Eval.Strict.Metrics.Recall
	}
	if r, ok := resultsByRatio[30]; ok {
		row.BroadRecallAt30 = r.Eval.Broad.Metrics.Recall
		row.SlowScanRecallAt30 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelSlowScan)
		row.StrictRecallAt30 = r.Eval.Strict.Metrics.Recall
	}

	var campaigns10, campaigns30 []CampaignGateAnalysis
	for _, c := range campaigns {
		switch c.Ratio {
		case 10:
			campaigns10 = append(campaigns10, c)
		case 30:
			campaigns30 = append(campaigns30, c)
		}
	}

	detected10 := 0
	for _, c := range campaigns10 {
		if c.DetectedEventually {
			detected10++
		}
	}
	row.EventualDetectionAt10 = ratioOf(detected10, len(campaigns10))
	row.MeanRequestsToDetectionAt10, row.MedianRequestsToDetectionAt10 = requestsToDetectionStats(campaigns10)

	detected30 := 0
	for _, c := range campaigns30 {
		if c.DetectedEventually {
			detected30++
		}
	}
	row.EventualDetectionAt30 = ratioOf(detected30, len(campaigns30))
	row.MeanRequestsToDetectionAt30, row.MedianRequestsToDetectionAt30 = requestsToDetectionStats(campaigns30)

	return row
}

// AggregateSlowScanSweepRows agrupa varias filas del MISMO candidato
// (una por seed) en una fila resumen — media simple de cada Ratio
// definido (ignorando los N/A, nunca tratándolos como 0). No es un
// nuevo cálculo estadístico sofisticado: es la forma más simple de
// responder "en promedio, entre los 3 seeds" sin ocultar cuántos
// seeds realmente aportaron un valor.
func AggregateSlowScanSweepRows(rows []SlowScanSweepRow) SlowScanSweepRow {
	if len(rows) == 0 {
		return SlowScanSweepRow{}
	}
	agg := SlowScanSweepRow{Candidate: rows[0].Candidate, Seed: 0}

	agg.FPRAt0 = meanRatio(extract(rows, func(r SlowScanSweepRow) eval.Ratio { return r.FPRAt0 }))
	agg.BroadRecallAt10 = meanRatio(extract(rows, func(r SlowScanSweepRow) eval.Ratio { return r.BroadRecallAt10 }))
	agg.BroadRecallAt30 = meanRatio(extract(rows, func(r SlowScanSweepRow) eval.Ratio { return r.BroadRecallAt30 }))
	agg.SlowScanRecallAt10 = meanRatio(extract(rows, func(r SlowScanSweepRow) eval.Ratio { return r.SlowScanRecallAt10 }))
	agg.SlowScanRecallAt30 = meanRatio(extract(rows, func(r SlowScanSweepRow) eval.Ratio { return r.SlowScanRecallAt30 }))
	agg.EventualDetectionAt10 = meanRatio(extract(rows, func(r SlowScanSweepRow) eval.Ratio { return r.EventualDetectionAt10 }))
	agg.EventualDetectionAt30 = meanRatio(extract(rows, func(r SlowScanSweepRow) eval.Ratio { return r.EventualDetectionAt30 }))
	agg.StrictRecallAt10 = meanRatio(extract(rows, func(r SlowScanSweepRow) eval.Ratio { return r.StrictRecallAt10 }))
	agg.StrictRecallAt30 = meanRatio(extract(rows, func(r SlowScanSweepRow) eval.Ratio { return r.StrictRecallAt30 }))
	agg.MeanRequestsToDetectionAt10 = meanOptionalFloat(extractOF(rows, func(r SlowScanSweepRow) OptionalFloat { return r.MeanRequestsToDetectionAt10 }))
	agg.MedianRequestsToDetectionAt10 = meanOptionalFloat(extractOF(rows, func(r SlowScanSweepRow) OptionalFloat { return r.MedianRequestsToDetectionAt10 }))
	agg.MeanRequestsToDetectionAt30 = meanOptionalFloat(extractOF(rows, func(r SlowScanSweepRow) OptionalFloat { return r.MeanRequestsToDetectionAt30 }))
	agg.MedianRequestsToDetectionAt30 = meanOptionalFloat(extractOF(rows, func(r SlowScanSweepRow) OptionalFloat { return r.MedianRequestsToDetectionAt30 }))

	return agg
}

func extract[T any](rows []T, f func(T) eval.Ratio) []eval.Ratio {
	out := make([]eval.Ratio, len(rows))
	for i, r := range rows {
		out[i] = f(r)
	}
	return out
}

func extractOF[T any](rows []T, f func(T) OptionalFloat) []OptionalFloat {
	out := make([]OptionalFloat, len(rows))
	for i, r := range rows {
		out[i] = f(r)
	}
	return out
}

func meanRatio(ratios []eval.Ratio) eval.Ratio {
	var sum float64
	var n int
	for _, r := range ratios {
		if r.Defined {
			sum += r.Value
			n++
		}
	}
	if n == 0 {
		return eval.Ratio{Defined: false}
	}
	return eval.Ratio{Value: sum / float64(n), Defined: true}
}

func meanOptionalFloat(values []OptionalFloat) OptionalFloat {
	var sum float64
	var n int
	for _, v := range values {
		if v.Defined {
			sum += v.Value
			n++
		}
	}
	if n == 0 {
		return OptionalFloat{}
	}
	return OptionalFloat{Value: sum / float64(n), Defined: true}
}

// RenderSlowScanSweep arma el reporte en Markdown del sweep completo:
// una fila por seed más una fila "PROMEDIO" por candidato.
func RenderSlowScanSweep(rowsByCandidate map[string][]SlowScanSweepRow, order []string) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("# Sweep de Slow Scan (tuning, seeds 101/102/103, ratios 0/10/30%%)\n\n")
	w("EventualDetection y RequestsToDetection usan el gate PROPIO de slowscan.Detector, no la Decision final combinada.\n\n")

	printRow := func(r SlowScanSweepRow, label string) {
		w("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %.2f/%.2f | %.2f/%.2f | %s | %s |\n",
			r.Candidate, label,
			formatRatio(r.FPRAt0),
			formatRatio(r.BroadRecallAt10), formatRatio(r.BroadRecallAt30),
			formatRatio(r.SlowScanRecallAt10), formatRatio(r.SlowScanRecallAt30),
			formatRatio(r.EventualDetectionAt10), formatRatio(r.EventualDetectionAt30),
			r.MeanRequestsToDetectionAt10.Value, r.MedianRequestsToDetectionAt10.Value,
			r.MeanRequestsToDetectionAt30.Value, r.MedianRequestsToDetectionAt30.Value,
			formatRatio(r.StrictRecallAt10), formatRatio(r.StrictRecallAt30),
		)
	}

	w("| Candidato | Seed | FPR@0%% | BroadRecall@10%% | BroadRecall@30%% | SSRecall@10%% | SSRecall@30%% | EventualDet@10%% | EventualDet@30%% | Req.medio/mediana@10%% | Req.medio/mediana@30%% | StrictRecall@10%% | StrictRecall@30%% |\n")
	w("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, name := range order {
		rows := rowsByCandidate[name]
		for _, r := range rows {
			printRow(r, fmt.Sprintf("%d", r.Seed))
		}
		printRow(AggregateSlowScanSweepRows(rows), "**PROMEDIO**")
	}
	w("\n")

	return string(b)
}
