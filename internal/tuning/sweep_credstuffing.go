package tuning

import (
	"fmt"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// CredentialStuffingSweepRow es, para UN candidato y UN seed, todas
// las métricas pedidas explícitamente en el sweep de credential
// stuffing: FPR@0%, recall broad y de credential_stuffing
// (decision-based Y detector-específico, mantenidos separados) a
// 10%/30%, detección eventual de campaña (usando el gate PROPIO de
// credstuffing.Detector — AnalyzeCredentialStuffingCampaigns, nunca
// la Decision final combinada), requests/tiempo medio-mediana hasta
// esa detección de gate, y el desglose de atribución
// credential-only/anomaly-only/both/neither.
//
// *DetectorAt10/30 usa CredentialStuffing.Triggered crudo
// (request-level: de todos los eventos etiquetados
// credential_stuffing, qué fracción hizo disparar el gate propio).
// *DecisionAt10/30 usa la Decision final ya combinada con Policy
// (mismo criterio que el resto de internal/eval) — se mantienen
// separadas a propósito, nunca mezcladas, porque en esta fase se
// calibra el detector, no Policy.
type CredentialStuffingSweepRow struct {
	Candidate string
	Seed      uint64

	FPRAt0             eval.Ratio
	PrecisionBroadAt10 eval.Ratio
	PrecisionBroadAt30 eval.Ratio
	F1BroadAt10        eval.Ratio
	F1BroadAt30        eval.Ratio

	BroadRecallAt10 eval.Ratio
	BroadRecallAt30 eval.Ratio

	CSRecallDecisionAt10 eval.Ratio
	CSRecallDecisionAt30 eval.Ratio

	CSRecallDetectorAt10 eval.Ratio
	CSRecallDetectorAt30 eval.Ratio

	// EventualDetection* usa el gate PROPIO de credstuffing.Detector
	// (CredentialStuffing.Triggered), no la Decision final.
	EventualDetectionAt10 eval.Ratio
	EventualDetectionAt30 eval.Ratio

	MeanRequestsToDetectionAt10   OptionalFloat
	MedianRequestsToDetectionAt10 OptionalFloat
	MeanTimeToDetectionAt10       OptionalDuration
	MeanRequestsToDetectionAt30   OptionalFloat
	MedianRequestsToDetectionAt30 OptionalFloat
	MeanTimeToDetectionAt30       OptionalDuration

	PctCredentialOnlyAt10 float64
	PctAnomalyOnlyAt10    float64
	PctBothAt10           float64
	PctNeitherAt10        float64
	PctCredentialOnlyAt30 float64
	PctAnomalyOnlyAt30    float64
	PctBothAt30           float64
	PctNeitherAt30        float64

	// StrictRecallAt10/30 es dato SECUNDARIO, nunca el criterio
	// principal — mismo criterio que el sweep de slow_scan.
	StrictRecallAt10 eval.Ratio
	StrictRecallAt30 eval.Ratio
}

// credentialStuffingDetectorRecall calcula, sobre diagnostics de UNA
// corrida, la fracción de eventos etiquetados credential_stuffing
// cuyo CredentialStuffing.Triggered fue true — el recall
// request-level del gate PROPIO, sin pasar por Policy ni por la
// Decision final. Distinto a proposito de eval.ByAttackVectorRecall,
// que es decision-based.
func credentialStuffingDetectorRecall(diagnostics []EventDiagnostic) eval.Ratio {
	var total, triggered int
	for _, d := range diagnostics {
		if d.Label != groundtruth.LabelCredentialStuffing {
			continue
		}
		total++
		if d.CredentialStuffing.Triggered {
			triggered++
		}
	}
	return ratioOf(triggered, total)
}

// csDetectionStats calcula mean/mediana de requests-a-detección y la
// media de tiempo-a-detección entre las campañas de campaigns que SÍ
// se detectaron (gate propio) — nunca promedia sobre las no
// detectadas.
func csDetectionStats(campaigns []CredentialStuffingCampaignAnalysis) (meanReq, medianReq OptionalFloat, meanTime OptionalDuration) {
	var reqValues []float64
	var timeSum float64
	var timeN int
	for _, c := range campaigns {
		if !c.DetectedEventually {
			continue
		}
		reqValues = append(reqValues, float64(c.FirstDetectionRequestIndex))
		if c.TimeToFirstDetection.Defined {
			timeSum += float64(c.TimeToFirstDetection.Value)
			timeN++
		}
	}
	if len(reqValues) == 0 {
		return OptionalFloat{}, OptionalFloat{}, OptionalDuration{}
	}
	sum := 0.0
	for _, v := range reqValues {
		sum += v
	}
	s := Summarize(reqValues)
	meanReq = OptionalFloat{Value: sum / float64(len(reqValues)), Defined: true}
	medianReq = OptionalFloat{Value: s.P50, Defined: true}
	if timeN > 0 {
		meanTime = OptionalDuration{Value: time.Duration(timeSum / float64(timeN)), Defined: true}
	}
	return meanReq, medianReq, meanTime
}

// pooledAttributionPct agrega varias campañas (por ejemplo, si
// hubiera más de una en el mismo seed/ratio) sumando sus conteos
// CRUDOS antes de convertir a porcentaje — nunca promedia
// porcentajes ya redondeados de campañas distintas.
func pooledAttributionPct(campaigns []CredentialStuffingCampaignAnalysis) (credOnly, anomOnly, both, neither float64) {
	var totalCred, totalAnom, totalBoth, totalNeither, total int
	for _, c := range campaigns {
		totalCred += c.CredOnlyEvents
		totalAnom += c.AnomOnlyEvents
		totalBoth += c.BothEvents
		totalNeither += c.NeitherEvents
		total += c.CredOnlyEvents + c.AnomOnlyEvents + c.BothEvents + c.NeitherEvents
	}
	if total == 0 {
		return 0, 0, 0, 0
	}
	pct := func(n int) float64 { return float64(n) / float64(total) * 100 }
	return pct(totalCred), pct(totalAnom), pct(totalBoth), pct(totalNeither)
}

func extractOD[T any](rows []T, f func(T) OptionalDuration) []OptionalDuration {
	out := make([]OptionalDuration, len(rows))
	for i, r := range rows {
		out[i] = f(r)
	}
	return out
}

func meanOptionalDuration(values []OptionalDuration) OptionalDuration {
	var sum time.Duration
	var n int
	for _, v := range values {
		if v.Defined {
			sum += v.Value
			n++
		}
	}
	if n == 0 {
		return OptionalDuration{}
	}
	return OptionalDuration{Value: sum / time.Duration(n), Defined: true}
}

// ComputeCredentialStuffingSweepRow arma la fila de un
// candidato/seed a partir de resultsByRatio (un RunResult por ratio
// 0/10/30, del MISMO candidato y seed), diagnosticsByRatio (de
// RunDiagnostics, mismo candidato/seed/ratio) y campaigns (las
// campañas de credential_stuffing de ese candidato/seed, de
// AnalyzeCredentialStuffingCampaigns, con eventos de cualquier ratio
// mezclados — se filtran acá por Ratio).
func ComputeCredentialStuffingSweepRow(candidateName string, seed uint64, resultsByRatio map[int]RunResult, diagnosticsByRatio map[int][]EventDiagnostic, campaigns []CredentialStuffingCampaignAnalysis) CredentialStuffingSweepRow {
	row := CredentialStuffingSweepRow{Candidate: candidateName, Seed: seed}

	if r, ok := resultsByRatio[0]; ok {
		row.FPRAt0 = r.Eval.Broad.Metrics.FPR
	}
	if r, ok := resultsByRatio[10]; ok {
		row.BroadRecallAt10 = r.Eval.Broad.Metrics.Recall
		row.PrecisionBroadAt10 = r.Eval.Broad.Metrics.Precision
		row.F1BroadAt10 = r.Eval.Broad.Metrics.F1
		row.CSRecallDecisionAt10 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelCredentialStuffing)
		row.StrictRecallAt10 = r.Eval.Strict.Metrics.Recall
	}
	if r, ok := resultsByRatio[30]; ok {
		row.BroadRecallAt30 = r.Eval.Broad.Metrics.Recall
		row.PrecisionBroadAt30 = r.Eval.Broad.Metrics.Precision
		row.F1BroadAt30 = r.Eval.Broad.Metrics.F1
		row.CSRecallDecisionAt30 = vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelCredentialStuffing)
		row.StrictRecallAt30 = r.Eval.Strict.Metrics.Recall
	}

	if d, ok := diagnosticsByRatio[10]; ok {
		row.CSRecallDetectorAt10 = credentialStuffingDetectorRecall(d)
	}
	if d, ok := diagnosticsByRatio[30]; ok {
		row.CSRecallDetectorAt30 = credentialStuffingDetectorRecall(d)
	}

	var campaigns10, campaigns30 []CredentialStuffingCampaignAnalysis
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
	row.MeanRequestsToDetectionAt10, row.MedianRequestsToDetectionAt10, row.MeanTimeToDetectionAt10 = csDetectionStats(campaigns10)
	row.PctCredentialOnlyAt10, row.PctAnomalyOnlyAt10, row.PctBothAt10, row.PctNeitherAt10 = pooledAttributionPct(campaigns10)

	detected30 := 0
	for _, c := range campaigns30 {
		if c.DetectedEventually {
			detected30++
		}
	}
	row.EventualDetectionAt30 = ratioOf(detected30, len(campaigns30))
	row.MeanRequestsToDetectionAt30, row.MedianRequestsToDetectionAt30, row.MeanTimeToDetectionAt30 = csDetectionStats(campaigns30)
	row.PctCredentialOnlyAt30, row.PctAnomalyOnlyAt30, row.PctBothAt30, row.PctNeitherAt30 = pooledAttributionPct(campaigns30)

	return row
}

// AggregateCredentialStuffingSweepRows agrupa varias filas del MISMO
// candidato (una por seed) en una fila resumen: media simple de cada
// Ratio/OptionalFloat/OptionalDuration definido (ignorando los N/A),
// y atribución pooled sobre los conteos crudos de TODAS las campañas
// de todos los seeds — mismo criterio que AggregateSlowScanSweepRows.
func AggregateCredentialStuffingSweepRows(rows []CredentialStuffingSweepRow, campaignsByRatio map[int][]CredentialStuffingCampaignAnalysis) CredentialStuffingSweepRow {
	if len(rows) == 0 {
		return CredentialStuffingSweepRow{}
	}
	agg := CredentialStuffingSweepRow{Candidate: rows[0].Candidate, Seed: 0}

	agg.FPRAt0 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.FPRAt0 }))
	agg.PrecisionBroadAt10 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.PrecisionBroadAt10 }))
	agg.PrecisionBroadAt30 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.PrecisionBroadAt30 }))
	agg.F1BroadAt10 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.F1BroadAt10 }))
	agg.F1BroadAt30 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.F1BroadAt30 }))
	agg.BroadRecallAt10 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.BroadRecallAt10 }))
	agg.BroadRecallAt30 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.BroadRecallAt30 }))
	agg.CSRecallDecisionAt10 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.CSRecallDecisionAt10 }))
	agg.CSRecallDecisionAt30 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.CSRecallDecisionAt30 }))
	agg.CSRecallDetectorAt10 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.CSRecallDetectorAt10 }))
	agg.CSRecallDetectorAt30 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.CSRecallDetectorAt30 }))
	agg.EventualDetectionAt10 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.EventualDetectionAt10 }))
	agg.EventualDetectionAt30 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.EventualDetectionAt30 }))
	agg.StrictRecallAt10 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.StrictRecallAt10 }))
	agg.StrictRecallAt30 = meanRatio(extract(rows, func(r CredentialStuffingSweepRow) eval.Ratio { return r.StrictRecallAt30 }))

	agg.MeanRequestsToDetectionAt10 = meanOptionalFloat(extractOF(rows, func(r CredentialStuffingSweepRow) OptionalFloat { return r.MeanRequestsToDetectionAt10 }))
	agg.MedianRequestsToDetectionAt10 = meanOptionalFloat(extractOF(rows, func(r CredentialStuffingSweepRow) OptionalFloat { return r.MedianRequestsToDetectionAt10 }))
	agg.MeanRequestsToDetectionAt30 = meanOptionalFloat(extractOF(rows, func(r CredentialStuffingSweepRow) OptionalFloat { return r.MeanRequestsToDetectionAt30 }))
	agg.MedianRequestsToDetectionAt30 = meanOptionalFloat(extractOF(rows, func(r CredentialStuffingSweepRow) OptionalFloat { return r.MedianRequestsToDetectionAt30 }))
	agg.MeanTimeToDetectionAt10 = meanOptionalDuration(extractOD(rows, func(r CredentialStuffingSweepRow) OptionalDuration { return r.MeanTimeToDetectionAt10 }))
	agg.MeanTimeToDetectionAt30 = meanOptionalDuration(extractOD(rows, func(r CredentialStuffingSweepRow) OptionalDuration { return r.MeanTimeToDetectionAt30 }))

	agg.PctCredentialOnlyAt10, agg.PctAnomalyOnlyAt10, agg.PctBothAt10, agg.PctNeitherAt10 = pooledAttributionPct(campaignsByRatio[10])
	agg.PctCredentialOnlyAt30, agg.PctAnomalyOnlyAt30, agg.PctBothAt30, agg.PctNeitherAt30 = pooledAttributionPct(campaignsByRatio[30])

	return agg
}

// RenderCredentialStuffingSweep arma el reporte en Markdown del sweep
// completo: una fila por seed más una fila "PROMEDIO" por candidato,
// en tablas separadas por grupo de métrica para mantener cada tabla
// legible.
func RenderCredentialStuffingSweep(rowsByCandidate map[string][]CredentialStuffingSweepRow, campaignsByCandidateRatio map[string]map[int][]CredentialStuffingCampaignAnalysis, order []string) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("# Sweep de Credential Stuffing (tuning, seeds 101/102/103, ratios 0/10/30%%)\n\n")
	w("EventualDetection y Requests/Tiempo-a-detección usan el gate PROPIO de credstuffing.Detector (CredentialStuffing.Triggered), nunca la Decision final combinada — Policy sigue sin tocarse. RecallDetector es request-level (fracción de eventos credential_stuffing con el gate disparado); RecallDecision es decision-based (mismo criterio que el resto de internal/eval).\n\n")

	aggFor := func(name string) CredentialStuffingSweepRow {
		return AggregateCredentialStuffingSweepRows(rowsByCandidate[name], campaignsByCandidateRatio[name])
	}

	w("## Métricas generales (broad, overall)\n\n")
	w("| Candidato | Seed | FPR@0%% | Precision@10%% | Precision@30%% | F1@10%% | F1@30%% | BroadRecall@10%% | BroadRecall@30%% | StrictRecall@10%% | StrictRecall@30%% |\n")
	w("|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, name := range order {
		for _, r := range rowsByCandidate[name] {
			w("| %s | %d | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
				r.Candidate, r.Seed, formatRatio(r.FPRAt0),
				formatRatio(r.PrecisionBroadAt10), formatRatio(r.PrecisionBroadAt30),
				formatRatio(r.F1BroadAt10), formatRatio(r.F1BroadAt30),
				formatRatio(r.BroadRecallAt10), formatRatio(r.BroadRecallAt30),
				formatRatio(r.StrictRecallAt10), formatRatio(r.StrictRecallAt30),
			)
		}
		a := aggFor(name)
		w("| %s | **PROMEDIO** | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			a.Candidate, formatRatio(a.FPRAt0),
			formatRatio(a.PrecisionBroadAt10), formatRatio(a.PrecisionBroadAt30),
			formatRatio(a.F1BroadAt10), formatRatio(a.F1BroadAt30),
			formatRatio(a.BroadRecallAt10), formatRatio(a.BroadRecallAt30),
			formatRatio(a.StrictRecallAt10), formatRatio(a.StrictRecallAt30),
		)
	}
	w("\n")

	w("## Recall de credential_stuffing: detector-específico vs. decision-based\n\n")
	w("| Candidato | Seed | RecallDetector@10%% | RecallDetector@30%% | RecallDecision@10%% | RecallDecision@30%% |\n")
	w("|---|---|---|---|---|---|\n")
	for _, name := range order {
		for _, r := range rowsByCandidate[name] {
			w("| %s | %d | %s | %s | %s | %s |\n",
				r.Candidate, r.Seed,
				formatRatio(r.CSRecallDetectorAt10), formatRatio(r.CSRecallDetectorAt30),
				formatRatio(r.CSRecallDecisionAt10), formatRatio(r.CSRecallDecisionAt30),
			)
		}
		a := aggFor(name)
		w("| %s | **PROMEDIO** | %s | %s | %s | %s |\n",
			a.Candidate,
			formatRatio(a.CSRecallDetectorAt10), formatRatio(a.CSRecallDetectorAt30),
			formatRatio(a.CSRecallDecisionAt10), formatRatio(a.CSRecallDecisionAt30),
		)
	}
	w("\n")

	w("## Detección eventual de campaña y delay (gate propio, request index y tiempo)\n\n")
	w("| Candidato | Seed | EventualDet@10%% | EventualDet@30%% | Req.medio/mediana@10%% | Tiempo medio@10%% | Req.medio/mediana@30%% | Tiempo medio@30%% |\n")
	w("|---|---|---|---|---|---|---|---|\n")
	for _, name := range order {
		for _, r := range rowsByCandidate[name] {
			w("| %s | %d | %s | %s | %.1f/%.1f | %s | %.1f/%.1f | %s |\n",
				r.Candidate, r.Seed,
				formatRatio(r.EventualDetectionAt10), formatRatio(r.EventualDetectionAt30),
				r.MeanRequestsToDetectionAt10.Value, r.MedianRequestsToDetectionAt10.Value,
				formatOptionalDurationSeconds(r.MeanTimeToDetectionAt10),
				r.MeanRequestsToDetectionAt30.Value, r.MedianRequestsToDetectionAt30.Value,
				formatOptionalDurationSeconds(r.MeanTimeToDetectionAt30),
			)
		}
		a := aggFor(name)
		w("| %s | **PROMEDIO** | %s | %s | %.1f/%.1f | %s | %.1f/%.1f | %s |\n",
			a.Candidate,
			formatRatio(a.EventualDetectionAt10), formatRatio(a.EventualDetectionAt30),
			a.MeanRequestsToDetectionAt10.Value, a.MedianRequestsToDetectionAt10.Value,
			formatOptionalDurationSeconds(a.MeanTimeToDetectionAt10),
			a.MeanRequestsToDetectionAt30.Value, a.MedianRequestsToDetectionAt30.Value,
			formatOptionalDurationSeconds(a.MeanTimeToDetectionAt30),
		)
	}
	w("\n")

	w("## Atribución por evento credential_stuffing (%% del total de eventos de esa campaña, pooled entre seeds)\n\n")
	w("| Candidato | Ratio | Credential only | Anomaly only | Both | Neither |\n")
	w("|---|---|---|---|---|---|\n")
	for _, name := range order {
		a := aggFor(name)
		w("| %s | 10%% | %.1f%% | %.1f%% | %.1f%% | %.1f%% |\n", a.Candidate, a.PctCredentialOnlyAt10, a.PctAnomalyOnlyAt10, a.PctBothAt10, a.PctNeitherAt10)
		w("| %s | 30%% | %.1f%% | %.1f%% | %.1f%% | %.1f%% |\n", a.Candidate, a.PctCredentialOnlyAt30, a.PctAnomalyOnlyAt30, a.PctBothAt30, a.PctNeitherAt30)
	}
	w("\n")

	return string(b)
}
