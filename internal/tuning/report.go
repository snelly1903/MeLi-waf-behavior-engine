// Exporta los resultados de tuning a CSV, JSON y Markdown.
package tuning

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type Row struct {
	Candidate string `json:"candidate"`
	Seed      uint64 `json:"seed"`
	Ratio     int    `json:"ratio"`

	StrictTP        int    `json:"strict_tp"`
	StrictFP        int    `json:"strict_fp"`
	StrictFN        int    `json:"strict_fn"`
	StrictTN        int    `json:"strict_tn"`
	StrictPrecision string `json:"strict_precision"`
	StrictRecall    string `json:"strict_recall"`
	StrictFPR       string `json:"strict_fpr"`
	StrictFNR       string `json:"strict_fnr"`
	StrictF1        string `json:"strict_f1"`

	BroadTP        int    `json:"broad_tp"`
	BroadFP        int    `json:"broad_fp"`
	BroadFN        int    `json:"broad_fn"`
	BroadTN        int    `json:"broad_tn"`
	BroadPrecision string `json:"broad_precision"`
	BroadRecall    string `json:"broad_recall"`
	BroadFPR       string `json:"broad_fpr"`
	BroadFNR       string `json:"broad_fnr"`
	BroadF1        string `json:"broad_f1"`

	RecallCredentialStuffing string `json:"recall_credential_stuffing"`
	RecallSlowScan           string `json:"recall_slow_scan"`

	CSCampaigns             int    `json:"cs_campaigns"`
	CSDetectedCampaigns     int    `json:"cs_detected_campaigns"`
	CSEventualDetectionRate string `json:"cs_eventual_detection_rate"`
	CSMeanRequestsToDetect  string `json:"cs_mean_requests_to_detection"`
	CSMeanSecondsToDetect   string `json:"cs_mean_seconds_to_detection"`

	SSCampaigns             int    `json:"ss_campaigns"`
	SSDetectedCampaigns     int    `json:"ss_detected_campaigns"`
	SSEventualDetectionRate string `json:"ss_eventual_detection_rate"`
	SSMeanRequestsToDetect  string `json:"ss_mean_requests_to_detection"`
	SSMeanSecondsToDetect   string `json:"ss_mean_seconds_to_detection"`

	IssuesClean bool `json:"issues_clean"`
}

func formatRatio(r eval.Ratio) string {
	if !r.Defined {
		return "N/A"
	}
	return strconv.FormatFloat(r.Value, 'f', 4, 64)
}

func formatOptionalFloat(v OptionalFloat) string {
	if !v.Defined {
		return "N/A"
	}
	return strconv.FormatFloat(v.Value, 'f', 2, 64)
}

func formatOptionalDurationSeconds(v OptionalDuration) string {
	if !v.Defined {
		return "N/A"
	}
	return strconv.FormatFloat(v.Value.Seconds(), 'f', 1, 64)
}

func vectorRecall(vs []eval.AttackVectorRecall, vector groundtruth.Label) eval.Ratio {
	for _, v := range vs {
		if v.Vector == vector {
			return v.Recall
		}
	}
	return eval.Ratio{Defined: false}
}

func delaySummaryFor(ds []DelaySummary, vector groundtruth.Label) DelaySummary {
	for _, d := range ds {
		if d.Vector == vector {
			return d
		}
	}
	return DelaySummary{Vector: vector, EventualDetectionRate: eval.Ratio{Defined: false}}
}

func ToRows(results []RunResult) []Row {
	rows := make([]Row, 0, len(results))
	for _, r := range results {
		cs := delaySummaryFor(r.DelaySummary, groundtruth.LabelCredentialStuffing)
		ss := delaySummaryFor(r.DelaySummary, groundtruth.LabelSlowScan)

		rows = append(rows, Row{
			Candidate: r.Candidate,
			Seed:      r.Seed,
			Ratio:     r.Ratio,

			StrictTP: r.Eval.Strict.Matrix.TP, StrictFP: r.Eval.Strict.Matrix.FP,
			StrictFN: r.Eval.Strict.Matrix.FN, StrictTN: r.Eval.Strict.Matrix.TN,
			StrictPrecision: formatRatio(r.Eval.Strict.Metrics.Precision),
			StrictRecall:    formatRatio(r.Eval.Strict.Metrics.Recall),
			StrictFPR:       formatRatio(r.Eval.Strict.Metrics.FPR),
			StrictFNR:       formatRatio(r.Eval.Strict.Metrics.FNR),
			StrictF1:        formatRatio(r.Eval.Strict.Metrics.F1),

			BroadTP: r.Eval.Broad.Matrix.TP, BroadFP: r.Eval.Broad.Matrix.FP,
			BroadFN: r.Eval.Broad.Matrix.FN, BroadTN: r.Eval.Broad.Matrix.TN,
			BroadPrecision: formatRatio(r.Eval.Broad.Metrics.Precision),
			BroadRecall:    formatRatio(r.Eval.Broad.Metrics.Recall),
			BroadFPR:       formatRatio(r.Eval.Broad.Metrics.FPR),
			BroadFNR:       formatRatio(r.Eval.Broad.Metrics.FNR),
			BroadF1:        formatRatio(r.Eval.Broad.Metrics.F1),

			RecallCredentialStuffing: formatRatio(vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelCredentialStuffing)),
			RecallSlowScan:           formatRatio(vectorRecall(r.Eval.ByAttackVector, groundtruth.LabelSlowScan)),

			CSCampaigns:             cs.Campaigns,
			CSDetectedCampaigns:     cs.DetectedCampaigns,
			CSEventualDetectionRate: formatRatio(cs.EventualDetectionRate),
			CSMeanRequestsToDetect:  formatOptionalFloat(cs.MeanRequestsToDetection),
			CSMeanSecondsToDetect:   formatOptionalDurationSeconds(cs.MeanTimeToDetection),

			SSCampaigns:             ss.Campaigns,
			SSDetectedCampaigns:     ss.DetectedCampaigns,
			SSEventualDetectionRate: formatRatio(ss.EventualDetectionRate),
			SSMeanRequestsToDetect:  formatOptionalFloat(ss.MeanRequestsToDetection),
			SSMeanSecondsToDetect:   formatOptionalDurationSeconds(ss.MeanTimeToDetection),

			IssuesClean: r.Eval.Issues.Clean(),
		})
	}
	return rows
}

var csvHeader = []string{
	"candidate", "seed", "ratio",
	"strict_tp", "strict_fp", "strict_fn", "strict_tn", "strict_precision", "strict_recall", "strict_fpr", "strict_fnr", "strict_f1",
	"broad_tp", "broad_fp", "broad_fn", "broad_tn", "broad_precision", "broad_recall", "broad_fpr", "broad_fnr", "broad_f1",
	"recall_credential_stuffing", "recall_slow_scan",
	"cs_campaigns", "cs_detected_campaigns", "cs_eventual_detection_rate", "cs_mean_requests_to_detection", "cs_mean_seconds_to_detection",
	"ss_campaigns", "ss_detected_campaigns", "ss_eventual_detection_rate", "ss_mean_requests_to_detection", "ss_mean_seconds_to_detection",
	"issues_clean",
}

func (r Row) csvRecord() []string {
	return []string{
		r.Candidate, strconv.FormatUint(r.Seed, 10), strconv.Itoa(r.Ratio),
		strconv.Itoa(r.StrictTP), strconv.Itoa(r.StrictFP), strconv.Itoa(r.StrictFN), strconv.Itoa(r.StrictTN),
		r.StrictPrecision, r.StrictRecall, r.StrictFPR, r.StrictFNR, r.StrictF1,
		strconv.Itoa(r.BroadTP), strconv.Itoa(r.BroadFP), strconv.Itoa(r.BroadFN), strconv.Itoa(r.BroadTN),
		r.BroadPrecision, r.BroadRecall, r.BroadFPR, r.BroadFNR, r.BroadF1,
		r.RecallCredentialStuffing, r.RecallSlowScan,
		strconv.Itoa(r.CSCampaigns), strconv.Itoa(r.CSDetectedCampaigns), r.CSEventualDetectionRate, r.CSMeanRequestsToDetect, r.CSMeanSecondsToDetect,
		strconv.Itoa(r.SSCampaigns), strconv.Itoa(r.SSDetectedCampaigns), r.SSEventualDetectionRate, r.SSMeanRequestsToDetect, r.SSMeanSecondsToDetect,
		strconv.FormatBool(r.IssuesClean),
	}
}

func WriteCSV(path string, rows []Row) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("tuning: creating %s: %w", path, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range rows {
		if err := w.Write(r.csvRecord()); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func WriteJSON(path string, rows []Row) error {
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func RenderMarkdown(results []RunResult) string {
	var b strings.Builder
	rows := ToRows(results)

	b.WriteString("# Reporte de evaluación offline — internal/tuning\n\n")

	byGroup := make(map[string][]Row)
	var order []string
	for _, r := range rows {
		key := fmt.Sprintf("%s|%d", r.Candidate, r.Ratio)
		if _, ok := byGroup[key]; !ok {
			order = append(order, key)
		}
		byGroup[key] = append(byGroup[key], r)
	}

	for _, key := range order {
		group := byGroup[key]
		fmt.Fprintf(&b, "## %s — %d%% malicious\n\n", group[0].Candidate, group[0].Ratio)

		b.WriteString("| Seed | Strict TP/FP/FN/TN | Strict P/R/F1 | Broad TP/FP/FN/TN | Broad P/R/F1 | Recall CS | Recall SS | CS campañas/detectadas/req.medio | SS campañas/detectadas/req.medio | Issues limpio |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
		for _, r := range group {
			fmt.Fprintf(&b, "| %d | %d/%d/%d/%d | %s/%s/%s | %d/%d/%d/%d | %s/%s/%s | %s | %s | %d/%d/%s | %d/%d/%s | %v |\n",
				r.Seed,
				r.StrictTP, r.StrictFP, r.StrictFN, r.StrictTN, r.StrictPrecision, r.StrictRecall, r.StrictF1,
				r.BroadTP, r.BroadFP, r.BroadFN, r.BroadTN, r.BroadPrecision, r.BroadRecall, r.BroadF1,
				r.RecallCredentialStuffing, r.RecallSlowScan,
				r.CSCampaigns, r.CSDetectedCampaigns, r.CSMeanRequestsToDetect,
				r.SSCampaigns, r.SSDetectedCampaigns, r.SSMeanRequestsToDetect,
				r.IssuesClean,
			)
		}
		b.WriteString("\n")

		csCampaigns := sumInt(group, func(r Row) int { return r.CSCampaigns })
		csDetected := sumInt(group, func(r Row) int { return r.CSDetectedCampaigns })
		ssCampaigns := sumInt(group, func(r Row) int { return r.SSCampaigns })
		ssDetected := sumInt(group, func(r Row) int { return r.SSDetectedCampaigns })

		fmt.Fprintf(&b, "Detection delay (credential_stuffing), agregado de %d seeds: campañas=%d detectadas=%d tasa=%s\n\n",
			len(group), csCampaigns, csDetected, formatRatio(ratioOf(csDetected, csCampaigns)))
		fmt.Fprintf(&b, "Detection delay (slow_scan), agregado de %d seeds: campañas=%d detectadas=%d tasa=%s\n\n",
			len(group), ssCampaigns, ssDetected, formatRatio(ratioOf(ssDetected, ssCampaigns)))
	}

	return b.String()
}

func sumInt(rows []Row, f func(Row) int) int {
	total := 0
	for _, r := range rows {
		total += f(r)
	}
	return total
}
