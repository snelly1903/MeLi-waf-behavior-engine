// Analiza la distribución de risk scores por detector y tipo de tráfico.
package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type RiskScoreBucket struct {
	Detector string
	Group    string
	Summary  PercentileSummary
}

func groupFor(label, target groundtruth.Label) string {
	switch {
	case label == groundtruth.LabelLegit:
		return "legit"
	case label == target:
		return "malicious"
	default:
		return "other_attack"
	}
}

func genericGroupFor(label groundtruth.Label) string {
	if label == groundtruth.LabelLegit {
		return "legit"
	}
	return "malicious"
}

func AnalyzeRiskScoreDistributions(diagnostics []EventDiagnostic) []RiskScoreBucket {
	type key struct{ detector, group string }
	samples := make(map[key][]float64)
	var order []key

	add := func(k key, v float64) {
		if _, exists := samples[k]; !exists {
			order = append(order, k)
		}
		samples[k] = append(samples[k], v)
	}

	for _, d := range diagnostics {
		add(key{"credential_stuffing", groupFor(d.Label, groundtruth.LabelCredentialStuffing)}, d.CredentialStuffing.RiskScore)
		add(key{"slow_scan", groupFor(d.Label, groundtruth.LabelSlowScan)}, d.SlowScan.RiskScore)

		if winner, ok := winningAnomalyEval(d.Anomaly); ok {
			add(key{"statistical_anomaly", genericGroupFor(d.Label)}, winner.RiskScore)
		}
	}

	result := make([]RiskScoreBucket, 0, len(order))
	for _, k := range order {
		result = append(result, RiskScoreBucket{Detector: k.detector, Group: k.group, Summary: Summarize(samples[k])})
	}
	return result
}

func RenderRiskScoreDistributions(buckets []RiskScoreBucket) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("## Distribución de RiskScore por detector y grupo de ground truth\n\n")
	w("RiskScore es 0 en cualquier evento donde ese detector no disparó — incluido en la distribución, nunca excluido.\n\n")
	w("| Detector | Grupo | N | min | p50 | p75 | p90 | p95 | max |\n")
	w("|---|---|---|---|---|---|---|---|---|\n")
	for _, buck := range buckets {
		s := buck.Summary
		w("| %s | %s | %d | %.4f | %.4f | %.4f | %.4f | %.4f | %.4f |\n",
			buck.Detector, buck.Group, s.N, s.Min, s.P50, s.P75, s.P90, s.P95, s.Max)
	}
	w("\n")
	return string(b)
}
