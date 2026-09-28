package tuning

import "fmt"

// RenderPolicySweep arma el reporte en Markdown del sweep de Policy
// completo: una fila por seed más una fila "POOLED" por
// candidato/ratio, y una tabla final de estabilidad entre seeds.
func RenderPolicySweep(rowsByCandidate map[string][]PolicySweepRow, order []string) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	rowsByCandidateRatio := func(name string, ratio int) []PolicySweepRow {
		var out []PolicySweepRow
		for _, r := range rowsByCandidate[name] {
			if r.Ratio == ratio {
				out = append(out, r)
			}
		}
		return out
	}

	w("# Sweep de Policy: ChallengeThreshold x BlockThreshold (tuning, seeds 101/102/103, ratios 0/10/30%%)\n\n")
	w("Evidencia cruda (ConfidenceScore/AttackVector) reutilizada de D1 — ningún detector se volvió a correr, solo se reaplicó Policy.actionFor. ScoreFloor sin tocar.\n\n")

	w("## Broad: TP/FP/FN/TN y métricas derivadas\n\n")
	w("| Candidato | Ratio | Seed | TP/FP/FN/TN | Precision | Recall | FPR | FNR | F1 |\n")
	w("|---|---|---|---|---|---|---|---|---|\n")
	for _, name := range order {
		for _, ratio := range []int{0, 10, 30} {
			rows := rowsByCandidateRatio(name, ratio)
			for _, r := range rows {
				w("| %s | %d%% | %d | %d/%d/%d/%d | %s | %s | %s | %s | %s |\n",
					r.Candidate, r.Ratio, r.Seed,
					r.Broad.TP, r.Broad.FP, r.Broad.FN, r.Broad.TN,
					formatRatio(r.PrecisionBroad), formatRatio(r.RecallBroad),
					formatRatio(r.FPRBroad), formatRatio(r.FNRBroad), formatRatio(r.F1Broad),
				)
			}
			a := AggregatePolicySweepRows(rows)
			w("| %s | %d%% | **POOLED** | %d/%d/%d/%d | %s | %s | %s | %s | %s |\n",
				a.Candidate, ratio,
				a.Broad.TP, a.Broad.FP, a.Broad.FN, a.Broad.TN,
				formatRatio(a.PrecisionBroad), formatRatio(a.RecallBroad),
				formatRatio(a.FPRBroad), formatRatio(a.FNRBroad), formatRatio(a.F1Broad),
			)
		}
	}
	w("\n")

	w("## Strict: TP/FP/FN/TN y métricas derivadas\n\n")
	w("| Candidato | Ratio | Seed | TP/FP/FN/TN | Precision | Recall | FPR |\n")
	w("|---|---|---|---|---|---|---|\n")
	for _, name := range order {
		for _, ratio := range []int{0, 10, 30} {
			rows := rowsByCandidateRatio(name, ratio)
			for _, r := range rows {
				w("| %s | %d%% | %d | %d/%d/%d/%d | %s | %s | %s |\n",
					r.Candidate, r.Ratio, r.Seed,
					r.Strict.TP, r.Strict.FP, r.Strict.FN, r.Strict.TN,
					formatRatio(r.PrecisionStrict), formatRatio(r.RecallStrict), formatRatio(r.FPRStrict),
				)
			}
			a := AggregatePolicySweepRows(rows)
			w("| %s | %d%% | **POOLED** | %d/%d/%d/%d | %s | %s | %s |\n",
				a.Candidate, ratio,
				a.Strict.TP, a.Strict.FP, a.Strict.FN, a.Strict.TN,
				formatRatio(a.PrecisionStrict), formatRatio(a.RecallStrict), formatRatio(a.FPRStrict),
			)
		}
	}
	w("\n")

	w("## Action distribution y tasas de falsos CHALLENGE/BLOCK sobre tráfico legítimo (pooled entre seeds)\n\n")
	w("| Candidato | Ratio | LegitAllow | LegitChallenge | LegitBlock | MaliciousAllow | MaliciousChallenge | MaliciousBlock | FalseChallengeRate | FalseBlockRate (=StrictFPR) |\n")
	w("|---|---|---|---|---|---|---|---|---|---|\n")
	for _, name := range order {
		for _, ratio := range []int{0, 10, 30} {
			a := AggregatePolicySweepRows(rowsByCandidateRatio(name, ratio))
			w("| %s | %d%% | %d | %d | %d | %d | %d | %d | %s | %s |\n",
				a.Candidate, ratio,
				a.Actions.LegitAllow, a.Actions.LegitChallenge, a.Actions.LegitBlock,
				a.Actions.MaliciousAllow, a.Actions.MaliciousChallenge, a.Actions.MaliciousBlock,
				formatRatio(a.FalseChallengeRate), formatRatio(a.FalseBlockRate),
			)
		}
	}
	w("\n")

	w("## Recall por vector, broad y strict (pooled entre seeds)\n\n")
	w("| Candidato | Ratio | CS Broad | CS Strict | SlowScan Broad | SlowScan Strict |\n")
	w("|---|---|---|---|---|---|\n")
	for _, name := range order {
		for _, ratio := range []int{10, 30} {
			a := AggregatePolicySweepRows(rowsByCandidateRatio(name, ratio))
			w("| %s | %d%% | %s | %s | %s | %s |\n",
				a.Candidate, ratio,
				formatRatio(a.CSVectorBroad.Recall), formatRatio(a.CSVectorStrict.Recall),
				formatRatio(a.SSVectorBroad.Recall), formatRatio(a.SSVectorStrict.Recall),
			)
		}
	}
	w("\n")

	w("## Estabilidad entre seeds (Range = max-min entre los 3 seeds, ignorando N/A)\n\n")
	w("| Candidato | Ratio | BroadRecall Range | StrictRecall Range | FPRBroad Range |\n")
	w("|---|---|---|---|---|\n")
	for _, name := range order {
		for _, ratio := range []int{0, 10, 30} {
			s := ComputePolicySweepStability(rowsByCandidateRatio(name, ratio))
			w("| %s | %d%% | %.4f | %.4f | %.4f |\n", s.Candidate, ratio, s.BroadRecallRange, s.StrictRecallRange, s.FPRBroadRange)
		}
	}
	w("\n")

	return string(b)
}
