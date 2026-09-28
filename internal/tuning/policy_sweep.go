package tuning

import (
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// PolicyCandidate identifica una combinación de ChallengeThreshold/
// BlockThreshold a evaluar en el sweep de Policy (tarea 1.9) —
// ScoreFloor nunca se toca en este sweep.
type PolicyCandidate struct {
	Name               string
	ChallengeThreshold float64
	BlockThreshold     float64
}

// PolicySweepRow es, para UN candidato de Policy, UN seed y UN ratio,
// todas las métricas pedidas para el sweep de Policy — calculadas SIN
// volver a correr ningún detector (ver RunResultWithPolicy): la
// evidencia cruda (ConfidenceScore/AttackVector) es la de D1, ya
// congelada; acá solo cambia el mapping RiskScore→Action.
type PolicySweepRow struct {
	Candidate string
	Seed      uint64
	Ratio     int

	Strict eval.ConfusionMatrix
	Broad  eval.ConfusionMatrix

	PrecisionBroad eval.Ratio
	RecallBroad    eval.Ratio
	FPRBroad       eval.Ratio
	FNRBroad       eval.Ratio
	F1Broad        eval.Ratio

	PrecisionStrict eval.Ratio
	RecallStrict    eval.Ratio
	FPRStrict       eval.Ratio

	Actions            ActionDistribution
	FalseChallengeRate eval.Ratio
	FalseBlockRate     eval.Ratio

	CSVectorBroad  eval.AttackVectorRecall
	SSVectorBroad  eval.AttackVectorRecall
	CSVectorStrict eval.AttackVectorRecall
	SSVectorStrict eval.AttackVectorRecall
}

// ComputePolicySweepRow arma la fila de un candidato/seed/ratio a
// partir de result (de RunResultWithPolicy) y scenario (el MISMO que
// produjo baseDecisions, necesario para cruzar Label con Action y
// para el recall STRICT por vector, que internal/eval.Evaluate no
// expone).
func ComputePolicySweepRow(candidateName string, scenario datagen.Scenario, result RunResult) (PolicySweepRow, error) {
	row := PolicySweepRow{Candidate: candidateName, Seed: result.Seed, Ratio: result.Ratio}

	row.Strict = result.Eval.Strict.Matrix
	row.Broad = result.Eval.Broad.Matrix

	row.PrecisionBroad = result.Eval.Broad.Metrics.Precision
	row.RecallBroad = result.Eval.Broad.Metrics.Recall
	row.FPRBroad = result.Eval.Broad.Metrics.FPR
	row.FNRBroad = result.Eval.Broad.Metrics.FNR
	row.F1Broad = result.Eval.Broad.Metrics.F1

	row.PrecisionStrict = result.Eval.Strict.Metrics.Precision
	row.RecallStrict = result.Eval.Strict.Metrics.Recall
	row.FPRStrict = result.Eval.Strict.Metrics.FPR

	actions, err := ComputeActionDistribution(scenario.Events, result.Decisions)
	if err != nil {
		return PolicySweepRow{}, err
	}
	row.Actions = actions
	row.FalseChallengeRate = actions.FalseChallengeRate()
	row.FalseBlockRate = actions.FalseBlockRate()

	row.CSVectorBroad = findVectorRecall(result.Eval.ByAttackVector, groundtruth.LabelCredentialStuffing)
	row.SSVectorBroad = findVectorRecall(result.Eval.ByAttackVector, groundtruth.LabelSlowScan)

	strictVec := strictByAttackVector(scenario, result.Decisions)
	row.CSVectorStrict = findVectorRecall(strictVec, groundtruth.LabelCredentialStuffing)
	row.SSVectorStrict = findVectorRecall(strictVec, groundtruth.LabelSlowScan)

	return row, nil
}

// pooledVectorRecall suma TruePositives/FalseNegatives de varios
// AttackVectorRecall del MISMO vector (uno por seed) y recalcula
// Recall sobre esa suma — nunca promedia Recalls ya calculados por
// separado (mismo criterio "pooled" que el resto de la validación de
// la detector layer).
func pooledVectorRecall(items []eval.AttackVectorRecall) eval.AttackVectorRecall {
	if len(items) == 0 {
		return eval.AttackVectorRecall{}
	}
	var tp, fn int
	for _, a := range items {
		tp += a.TruePositives
		fn += a.FalseNegatives
	}
	return eval.AttackVectorRecall{
		Vector:         items[0].Vector,
		TruePositives:  tp,
		FalseNegatives: fn,
		Recall:         ratioOf(tp, tp+fn),
	}
}

func findVectorRecall(items []eval.AttackVectorRecall, vector groundtruth.Label) eval.AttackVectorRecall {
	for _, a := range items {
		if a.Vector == vector {
			return a
		}
	}
	return eval.AttackVectorRecall{Vector: vector}
}

// AggregatePolicySweepRows agrupa varias filas del MISMO
// candidato/ratio (una por seed) sumando sus matrices de confusión y
// ActionDistribution CRUDAS (pooled, nunca promedio de ratios ya
// calculados) y recalculando las métricas derivadas sobre esos
// totales — mismo criterio que AggregateDetectorLayerRows.
func AggregatePolicySweepRows(rows []PolicySweepRow) PolicySweepRow {
	if len(rows) == 0 {
		return PolicySweepRow{}
	}
	agg := PolicySweepRow{Candidate: rows[0].Candidate, Ratio: rows[0].Ratio}

	var strictMatrices, broadMatrices []eval.ConfusionMatrix
	var actions []ActionDistribution
	var csBroad, ssBroad, csStrict, ssStrict []eval.AttackVectorRecall
	for _, r := range rows {
		strictMatrices = append(strictMatrices, r.Strict)
		broadMatrices = append(broadMatrices, r.Broad)
		actions = append(actions, r.Actions)
		csBroad = append(csBroad, r.CSVectorBroad)
		ssBroad = append(ssBroad, r.SSVectorBroad)
		csStrict = append(csStrict, r.CSVectorStrict)
		ssStrict = append(ssStrict, r.SSVectorStrict)
	}

	agg.Strict = sumMatrix(strictMatrices)
	agg.Broad = sumMatrix(broadMatrices)

	broadMetrics := agg.Broad.Metrics()
	agg.PrecisionBroad = broadMetrics.Precision
	agg.RecallBroad = broadMetrics.Recall
	agg.FPRBroad = broadMetrics.FPR
	agg.FNRBroad = broadMetrics.FNR
	agg.F1Broad = broadMetrics.F1

	strictMetrics := agg.Strict.Metrics()
	agg.PrecisionStrict = strictMetrics.Precision
	agg.RecallStrict = strictMetrics.Recall
	agg.FPRStrict = strictMetrics.FPR

	agg.Actions = SumActionDistribution(actions)
	agg.FalseChallengeRate = agg.Actions.FalseChallengeRate()
	agg.FalseBlockRate = agg.Actions.FalseBlockRate()

	agg.CSVectorBroad = pooledVectorRecall(csBroad)
	agg.SSVectorBroad = pooledVectorRecall(ssBroad)
	agg.CSVectorStrict = pooledVectorRecall(csStrict)
	agg.SSVectorStrict = pooledVectorRecall(ssStrict)

	return agg
}

// PolicySweepStability resume, para UN candidato de Policy y UN
// ratio, cuánto varían BroadRecall/StrictRecall/FPRBroad entre los 3
// seeds — un Range grande (max-min) es evidencia directa de
// inestabilidad, mismo criterio cualitativo ya usado para descartar
// candidatos inestables en el sweep de detectores.
type PolicySweepStability struct {
	Candidate string
	Ratio     int

	BroadRecallRange  float64
	StrictRecallRange float64
	FPRBroadRange     float64
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

// ComputePolicySweepStability calcula el Range de cada métrica entre
// rows — que deben ser todas del MISMO candidato/ratio, una por seed.
// Ignora seeds donde la métrica sea N/A (no hay positivos reales en
// ese seed/ratio para esa métrica), nunca los trata como 0.
func ComputePolicySweepStability(rows []PolicySweepRow) PolicySweepStability {
	if len(rows) == 0 {
		return PolicySweepStability{}
	}
	s := PolicySweepStability{Candidate: rows[0].Candidate, Ratio: rows[0].Ratio}

	definedValues := func(f func(PolicySweepRow) eval.Ratio) []float64 {
		var vs []float64
		for _, r := range rows {
			if v := f(r); v.Defined {
				vs = append(vs, v.Value)
			}
		}
		return vs
	}

	s.BroadRecallRange = rangeOf(definedValues(func(r PolicySweepRow) eval.Ratio { return r.RecallBroad }))
	s.StrictRecallRange = rangeOf(definedValues(func(r PolicySweepRow) eval.Ratio { return r.RecallStrict }))
	s.FPRBroadRange = rangeOf(definedValues(func(r PolicySweepRow) eval.Ratio { return r.FPRBroad }))

	return s
}
