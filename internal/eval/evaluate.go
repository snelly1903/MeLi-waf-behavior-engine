package eval

import "github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"

// PolicyResult junta la matriz de confusión de una política con sus
// métricas derivadas.
type PolicyResult struct {
	Matrix  ConfusionMatrix
	Metrics Metrics
}

type Result struct {
	Strict PolicyResult
	Broad  PolicyResult

	ByAttackVector []AttackVectorRecall

	VectorAttribution VectorAttribution

	Issues Issues

	TotalJoined int
}

func Evaluate(labelsResult LoadLabelsResult, decisions []decision.Decision) Result {
	baseIssues := Issues{
		DuplicateLabelIDs: labelsResult.DuplicateIDs,
		UnknownLabelIDs:   labelsResult.UnknownLabelIDs,
	}
	joined, issues := Join(labelsResult.Labels, baseIssues, decisions)

	strictMatrix := BuildConfusionMatrix(joined, PolicyStrict)
	broadMatrix := BuildConfusionMatrix(joined, PolicyBroad)

	return Result{
		Strict:            PolicyResult{Matrix: strictMatrix, Metrics: strictMatrix.Metrics()},
		Broad:             PolicyResult{Matrix: broadMatrix, Metrics: broadMatrix.Metrics()},
		ByAttackVector:    ByAttackVectorRecall(joined, PolicyBroad),
		VectorAttribution: EvaluateVectorAttribution(joined),
		Issues:            issues,
		TotalJoined:       len(joined),
	}
}

func EvaluateDecisions(labelsResult LoadLabelsResult, decisionsResult LoadDecisionsResult) Result {
	result := Evaluate(labelsResult, decisionsResult.Decisions)

	result.Issues.InvalidDecisionIDs = decisionsResult.InvalidIDs
	result.Issues.CorruptDecisionLines = decisionsResult.CorruptLines
	result.Issues.MissingDecisionIDs = removeIDs(result.Issues.MissingDecisionIDs, decisionsResult.InvalidIDs)

	return result
}

func removeIDs(ids []string, exclude []string) []string {
	if len(exclude) == 0 {
		return ids
	}
	excluded := make(map[string]bool, len(exclude))
	for _, id := range exclude {
		excluded[id] = true
	}
	var kept []string
	for _, id := range ids {
		if !excluded[id] {
			kept = append(kept, id)
		}
	}
	return kept
}
