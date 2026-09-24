package eval

import "github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"

// PolicyResult junta la matriz de confusión de una política con sus
// métricas derivadas.
type PolicyResult struct {
	Matrix  ConfusionMatrix
	Metrics Metrics
}

// Result es el resultado completo de evaluar un conjunto de decisiones
// contra su ground truth. Result.Issues.Clean() dice si el resultado es
// íntegro o solo un diagnóstico parcial (ver docs/decisiones.md, tarea
// 0.7) — quien lea este resultado tiene que comprobarlo antes de
// tratarlo como definitivo, nunca asumirlo.
type Result struct {
	// Strict y Broad son las dos políticas de evaluación — ver
	// metrics.go.
	Strict PolicyResult
	Broad  PolicyResult

	// ByAttackVector es el recall separado de credential_stuffing y de
	// slow_scan, calculado con la política amplia.
	ByAttackVector []AttackVectorRecall

	// VectorAttribution resume si, entre los verdaderos positivos, el
	// motor supo decir de qué ataque se trataba.
	VectorAttribution VectorAttribution

	// Issues son todos los problemas de integridad encontrados al
	// cargar y cruzar los datos.
	Issues Issues

	// TotalJoined es cuántos pares etiqueta+decisión se pudieron cruzar
	// sin ambigüedad — la base real sobre la que se calcularon Strict y
	// Broad.
	TotalJoined int
}

// Evaluate cruza las etiquetas ya cargadas (por ejemplo, con
// LoadLabels) con decisions — en memoria, sin leer ningún archivo de
// decisiones todavía (eso queda para cmd/eval, tarea 0.8) — y calcula
// el resultado completo.
//
// Evaluate nunca falla por problemas de integridad de datos: los
// reporta en Result.Issues y calcula las métricas con lo que sí pudo
// cruzar sin ambigüedad. Esas métricas parciales sirven para
// diagnóstico (por ejemplo, para ver rápido si un motor con bugs está
// perdiendo eventos), pero NO deben leerse como un resultado
// definitivo mientras Result.Issues.Clean() sea false.
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

// EvaluateDecisions es la puerta de entrada que usa cmd/eval (tarea
// 0.8): igual que Evaluate, pero a partir de un LoadDecisionsResult
// (ver decisions.go) en lugar de un []decision.Decision ya limpio. No
// duplica ningún cálculo de métricas — llama a Evaluate con las
// decisiones utilizables y después le agrega a Issues los problemas
// que ya traía la carga del archivo (JSON corrupto, decisiones que no
// pasan decision.Validate()).
//
// Un request_id cuya única decisión fue inválida aparecería, si no se
// corrigiera nada más, tanto en InvalidDecisionIDs como en
// MissingDecisionIDs (Join no tiene forma de saber que la decisión
// "faltante" en realidad existía pero fue rechazada). Para no reportar
// el mismo problema dos veces con dos nombres distintos, se lo deja
// solamente en InvalidDecisionIDs, que es el diagnóstico más preciso.
func EvaluateDecisions(labelsResult LoadLabelsResult, decisionsResult LoadDecisionsResult) Result {
	result := Evaluate(labelsResult, decisionsResult.Decisions)

	result.Issues.InvalidDecisionIDs = decisionsResult.InvalidIDs
	result.Issues.CorruptDecisionLines = decisionsResult.CorruptLines
	result.Issues.MissingDecisionIDs = removeIDs(result.Issues.MissingDecisionIDs, decisionsResult.InvalidIDs)

	return result
}

// removeIDs devuelve ids sin los elementos presentes en exclude. No
// modifica ids en el lugar.
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
