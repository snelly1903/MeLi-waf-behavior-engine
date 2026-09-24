package eval

import (
	"sort"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// JoinedRecord es un par etiqueta+decisión ya cruzado por request_id —
// la unidad básica sobre la que se calculan todas las métricas.
type JoinedRecord struct {
	RequestID string
	Label     groundtruth.Label
	Decision  decision.Decision
}

// Issues resume todos los problemas de integridad encontrados al
// cargar las etiquetas y al cruzarlas con las decisiones. Ninguno de
// estos problemas frena el cálculo de métricas — pero su presencia
// significa que el resultado es un diagnóstico parcial, no un
// resultado definitivo (ver docs/decisiones.md, tarea 0.7).
type Issues struct {
	// DuplicateLabelIDs y UnknownLabelIDs vienen tal cual de LoadLabels.
	DuplicateLabelIDs []string
	UnknownLabelIDs   []string

	// DuplicateDecisionIDs: el mismo request_id aparece más de una vez
	// entre las decisiones recibidas.
	DuplicateDecisionIDs []string

	// MissingDecisionIDs: tiene etiqueta pero ninguna decisión — el
	// motor nunca se pronunció sobre este evento. Se excluye del
	// cálculo de métricas (no se puede contar una acción que no
	// existe).
	MissingDecisionIDs []string

	// ExtraDecisionIDs: tiene decisión pero ninguna etiqueta — típico
	// de estar evaluando contra el dataset equivocado. También se
	// excluye del cálculo.
	ExtraDecisionIDs []string

	// InvalidDecisionIDs: la decisión tiene un request_id utilizable
	// pero no pasa decision.Validate() (por ejemplo, un BLOCK sin
	// Explanation). Viene de LoadDecisions (tarea 0.8) y, al igual que
	// las demás listas de esta struct, se excluye del cálculo de
	// métricas — una decisión inválida nunca se convierte
	// silenciosamente en un ALLOW.
	InvalidDecisionIDs []string

	// CorruptDecisionLines: números de línea (1-indexado) de
	// decisions.jsonl que no se pudieron interpretar en absoluto — ni
	// como JSON válido, ni con un request_id utilizable para
	// identificarlas de otra forma. Viene de LoadDecisions.
	CorruptDecisionLines []int
}

// Clean informa si no se encontró ningún problema de integridad. Si es
// false, el resultado de la evaluación tiene que tratarse como
// diagnóstico parcial — nunca como un resultado definitivo (ver
// docs/decisiones.md).
func (i Issues) Clean() bool {
	return len(i.DuplicateLabelIDs) == 0 &&
		len(i.UnknownLabelIDs) == 0 &&
		len(i.DuplicateDecisionIDs) == 0 &&
		len(i.MissingDecisionIDs) == 0 &&
		len(i.ExtraDecisionIDs) == 0 &&
		len(i.InvalidDecisionIDs) == 0 &&
		len(i.CorruptDecisionLines) == 0
}

// Join cruza labels (ya cargadas, por ejemplo con LoadLabels) con
// decisions, por request_id. baseIssues arrastra los problemas que ya
// traía la carga de etiquetas (duplicados, desconocidas), para que
// Issues quede completo en un solo lugar.
//
// Devuelve los pares que se pudieron cruzar sin ambigüedad, y por
// separado, todos los problemas encontrados — nunca deja que un
// problema silencioso se cuele en el cálculo de métricas.
func Join(labels map[string]groundtruth.Label, baseIssues Issues, decisions []decision.Decision) ([]JoinedRecord, Issues) {
	issues := baseIssues

	decisionByID := make(map[string]decision.Decision, len(decisions))
	seenDecisionIDs := make(map[string]bool, len(decisions))
	for _, d := range decisions {
		if seenDecisionIDs[d.RequestID] {
			issues.DuplicateDecisionIDs = append(issues.DuplicateDecisionIDs, d.RequestID)
			continue
		}
		seenDecisionIDs[d.RequestID] = true
		decisionByID[d.RequestID] = d
	}

	var joined []JoinedRecord
	matchedIDs := make(map[string]bool, len(labels))
	for id, label := range labels {
		d, ok := decisionByID[id]
		if !ok {
			issues.MissingDecisionIDs = append(issues.MissingDecisionIDs, id)
			continue
		}
		matchedIDs[id] = true
		joined = append(joined, JoinedRecord{RequestID: id, Label: label, Decision: d})
	}

	for id := range decisionByID {
		if matchedIDs[id] {
			continue
		}
		if _, hadLabel := labels[id]; !hadLabel {
			issues.ExtraDecisionIDs = append(issues.ExtraDecisionIDs, id)
		}
	}

	// labels y decisionByID son maps: su orden de iteración no está
	// garantizado en Go. Se ordena acá para que el resultado sea
	// determinista y los tests puedan comparar listas exactas, no
	// solo conjuntos.
	sort.Strings(issues.MissingDecisionIDs)
	sort.Strings(issues.ExtraDecisionIDs)
	sort.Slice(joined, func(i, j int) bool { return joined[i].RequestID < joined[j].RequestID })

	return joined, issues
}
