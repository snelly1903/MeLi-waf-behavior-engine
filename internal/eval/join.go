// Une etiquetas y decisiones por request_id y registra los problemas de datos.
package eval

import (
	"sort"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type JoinedRecord struct {
	RequestID string
	Label     groundtruth.Label
	Decision  decision.Decision
}

type Issues struct {
	DuplicateLabelIDs []string
	UnknownLabelIDs   []string

	DuplicateDecisionIDs []string

	MissingDecisionIDs []string

	ExtraDecisionIDs []string

	InvalidDecisionIDs []string

	CorruptDecisionLines []int
}

func (i Issues) Clean() bool {
	return len(i.DuplicateLabelIDs) == 0 &&
		len(i.UnknownLabelIDs) == 0 &&
		len(i.DuplicateDecisionIDs) == 0 &&
		len(i.MissingDecisionIDs) == 0 &&
		len(i.ExtraDecisionIDs) == 0 &&
		len(i.InvalidDecisionIDs) == 0 &&
		len(i.CorruptDecisionLines) == 0
}

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

	sort.Strings(issues.MissingDecisionIDs)
	sort.Strings(issues.ExtraDecisionIDs)
	sort.Slice(joined, func(i, j int) bool { return joined[i].RequestID < joined[j].RequestID })

	return joined, issues
}
