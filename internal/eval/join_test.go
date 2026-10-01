// Prueba el join entre etiquetas y decisiones y la detección de problemas.
package eval

import (
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func fakeDecision(requestID string, action decision.Action) decision.Decision {
	return decision.Decision{
		RequestID: requestID,
		Timestamp: time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC),
		EntityID:  "ip:203.0.113.7",
		Action:    action,
	}
}

func TestJoin_MixOfProblems(t *testing.T) {
	labels := map[string]groundtruth.Label{
		"r-1": groundtruth.LabelLegit,
		"r-2": groundtruth.LabelCredentialStuffing,
		"r-3": groundtruth.LabelSlowScan,
		"r-4": groundtruth.LabelLegit,
	}
	decisions := []decision.Decision{
		fakeDecision("r-1", decision.ActionAllow),
		fakeDecision("r-2", decision.ActionBlock),
		fakeDecision("r-2", decision.ActionAllow),
		fakeDecision("r-3", decision.ActionChallenge),
		fakeDecision("r-5", decision.ActionBlock),
	}

	joined, issues := Join(labels, Issues{}, decisions)

	if len(joined) != 3 {
		t.Fatalf("joined has %d records, want 3: %+v", len(joined), joined)
	}
	wantIDs := []string{"r-1", "r-2", "r-3"}
	for i, want := range wantIDs {
		if joined[i].RequestID != want {
			t.Errorf("joined[%d].RequestID = %q, want %q", i, joined[i].RequestID, want)
		}
	}
	if joined[1].Decision.Action != decision.ActionBlock {
		t.Errorf("joined record for r-2 has action %q, want BLOCK (the first one seen)", joined[1].Decision.Action)
	}

	if len(issues.DuplicateDecisionIDs) != 1 || issues.DuplicateDecisionIDs[0] != "r-2" {
		t.Errorf("DuplicateDecisionIDs = %v, want [r-2]", issues.DuplicateDecisionIDs)
	}
	if len(issues.MissingDecisionIDs) != 1 || issues.MissingDecisionIDs[0] != "r-4" {
		t.Errorf("MissingDecisionIDs = %v, want [r-4]", issues.MissingDecisionIDs)
	}
	if len(issues.ExtraDecisionIDs) != 1 || issues.ExtraDecisionIDs[0] != "r-5" {
		t.Errorf("ExtraDecisionIDs = %v, want [r-5]", issues.ExtraDecisionIDs)
	}

	if issues.Clean() {
		t.Error("Issues.Clean() = true, want false (this dataset has problems)")
	}
}

func TestJoin_NoProblems_IsClean(t *testing.T) {
	labels := map[string]groundtruth.Label{
		"r-1": groundtruth.LabelLegit,
		"r-2": groundtruth.LabelSlowScan,
	}
	decisions := []decision.Decision{
		fakeDecision("r-1", decision.ActionAllow),
		fakeDecision("r-2", decision.ActionBlock),
	}

	joined, issues := Join(labels, Issues{}, decisions)

	if len(joined) != 2 {
		t.Fatalf("joined has %d records, want 2", len(joined))
	}
	if !issues.Clean() {
		t.Errorf("Issues.Clean() = false, want true: %+v", issues)
	}
}

func TestJoin_CarriesBaseIssuesFromLabelLoading(t *testing.T) {
	base := Issues{
		DuplicateLabelIDs: []string{"r-9"},
		UnknownLabelIDs:   []string{"r-10"},
	}
	labels := map[string]groundtruth.Label{"r-1": groundtruth.LabelLegit}
	decisions := []decision.Decision{fakeDecision("r-1", decision.ActionAllow)}

	_, issues := Join(labels, base, decisions)

	if len(issues.DuplicateLabelIDs) != 1 || issues.DuplicateLabelIDs[0] != "r-9" {
		t.Errorf("DuplicateLabelIDs = %v, want [r-9]", issues.DuplicateLabelIDs)
	}
	if len(issues.UnknownLabelIDs) != 1 || issues.UnknownLabelIDs[0] != "r-10" {
		t.Errorf("UnknownLabelIDs = %v, want [r-10]", issues.UnknownLabelIDs)
	}
	if issues.Clean() {
		t.Error("Issues.Clean() = true, want false (base issues carried over)")
	}
}
