package tuning

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// TestRunResultWithPolicy_SamePolicy_MatchesFullRun es el test
// central de esta optimización: reaplicar LA MISMA Policy que ya
// produjo baseDecisions, sin volver a correr
// ningún detector, tiene que dar EXACTAMENTE el mismo Eval y Delay que
// una corrida completa con RunScenario — si esto no fuera cierto, el
// sweep de Policy estaría comparando candidatos con una métrica
// distinta a la que produciría el motor real.
func TestRunResultWithPolicy_SamePolicy_MatchesFullRun(t *testing.T) {
	scenario := datagen.BuildScenario(datagen.DefaultScenarioConfig(555, 0.10))
	resolver := datagen.NewSimulatedASNResolver()
	candidate := BaselineCandidate() // Policy = engine.DefaultPolicy() = {0.5, 0.8}

	full, err := RunScenario(scenario, candidate, resolver)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}

	reapplied := RunResultWithPolicy(scenario, full.Decisions, resolver, candidate.Name, candidate.Policy)

	for i := range full.Decisions {
		if full.Decisions[i].Action != reapplied.Decisions[i].Action {
			t.Fatalf("decision %d: Action = %v, want %v (misma Policy, tiene que coincidir)", i, reapplied.Decisions[i].Action, full.Decisions[i].Action)
		}
	}
	if !reflect.DeepEqual(full.Eval, reapplied.Eval) {
		t.Error("Eval no coincide al reaplicar la MISMA Policy — la optimización de no re-correr detectores rompería el sweep")
	}
	if !reflect.DeepEqual(full.Delay, reapplied.Delay) {
		t.Error("Delay no coincide al reaplicar la MISMA Policy")
	}
}

// TestReapplyPolicy_KeepsEvidenceChangesOnlyAction confirma que
// ReapplyPolicy nunca toca ConfidenceScore/AttackVector/EntityID —
// solo Action — y que una Policy más permisiva (ChallengeThreshold
// más bajo) nunca puede producir MENOS CHALLENGE+BLOCK que la
// original sobre el mismo ConfidenceScore.
func TestReapplyPolicy_KeepsEvidenceChangesOnlyAction(t *testing.T) {
	original := []decision.Decision{
		{RequestID: "r-1", ConfidenceScore: 0.55, AttackVector: decision.AttackVectorCredentialStuffing, EntityID: "network:asn:1", Action: decision.ActionAllow},
		{RequestID: "r-2", ConfidenceScore: 0.0, AttackVector: decision.AttackVectorUnknown, EntityID: "ip:192.0.2.1", Action: decision.ActionAllow},
	}
	stricter := engine.Policy{ChallengeThreshold: 0.5, BlockThreshold: 0.8}
	got := ReapplyPolicy(original, stricter)

	if got[0].Action != decision.ActionChallenge {
		t.Errorf("r-1 Action = %v, want CHALLENGE (0.55 >= 0.5)", got[0].Action)
	}
	if got[1].Action != decision.ActionAllow {
		t.Errorf("r-2 Action = %v, want ALLOW (score 0, ningún detector disparó)", got[1].Action)
	}
	for i := range original {
		if got[i].ConfidenceScore != original[i].ConfidenceScore || got[i].AttackVector != original[i].AttackVector || got[i].EntityID != original[i].EntityID || got[i].RequestID != original[i].RequestID {
			t.Errorf("decision %d: la evidencia cruda cambió, want solo Action distinto", i)
		}
	}
}

func TestComputeActionDistribution_SplitsLegitVsMaliciousByAction(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	events := []groundtruth.LabeledEvent{
		labeledEvent(groundtruth.LabelLegit, "r-1", 0, ip, "/", 200),
		labeledEvent(groundtruth.LabelLegit, "r-2", time.Minute, ip, "/", 200),
		labeledEvent(groundtruth.LabelLegit, "r-3", 2*time.Minute, ip, "/", 200),
		labeledEvent(groundtruth.LabelCredentialStuffing, "r-4", 3*time.Minute, ip, "/login", 401),
		labeledEvent(groundtruth.LabelCredentialStuffing, "r-5", 4*time.Minute, ip, "/login", 401),
		labeledEvent(groundtruth.LabelCredentialStuffing, "r-6", 5*time.Minute, ip, "/login", 401),
	}
	decisions := []decision.Decision{
		{Action: decision.ActionAllow},
		{Action: decision.ActionChallenge},
		{Action: decision.ActionBlock},
		{Action: decision.ActionAllow},
		{Action: decision.ActionBlock},
		{Action: decision.ActionBlock},
	}

	d, err := ComputeActionDistribution(events, decisions)
	if err != nil {
		t.Fatalf("ComputeActionDistribution: %v", err)
	}
	if d.LegitAllow != 1 || d.LegitChallenge != 1 || d.LegitBlock != 1 {
		t.Errorf("legit = %+v, want 1/1/1", d)
	}
	if d.MaliciousAllow != 1 || d.MaliciousBlock != 2 {
		t.Errorf("malicious = %+v, want Allow=1 Block=2", d)
	}
	if fcr := d.FalseChallengeRate(); !fcr.Defined || fcr.Value != 1.0/3.0 {
		t.Errorf("FalseChallengeRate = %+v, want {0.333, true}", fcr)
	}
	if fbr := d.FalseBlockRate(); !fbr.Defined || fbr.Value != 1.0/3.0 {
		t.Errorf("FalseBlockRate = %+v, want {0.333, true}", fbr)
	}
}

func TestComputeActionDistribution_LengthMismatch_ReturnsError(t *testing.T) {
	_, err := ComputeActionDistribution([]groundtruth.LabeledEvent{{}}, []decision.Decision{{}, {}})
	if err == nil {
		t.Fatal("error = nil, want un error por longitudes distintas")
	}
}
