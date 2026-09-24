package eval

import (
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func fakeDecisionWithVector(requestID string, action decision.Action, vector decision.AttackVector) decision.Decision {
	d := fakeDecision(requestID, action)
	d.AttackVector = vector
	return d
}

// buildVectorTestRecords arma, a mano, siete registros que cubren cada
// combinación que importa:
//
//	r-1  credential_stuffing  BLOCK      vector=credential_stuffing  -> TP, atribución correcta
//	r-2  credential_stuffing  ALLOW      -                           -> FN (no cuenta para atribución)
//	r-3  credential_stuffing  CHALLENGE  vector=unknown              -> TP, atribución desconocida
//	r-4  credential_stuffing  BLOCK      vector=slow_scan            -> TP, atribución incorrecta
//	r-5  slow_scan            BLOCK      vector=slow_scan            -> TP, atribución correcta
//	r-6  slow_scan            ALLOW      -                           -> FN (no cuenta para atribución)
//	r-7  legit                BLOCK      vector=credential_stuffing  -> FP (no cuenta para atribución: no hay ataque real)
func buildVectorTestRecords() []JoinedRecord {
	return []JoinedRecord{
		{RequestID: "r-1", Label: groundtruth.LabelCredentialStuffing, Decision: fakeDecisionWithVector("r-1", decision.ActionBlock, decision.AttackVectorCredentialStuffing)},
		{RequestID: "r-2", Label: groundtruth.LabelCredentialStuffing, Decision: fakeDecision("r-2", decision.ActionAllow)},
		{RequestID: "r-3", Label: groundtruth.LabelCredentialStuffing, Decision: fakeDecisionWithVector("r-3", decision.ActionChallenge, decision.AttackVectorUnknown)},
		{RequestID: "r-4", Label: groundtruth.LabelCredentialStuffing, Decision: fakeDecisionWithVector("r-4", decision.ActionBlock, decision.AttackVectorSlowScan)},
		{RequestID: "r-5", Label: groundtruth.LabelSlowScan, Decision: fakeDecisionWithVector("r-5", decision.ActionBlock, decision.AttackVectorSlowScan)},
		{RequestID: "r-6", Label: groundtruth.LabelSlowScan, Decision: fakeDecision("r-6", decision.ActionAllow)},
		{RequestID: "r-7", Label: groundtruth.LabelLegit, Decision: fakeDecisionWithVector("r-7", decision.ActionBlock, decision.AttackVectorCredentialStuffing)},
	}
}

// TestByAttackVectorRecall_HandComputed:
//
//	credential_stuffing: TP=3 (r-1,r-3,r-4), FN=1 (r-2) -> recall = 3/4 = 0.75
//	slow_scan:            TP=1 (r-5),         FN=1 (r-6) -> recall = 1/2 = 0.5
func TestByAttackVectorRecall_HandComputed(t *testing.T) {
	results := ByAttackVectorRecall(buildVectorTestRecords(), PolicyBroad)

	byVector := make(map[groundtruth.Label]AttackVectorRecall, len(results))
	for _, r := range results {
		byVector[r.Vector] = r
	}

	stuffing := byVector[groundtruth.LabelCredentialStuffing]
	if stuffing.TruePositives != 3 || stuffing.FalseNegatives != 1 {
		t.Fatalf("credential_stuffing: TP=%d FN=%d, want TP=3 FN=1", stuffing.TruePositives, stuffing.FalseNegatives)
	}
	checkRatio(t, "credential_stuffing recall", stuffing.Recall, true, 0.75)

	scan := byVector[groundtruth.LabelSlowScan]
	if scan.TruePositives != 1 || scan.FalseNegatives != 1 {
		t.Fatalf("slow_scan: TP=%d FN=%d, want TP=1 FN=1", scan.TruePositives, scan.FalseNegatives)
	}
	checkRatio(t, "slow_scan recall", scan.Recall, true, 0.5)
}

// TestEvaluateVectorAttribution_HandComputed:
//
//	Correct   = 2  (r-1, r-5)
//	Unknown   = 1  (r-3)
//	Incorrect = 1  (r-4)
//	r-2, r-6 (falsos negativos) y r-7 (falso positivo) no cuentan para nada acá.
//	Accuracy = Correct / (Correct + Incorrect) = 2 / 3
func TestEvaluateVectorAttribution_HandComputed(t *testing.T) {
	got := EvaluateVectorAttribution(buildVectorTestRecords())

	if got.Correct != 2 {
		t.Errorf("Correct = %d, want 2", got.Correct)
	}
	if got.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", got.Unknown)
	}
	if got.Incorrect != 1 {
		t.Errorf("Incorrect = %d, want 1", got.Incorrect)
	}
	checkRatio(t, "Accuracy", got.Accuracy(), true, 2.0/3.0)
}

// TestEvaluateVectorAttribution_AllUnknown_AccuracyIsNotAvailable
// comprueba el caso límite: si un motor siempre responde "unknown", no
// hay ningún "correcto" ni "incorrecto" para dividir — la precisión de
// atribución tiene que ser N/A, no 0%.
func TestEvaluateVectorAttribution_AllUnknown_AccuracyIsNotAvailable(t *testing.T) {
	records := []JoinedRecord{
		{RequestID: "r-1", Label: groundtruth.LabelCredentialStuffing, Decision: fakeDecisionWithVector("r-1", decision.ActionBlock, decision.AttackVectorUnknown)},
	}
	got := EvaluateVectorAttribution(records)

	if got.Correct != 0 || got.Incorrect != 0 || got.Unknown != 1 {
		t.Fatalf("got %+v, want Correct=0 Incorrect=0 Unknown=1", got)
	}
	checkRatio(t, "Accuracy", got.Accuracy(), false, 0)
}
