package eval

import (
	"strings"
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

func smallCleanResult() Result {
	matrix := ConfusionMatrix{TP: 1, FP: 0, FN: 0, TN: 1}
	pr := PolicyResult{Matrix: matrix, Metrics: matrix.Metrics()}
	return Result{
		Strict: pr,
		Broad:  pr,
		ByAttackVector: []AttackVectorRecall{
			{Vector: groundtruth.LabelCredentialStuffing, TruePositives: 1, FalseNegatives: 0, Recall: Ratio{Value: 1, Defined: true}},
			{Vector: groundtruth.LabelSlowScan, TruePositives: 0, FalseNegatives: 0, Recall: Ratio{Defined: false}},
		},
		VectorAttribution: VectorAttribution{Correct: 1, Unknown: 0, Incorrect: 0},
		Issues:            Issues{},
		TotalJoined:       2,
	}
}

func TestRenderMarkdown_CleanResult_NoWarning(t *testing.T) {
	report := RenderMarkdown(smallCleanResult(), ReportMeta{ScenarioName: "scenario-test", ExpectedRecords: 2})

	if strings.Contains(report, "problemas de integridad") {
		t.Error("clean report must not contain the integrity warning")
	}
	if !strings.Contains(report, "# Reporte de evaluación — scenario-test") {
		t.Error("report is missing the scenario title")
	}
	if !strings.Contains(report, "Registros cruzados: 2 de 2 esperados.") {
		t.Error("report is missing the expected-vs-joined line")
	}
	if !strings.Contains(report, "credential_stuffing | 1 | 0 | 1.000") {
		t.Error("report is missing the credential_stuffing recall row")
	}
	// slow_scan no tuvo ningún registro real: su Recall es N/A, no 0.
	if !strings.Contains(report, "slow_scan | 0 | 0 | N/A") {
		t.Error("report must show N/A for slow_scan recall, not 0.000")
	}
	if !strings.Contains(report, "Correcto: 1, Desconocido: 0, Incorrecto: 0 — Accuracy: 1.000") {
		t.Error("report is missing the vector attribution line")
	}
}

func TestRenderMarkdown_DirtyResult_ShowsWarningAndLists(t *testing.T) {
	result := smallCleanResult()
	result.Issues = Issues{
		MissingDecisionIDs:   []string{"r-4"},
		InvalidDecisionIDs:   []string{"r-9"},
		CorruptDecisionLines: []int{7},
	}

	report := RenderMarkdown(result, ReportMeta{ScenarioName: "scenario-test", ExpectedRecords: 4})

	if !strings.Contains(report, "⚠️") {
		t.Error("dirty report must open with the integrity warning")
	}
	if !strings.Contains(report, "NO debe leerse como definitivo") {
		t.Error("dirty report must state explicitly that it is not a definitive result")
	}
	if !strings.Contains(report, "Decisiones faltantes: r-4") {
		t.Error("report is missing MissingDecisionIDs")
	}
	if !strings.Contains(report, "Decisiones inválidas (no pasan decision.Validate): r-9") {
		t.Error("report is missing InvalidDecisionIDs")
	}
	if !strings.Contains(report, "Líneas de decisions.jsonl no interpretables: 7") {
		t.Error("report is missing CorruptDecisionLines")
	}
	// El bloque de advertencia tiene que aparecer ANTES de los números.
	warnIdx := strings.Index(report, "⚠️")
	policyIdx := strings.Index(report, "Política estricta")
	if warnIdx == -1 || policyIdx == -1 || warnIdx > policyIdx {
		t.Error("the warning must appear before the policy sections")
	}
}

// TestRenderMarkdown_AllZeroMatrix_EverythingIsNA confirma que un
// escenario 0%-malicioso (sin ningún positivo real ni predicho) no
// disfraza el N/A con ceros en el texto del reporte.
func TestRenderMarkdown_AllZeroMatrix_EverythingIsNA(t *testing.T) {
	empty := ConfusionMatrix{}
	pr := PolicyResult{Matrix: empty, Metrics: empty.Metrics()}
	result := Result{Strict: pr, Broad: pr, VectorAttribution: VectorAttribution{}}

	report := RenderMarkdown(result, ReportMeta{ScenarioName: "scenario-0", ExpectedRecords: 0})

	if strings.Count(report, "| N/A |") < 5 {
		t.Errorf("expected every metric to render as N/A, got:\n%s", report)
	}
}
