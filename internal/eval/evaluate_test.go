package eval

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// --- "Motores" ficticios, solo para probar el evaluador -------------
//
// Nada de esto es el motor real (que no existe todavía): son reglas de
// juguete que existen ÚNICAMENTE en este archivo de test, para
// confirmar que Evaluate calcula bien las métricas antes de usarlo
// contra nada real.

func sortedIDs(labels map[string]groundtruth.Label) []string {
	ids := make([]string, 0, len(labels))
	for id := range labels {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// decideAllowAll deja pasar todo — recall 0% garantizado.
func decideAllowAll(labels map[string]groundtruth.Label) []decision.Decision {
	var out []decision.Decision
	for _, id := range sortedIDs(labels) {
		out = append(out, fakeDecisionWithVector(id, decision.ActionAllow, decision.AttackVectorUnknown))
	}
	return out
}

// decideBlockAll bloquea todo, sin saber nunca de qué se trata — FPR
// 100% garantizado, y atribución de vector siempre "unknown".
func decideBlockAll(labels map[string]groundtruth.Label) []decision.Decision {
	var out []decision.Decision
	for _, id := range sortedIDs(labels) {
		out = append(out, fakeDecisionWithVector(id, decision.ActionBlock, decision.AttackVectorUnknown))
	}
	return out
}

// decidePerfectOracle "adivina" la etiqueta real — sirve solo para
// confirmar que el evaluador, en el mejor caso posible, da 100% en
// todo. Ningún motor real puede hacer esto (necesitaría el ground
// truth, que nunca ve) — es exclusivamente una herramienta de test.
func decidePerfectOracle(labels map[string]groundtruth.Label) []decision.Decision {
	var out []decision.Decision
	for _, id := range sortedIDs(labels) {
		label := labels[id]
		if label == groundtruth.LabelLegit {
			out = append(out, fakeDecisionWithVector(id, decision.ActionAllow, decision.AttackVectorUnknown))
			continue
		}
		out = append(out, fakeDecisionWithVector(id, decision.ActionBlock, decision.AttackVector(label)))
	}
	return out
}

func sampleLabels() map[string]groundtruth.Label {
	return map[string]groundtruth.Label{
		"r-1": groundtruth.LabelLegit,
		"r-2": groundtruth.LabelLegit,
		"r-3": groundtruth.LabelLegit,
		"r-4": groundtruth.LabelCredentialStuffing,
		"r-5": groundtruth.LabelCredentialStuffing,
		"r-6": groundtruth.LabelSlowScan,
		"r-7": groundtruth.LabelSlowScan,
	}
}

func TestEvaluate_AllowAllEngine(t *testing.T) {
	labels := sampleLabels()
	result := Evaluate(LoadLabelsResult{Labels: labels}, decideAllowAll(labels))

	if !result.Issues.Clean() {
		t.Fatalf("Issues not clean: %+v", result.Issues)
	}
	// 3 legit, 4 maliciosos (2 stuffing + 2 scan); "permitir todo"
	// nunca predice positivo: TP=0, FP=0, FN=4, TN=3 — en las dos
	// políticas, porque nunca hay ni BLOCK ni CHALLENGE.
	want := ConfusionMatrix{TP: 0, FP: 0, FN: 4, TN: 3}
	if result.Strict.Matrix != want {
		t.Errorf("strict matrix = %+v, want %+v", result.Strict.Matrix, want)
	}
	if result.Broad.Matrix != want {
		t.Errorf("broad matrix = %+v, want %+v", result.Broad.Matrix, want)
	}
	checkRatio(t, "Recall", result.Broad.Metrics.Recall, true, 0)
	checkRatio(t, "Precision", result.Broad.Metrics.Precision, false, 0)
}

func TestEvaluate_BlockAllEngine(t *testing.T) {
	labels := sampleLabels()
	result := Evaluate(LoadLabelsResult{Labels: labels}, decideBlockAll(labels))

	if !result.Issues.Clean() {
		t.Fatalf("Issues not clean: %+v", result.Issues)
	}
	// "Bloquear todo": TP=4, FP=3, FN=0, TN=0 en ambas políticas
	// (BLOCK ya es positivo en las dos).
	want := ConfusionMatrix{TP: 4, FP: 3, FN: 0, TN: 0}
	if result.Strict.Matrix != want {
		t.Errorf("strict matrix = %+v, want %+v", result.Strict.Matrix, want)
	}
	checkRatio(t, "Precision", result.Strict.Metrics.Precision, true, 4.0/7.0)
	checkRatio(t, "Recall", result.Strict.Metrics.Recall, true, 1)
	checkRatio(t, "FPR", result.Strict.Metrics.FPR, true, 1)

	// Como decideBlockAll siempre responde "unknown", la atribución de
	// vector no tiene ningún acierto ni ningún error — todo es
	// "desconocido", y la precisión de atribución es N/A.
	if result.VectorAttribution.Correct != 0 || result.VectorAttribution.Incorrect != 0 {
		t.Errorf("VectorAttribution = %+v, want Correct=0 Incorrect=0", result.VectorAttribution)
	}
	if result.VectorAttribution.Unknown != 4 {
		t.Errorf("VectorAttribution.Unknown = %d, want 4", result.VectorAttribution.Unknown)
	}
	checkRatio(t, "VectorAttribution.Accuracy", result.VectorAttribution.Accuracy(), false, 0)
}

func TestEvaluate_PerfectOracleEngine(t *testing.T) {
	labels := sampleLabels()
	result := Evaluate(LoadLabelsResult{Labels: labels}, decidePerfectOracle(labels))

	if !result.Issues.Clean() {
		t.Fatalf("Issues not clean: %+v", result.Issues)
	}
	want := ConfusionMatrix{TP: 4, FP: 0, FN: 0, TN: 3}
	if result.Strict.Matrix != want {
		t.Errorf("strict matrix = %+v, want %+v", result.Strict.Matrix, want)
	}
	checkRatio(t, "Precision", result.Strict.Metrics.Precision, true, 1)
	checkRatio(t, "Recall", result.Strict.Metrics.Recall, true, 1)
	checkRatio(t, "FPR", result.Strict.Metrics.FPR, true, 0)
	checkRatio(t, "Accuracy", result.Strict.Metrics.Accuracy, true, 1)

	if result.VectorAttribution.Correct != 4 || result.VectorAttribution.Incorrect != 0 || result.VectorAttribution.Unknown != 0 {
		t.Errorf("VectorAttribution = %+v, want Correct=4 Incorrect=0 Unknown=0", result.VectorAttribution)
	}
}

// TestEvaluate_DirtyDataset_StillReportsPartialMetricsButNotClean
// comprueba el requisito de integridad: con decisiones faltantes, el
// resultado sigue calculándose (para diagnóstico), pero
// Issues.Clean() tiene que dar false — la señal de que este resultado
// NO debe leerse como definitivo.
func TestEvaluate_DirtyDataset_StillReportsPartialMetricsButNotClean(t *testing.T) {
	labels := sampleLabels()
	decisions := decideAllowAll(labels)
	// Se descarta la decisión de r-4: ahora tiene etiqueta pero
	// ninguna decisión.
	var incomplete []decision.Decision
	for _, d := range decisions {
		if d.RequestID != "r-4" {
			incomplete = append(incomplete, d)
		}
	}

	result := Evaluate(LoadLabelsResult{Labels: labels}, incomplete)

	if result.Issues.Clean() {
		t.Fatal("Issues.Clean() = true, want false (r-4 has no decision)")
	}
	if len(result.Issues.MissingDecisionIDs) != 1 || result.Issues.MissingDecisionIDs[0] != "r-4" {
		t.Errorf("MissingDecisionIDs = %v, want [r-4]", result.Issues.MissingDecisionIDs)
	}
	// El total evaluado tiene que ser 6, no 7 — r-4 queda excluido del
	// cálculo, no contado como si hubiera sido un ALLOW implícito.
	if result.TotalJoined != 6 {
		t.Errorf("TotalJoined = %d, want 6", result.TotalJoined)
	}
	if result.Strict.Matrix.Total() != 6 {
		t.Errorf("strict matrix total = %d, want 6", result.Strict.Matrix.Total())
	}
}

// --- Prueba de extremo a extremo contra un dataset con forma real ----

func fakeEntityID(ip string) string { return "ip:" + ip }

// decideNaiveRule es una regla de juguete de una sola línea, construida
// ÚNICAMENTE a partir de los campos de event.Event — nunca mira ninguna
// etiqueta. Existe solo para ejercitar la tubería completa del
// evaluador (leer, cruzar, calcular) sobre datos con la forma real de
// la tarea 0.6, no para medir si la regla en sí es buena.
func decideNaiveRule(e event.Event) decision.Decision {
	action := decision.ActionAllow
	vector := decision.AttackVectorUnknown
	explanation := ""
	var signals []decision.ContributingSignal

	switch {
	case e.Method == "POST" && e.Path == datagen.DefaultLoginPath && (e.StatusCode == 401 || e.StatusCode == 403):
		action = decision.ActionBlock
		vector = decision.AttackVectorCredentialStuffing
		explanation = "login attempt returned 401/403"
		signals = []decision.ContributingSignal{{Name: "login_failure", Value: 1, Weight: 1}}
	case e.StatusCode == 404:
		action = decision.ActionChallenge
		vector = decision.AttackVectorSlowScan
		explanation = "request returned 404"
		signals = []decision.ContributingSignal{{Name: "not_found", Value: 1, Weight: 1}}
	}

	return decision.Decision{
		RequestID:           e.RequestID,
		Timestamp:           e.Timestamp,
		EntityID:            fakeEntityID(e.ClientIP.String()),
		Action:              action,
		AttackVector:        vector,
		Explanation:         explanation,
		ContributingSignals: signals,
	}
}

func readEvents(t *testing.T, path string) []event.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("os.Open(%s): %v", path, err)
	}
	defer f.Close()

	var events []event.Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e event.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	return events
}

func TestEvaluate_EndToEnd_RealScenarioShape(t *testing.T) {
	cfg := datagen.DefaultScenarioConfig(999, 0.10)
	scenario := datagen.BuildScenario(cfg)

	dir := t.TempDir()
	if err := datagen.WriteScenario(dir, scenario); err != nil {
		t.Fatalf("WriteScenario: %v", err)
	}

	labelsResult, err := LoadLabels(filepath.Join(dir, "labels.jsonl"))
	if err != nil {
		t.Fatalf("LoadLabels: %v", err)
	}

	events := readEvents(t, filepath.Join(dir, "events.jsonl"))
	decisions := make([]decision.Decision, 0, len(events))
	for _, e := range events {
		decisions = append(decisions, decideNaiveRule(e))
	}

	result := Evaluate(labelsResult, decisions)

	if !result.Issues.Clean() {
		t.Fatalf("Issues not clean on a self-consistent dataset: %+v", result.Issues)
	}
	if result.TotalJoined != len(scenario.Events) {
		t.Fatalf("TotalJoined = %d, want %d", result.TotalJoined, len(scenario.Events))
	}
	if got := result.Strict.Matrix.Total(); got != result.TotalJoined {
		t.Errorf("strict matrix total = %d, want %d", got, result.TotalJoined)
	}
	if got := result.Broad.Matrix.Total(); got != result.TotalJoined {
		t.Errorf("broad matrix total = %d, want %d", got, result.TotalJoined)
	}

	t.Logf("regla de juguete sobre %d eventos (10%% malicioso objetivo): estricta=%+v amplia=%+v vector=%+v",
		result.TotalJoined, result.Strict.Matrix, result.Broad.Matrix, result.VectorAttribution)
}
