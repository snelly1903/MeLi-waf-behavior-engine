package eval

import (
	"fmt"
	"strconv"
	"strings"
)

// ReportMeta es la información del reporte que no viene de Result: de
// dónde salió este resultado. Deliberadamente no incluye ningún
// timestamp de reloj real — el texto generado por RenderMarkdown tiene
// que ser reproducible byte a byte para los mismos datos de entrada,
// igual que el resto del proyecto (ver docs/decisiones.md).
type ReportMeta struct {
	// ScenarioName es un nombre legible del escenario evaluado, por
	// ejemplo "scenario-10".
	ScenarioName string

	// ExpectedRecords es cuántas etiquetas había en labels.jsonl — la
	// base contra la que se compara TotalJoined para saber si se
	// evaluó todo lo que se esperaba evaluar.
	ExpectedRecords int
}

// formatRatio imprime r como porcentaje con tres decimales, o "N/A" si
// r.Defined es false — nunca disimula un denominador en cero con un
// número (ver docs/decisiones.md, tarea 0.7).
func formatRatio(r Ratio) string {
	if !r.Defined {
		return "N/A"
	}
	return strconv.FormatFloat(r.Value, 'f', 3, 64)
}

func formatIDList(ids []string) string {
	if len(ids) == 0 {
		return "(ninguna)"
	}
	return strings.Join(ids, ", ")
}

func formatLineList(lines []int) string {
	if len(lines) == 0 {
		return "(ninguna)"
	}
	parts := make([]string, len(lines))
	for i, n := range lines {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}

func writePolicySection(b *strings.Builder, title string, pr PolicyResult) {
	fmt.Fprintf(b, "## %s\n\n", title)
	fmt.Fprintf(b, "| Métrica | Valor |\n")
	fmt.Fprintf(b, "|---|---|\n")
	fmt.Fprintf(b, "| Precision | %s |\n", formatRatio(pr.Metrics.Precision))
	fmt.Fprintf(b, "| Recall | %s |\n", formatRatio(pr.Metrics.Recall))
	fmt.Fprintf(b, "| FPR | %s |\n", formatRatio(pr.Metrics.FPR))
	fmt.Fprintf(b, "| FNR | %s |\n", formatRatio(pr.Metrics.FNR))
	fmt.Fprintf(b, "| Accuracy | %s |\n\n", formatRatio(pr.Metrics.Accuracy))
	fmt.Fprintf(b, "Matriz: TP=%d FP=%d FN=%d TN=%d (total=%d)\n\n",
		pr.Matrix.TP, pr.Matrix.FP, pr.Matrix.FN, pr.Matrix.TN, pr.Matrix.Total())
}

// RenderMarkdown arma el reporte legible en Markdown de result. No
// vuelve a calcular ninguna métrica: solo formatea lo que ya está en
// result (ver evaluate.go). Si result.Issues.Clean() es false, el
// reporte abre con una advertencia explícita y visible antes de
// mostrar cualquier número, para que nunca se lo confunda con un
// resultado definitivo.
func RenderMarkdown(result Result, meta ReportMeta) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Reporte de evaluación — %s\n\n", meta.ScenarioName)

	if !result.Issues.Clean() {
		b.WriteString("⚠️ **Este resultado tiene problemas de integridad de datos y NO debe leerse como definitivo.**\n\n")
		fmt.Fprintf(&b, "- Decisiones duplicadas: %s\n", formatIDList(result.Issues.DuplicateDecisionIDs))
		fmt.Fprintf(&b, "- Decisiones faltantes: %s\n", formatIDList(result.Issues.MissingDecisionIDs))
		fmt.Fprintf(&b, "- Decisiones sobrantes: %s\n", formatIDList(result.Issues.ExtraDecisionIDs))
		fmt.Fprintf(&b, "- Decisiones inválidas (no pasan decision.Validate): %s\n", formatIDList(result.Issues.InvalidDecisionIDs))
		fmt.Fprintf(&b, "- Líneas de decisions.jsonl no interpretables: %s\n", formatLineList(result.Issues.CorruptDecisionLines))
		fmt.Fprintf(&b, "- Etiquetas duplicadas: %s\n", formatIDList(result.Issues.DuplicateLabelIDs))
		fmt.Fprintf(&b, "- Etiquetas desconocidas: %s\n\n", formatIDList(result.Issues.UnknownLabelIDs))
	}

	fmt.Fprintf(&b, "Registros cruzados: %d de %d esperados.\n\n", result.TotalJoined, meta.ExpectedRecords)

	writePolicySection(&b, "Política estricta (solo BLOCK cuenta como positivo)", result.Strict)
	writePolicySection(&b, "Política amplia (CHALLENGE + BLOCK cuentan como positivo)", result.Broad)

	b.WriteString("## Recall por vector de ataque (política amplia)\n\n")
	b.WriteString("| Vector | TP | FN | Recall |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, v := range result.ByAttackVector {
		fmt.Fprintf(&b, "| %s | %d | %d | %s |\n", v.Vector, v.TruePositives, v.FalseNegatives, formatRatio(v.Recall))
	}
	b.WriteString("\n")

	b.WriteString("## Atribución del vector de ataque (entre verdaderos positivos)\n\n")
	fmt.Fprintf(&b, "Correcto: %d, Desconocido: %d, Incorrecto: %d — Accuracy: %s\n",
		result.VectorAttribution.Correct, result.VectorAttribution.Unknown, result.VectorAttribution.Incorrect,
		formatRatio(result.VectorAttribution.Accuracy()))

	return b.String()
}
