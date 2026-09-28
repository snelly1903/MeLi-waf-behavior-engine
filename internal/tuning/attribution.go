package tuning

import (
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// MitigationAttribution resume, para UN vector de ataque (dentro de
// una corrida), cuántos de sus eventos MITIGADOS (Decision positiva,
// según policy) dispararon por su propio detector, cuántos tuvieron
// además a statistical_anomaly disparando para el mismo evento, y
// cuántos dependieron ÚNICAMENTE de statistical_anomaly (su propio
// detector no disparó, pero anomaly sí). Reutiliza directamente los
// Finding crudos que ya expone RunDiagnostics — no agrega ninguna
// corrida ni estado nuevo (tarea 1.9, pedido explícito de "sin
// añadir complejidad grande").
type MitigationAttribution struct {
	Vector groundtruth.Label

	// Mitigated es el total de eventos de este vector con Decision
	// positiva (según policy) — la base de los tres conteos de abajo.
	Mitigated int

	// DetectorOnly: el detector propio del vector disparó; anomaly no.
	DetectorOnly int

	// WithAnomalyAssist: el detector propio disparó Y anomaly también
	// disparó para el mismo evento — anomaly no fue necesario, pero
	// coincidió.
	WithAnomalyAssist int

	// AnomalyOnly: el detector propio NO disparó, pero anomaly sí —
	// sin anomaly, este evento no se habría mitigado.
	AnomalyOnly int

	// Neither: mitigado sin que el detector propio NI anomaly
	// dispararan — solo puede pasar por una señal cruzada (por
	// ejemplo, el otro detector de ataque). Se cuenta aparte para no
	// esconderlo, nunca se descarta en silencio.
	Neither int
}

// ComputeMitigationAttribution recorre diagnostics y arma un
// MitigationAttribution por cada uno de los dos vectores de ataque
// (credential_stuffing, slow_scan) — nunca statistical_anomaly, que
// no tiene un tipo de ataque propio con el que comparar (ver
// docs/decisiones.md, tarea 1.6).
func ComputeMitigationAttribution(diagnostics []EventDiagnostic, policy eval.Policy) []MitigationAttribution {
	vectors := []struct {
		label groundtruth.Label
		own   func(EventDiagnostic) bool
	}{
		{groundtruth.LabelCredentialStuffing, func(d EventDiagnostic) bool { return d.CredentialStuffing.Triggered }},
		{groundtruth.LabelSlowScan, func(d EventDiagnostic) bool { return d.SlowScan.Triggered }},
	}

	result := make([]MitigationAttribution, len(vectors))
	for i, v := range vectors {
		result[i] = MitigationAttribution{Vector: v.label}
		for _, d := range diagnostics {
			if d.Label != v.label {
				continue
			}
			if !policy.IsPositive(d.Decision.Action) {
				continue
			}
			result[i].Mitigated++

			own := v.own(d)
			winner, ok := winningAnomalyEval(d.Anomaly)
			anomalyTriggered := ok && winner.Triggered

			switch {
			case own && anomalyTriggered:
				result[i].WithAnomalyAssist++
			case own && !anomalyTriggered:
				result[i].DetectorOnly++
			case !own && anomalyTriggered:
				result[i].AnomalyOnly++
			default:
				result[i].Neither++
			}
		}
	}
	return result
}
