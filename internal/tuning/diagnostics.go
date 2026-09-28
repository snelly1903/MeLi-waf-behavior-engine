package tuning

import (
	"fmt"
	"math"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

// EventDiagnostic es, para UN evento del escenario, el detalle CRUDO
// de cada detector — nunca solo la Decision final ya combinada (tarea
// 1.9, pasada diagnóstica). Decision viene de una corrida real con
// engine.BehavioralDecider (ver RunDiagnostics) — nunca se reinventa
// su lógica de combinación/policy acá. El resto de los campos viene
// de tres detectores propios de esta corrida de diagnóstico,
// construidos con la misma configuración que Candidate.Build, que
// SÍ mantienen visible el Finding de cada uno, ganador o no.
type EventDiagnostic struct {
	Seed      uint64
	Ratio     int
	RequestID string
	Label     groundtruth.Label
	Decision  decision.Decision

	CredentialStuffing          finding.Finding
	CredentialStuffingGate      credstuffing.GateMetrics
	CredentialStuffingGateFound bool
	SlowScan                    finding.Finding
	SlowScanGates               []slowscan.GateMetrics
	Anomaly                     []anomaly.DebugEvaluation
}

// RunDiagnostics corre, sobre los MISMOS eventos y con la MISMA
// configuración que RunScenario, tres detectores propios de
// diagnóstico — nunca los de BehavioralDecider, que no expone el
// Finding de cada uno por separado, solo el que ganó. decisions tiene
// que venir de correr RunScenario sobre el MISMO scenario y candidate
// (mismo orden, misma longitud) — se cruza por índice, nunca por
// RequestID, mismo criterio que ComputeDetectionDelay.
//
// Cada detector de esta corrida arranca con estado limpio (igual que
// Candidate.Build) y observa los eventos en el mismo orden que la
// corrida real — así que, para el mismo evento, el Finding que cada
// uno produce acá es EXACTAMENTE el que produciría el detector
// interno equivalente dentro de BehavioralDecider.Decide.
func RunDiagnostics(scenario datagen.Scenario, candidate Candidate, resolver credstuffing.NetworkResolver, decisions []decision.Decision) ([]EventDiagnostic, error) {
	if len(decisions) != len(scenario.Events) {
		return nil, fmt.Errorf("tuning: RunDiagnostics: %d decisions, want %d (una por evento, mismo orden)", len(decisions), len(scenario.Events))
	}

	csCfg := candidate.CredentialStuffing
	csCfg.Resolver = resolver
	cs, err := credstuffing.NewDetector(csCfg)
	if err != nil {
		return nil, fmt.Errorf("tuning: RunDiagnostics: credential stuffing detector: %w", err)
	}
	ss, err := slowscan.NewDetector(candidate.SlowScan)
	if err != nil {
		return nil, fmt.Errorf("tuning: RunDiagnostics: slow scan detector: %w", err)
	}
	an, err := anomaly.NewDetector(candidate.Anomaly)
	if err != nil {
		return nil, fmt.Errorf("tuning: RunDiagnostics: anomaly detector: %w", err)
	}

	result := make([]EventDiagnostic, len(scenario.Events))
	for i, le := range scenario.Events {
		e := le.Payload()
		cs.Observe(e)
		ss.Observe(e)
		an.Observe(e)

		csGate, csGateFound := cs.EvaluateGateMetrics(e)
		result[i] = EventDiagnostic{
			Seed:                        scenario.Stats.Seed,
			Ratio:                       int(math.Round(scenario.Stats.TargetMaliciousRatio * 100)),
			RequestID:                   e.RequestID,
			Label:                       le.Label,
			Decision:                    decisions[i],
			CredentialStuffing:          cs.Evaluate(e),
			CredentialStuffingGate:      csGate,
			CredentialStuffingGateFound: csGateFound,
			SlowScan:                    ss.Evaluate(e),
			SlowScanGates:               ss.EvaluateGateMetrics(e),
			Anomaly:                     an.EvaluateDebug(e),
		}
	}
	return result, nil
}

// winningAnomalyEval devuelve, entre evals (IP y, si existe, sesión),
// el que "ganaría" si tuviera que convertirse en el Finding de
// anomaly.Detector.Evaluate: el de mayor RiskScore entre los
// Triggered; en empate exacto, o si ninguno disparó, el de sesión (si
// existe) por ser la entidad más específica — misma regla que
// anomaly.Detector.Evaluate. found es false solo si evals está vacío
// (nunca debería pasar: EvaluateDebug siempre devuelve al menos el
// scope IP).
func winningAnomalyEval(evals []anomaly.DebugEvaluation) (anomaly.DebugEvaluation, bool) {
	if len(evals) == 0 {
		return anomaly.DebugEvaluation{}, false
	}
	best := evals[0]
	for _, e := range evals[1:] {
		switch {
		case e.Triggered && best.Triggered:
			if e.RiskScore >= best.RiskScore {
				best = e
			}
		case e.Triggered && !best.Triggered:
			best = e
		}
	}
	return best, true
}
