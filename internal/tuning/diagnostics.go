// Ejecuta el motor evento por evento capturando el diagnóstico de cada detector.
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
