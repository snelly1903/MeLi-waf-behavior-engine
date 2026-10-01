// Package engine (behavioral.go): el Decider real — combina los
// detectores conductuales (internal/credstuffing, internal/slowscan e
// internal/anomaly) en una única decision.Decision. Sin LLM, sin ASN
// real, sin OTel/Grafana/k6/AWS todavía — ver docs/decisiones.md para
// el alcance exacto.
package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

// anomalyPriority es la prioridad de desempate de statistical_anomaly
// — la más alta (el desempate más débil) de las tres, y la referencia
// para distinguir "detector específico" (credential_stuffing/
// slow_scan, priority < anomalyPriority) de "genérico" en
// selectAttribution.
const anomalyPriority = 2

var (
	ErrNilCredentialStuffingDetector = errors.New("engine: credential stuffing detector is required (use credstuffing.UnavailableNetworkResolver as an explicit placeholder if no real ASN provider exists yet)")
	ErrNilSlowScanDetector           = errors.New("engine: slow scan detector is required")
	ErrNilAnomalyDetector            = errors.New("engine: statistical anomaly detector is required")
)

// detector es la interfaz mínima que BehavioralDecider necesita de
// cada fuente de Finding
type detector interface {
	Observe(event.Event)
	Evaluate(event.Event) finding.Finding
	Sweep(now time.Time, idleTTL time.Duration) int
}

type FindingsRecorder interface {
	RecordFinding(detector string)
	RecordAnomalyScore(score float64)
}


type noopFindingsRecorder struct{}

func (noopFindingsRecorder) RecordFinding(string)       {}
func (noopFindingsRecorder) RecordAnomalyScore(float64) {}

type namedDetector struct {
	name     string
	detector detector
	priority int
}

type BehavioralDecider struct {
	detectors []namedDetector
	policy    Policy
	recorder  FindingsRecorder
}

func NewBehavioralDecider(cs *credstuffing.Detector, ss *slowscan.Detector, an *anomaly.Detector, policy Policy, recorder FindingsRecorder) (*BehavioralDecider, error) {
	if cs == nil {
		return nil, ErrNilCredentialStuffingDetector
	}
	if ss == nil {
		return nil, ErrNilSlowScanDetector
	}
	if an == nil {
		return nil, ErrNilAnomalyDetector
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if recorder == nil {
		recorder = noopFindingsRecorder{}
	}
	return &BehavioralDecider{
		detectors: []namedDetector{
			{name: "credential_stuffing", detector: cs, priority: 0},
			{name: "slow_scan", detector: ss, priority: 1},
			{name: "statistical_anomaly", detector: an, priority: anomalyPriority},
		},
		policy:   policy,
		recorder: recorder,
	}, nil
}

func (d *BehavioralDecider) Decide(_ context.Context, e event.Event) decision.Decision {
	for _, nd := range d.detectors {
		nd.detector.Observe(e)
	}

	var triggered []triggeredFinding
	for _, nd := range d.detectors {
		f := nd.detector.Evaluate(e)
		if nd.name == "statistical_anomaly" {
			d.recorder.RecordAnomalyScore(f.RiskScore)
		}
		if f.Triggered {
			d.recorder.RecordFinding(nd.name)
			triggered = append(triggered, triggeredFinding{finding: f, priority: nd.priority})
		}
	}

	scoreSource, _ := selectPrincipal(triggered)

	if scoreSource == nil {
		return decision.Decision{
			RequestID:    e.RequestID,
			Timestamp:    e.Timestamp,
			EntityID:     "ip:" + e.ClientIP.String(),
			Action:       decision.ActionAllow,
			AttackVector: decision.AttackVectorUnknown,
			Explanation:  "no behavioral detector flagged this request",
		}
	}

	action := d.policy.actionFor(scoreSource.RiskScore)

	attribution, secondaries := selectAttribution(triggered)


	explanation := explanationFor(*attribution, secondaries, action, scoreSource.RiskScore, d.policy)

	return decision.Decision{
		RequestID:           e.RequestID,
		Timestamp:           e.Timestamp,
		EntityID:            attribution.EntityID,
		Action:              action,
		ConfidenceScore:     scoreSource.RiskScore,
		AttackVector:        attribution.AttackVector,
		ContributingSignals: attribution.ContributingSignals,
		Explanation:         explanation,
	}
}

type triggeredFinding struct {
	finding  finding.Finding
	priority int
}

func bestIndexByScore(pool []triggeredFinding) int {
	best := 0
	for i := 1; i < len(pool); i++ {
		c, p := pool[i], pool[best]
		if c.finding.RiskScore > p.finding.RiskScore ||
			(c.finding.RiskScore == p.finding.RiskScore && c.priority < p.priority) {
			best = i
		}
	}
	return best
}

func selectPrincipal(triggered []triggeredFinding) (principal *finding.Finding, secondaries []finding.Finding) {
	if len(triggered) == 0 {
		return nil, nil
	}
	best := bestIndexByScore(triggered)
	for i, t := range triggered {
		if i != best {
			secondaries = append(secondaries, t.finding)
		}
	}
	f := triggered[best].finding
	return &f, secondaries
}

func selectAttribution(triggered []triggeredFinding) (attribution *finding.Finding, secondaries []finding.Finding) {
	if len(triggered) == 0 {
		return nil, nil
	}

	var specificIdx []int
	for i, t := range triggered {
		if t.priority < anomalyPriority {
			specificIdx = append(specificIdx, i)
		}
	}

	var chosen int
	if len(specificIdx) > 0 {
		pool := make([]triggeredFinding, len(specificIdx))
		for j, idx := range specificIdx {
			pool[j] = triggered[idx]
		}
		chosen = specificIdx[bestIndexByScore(pool)]
	} else {
		chosen = bestIndexByScore(triggered)
	}

	for i, t := range triggered {
		if i != chosen {
			secondaries = append(secondaries, t.finding)
		}
	}
	f := triggered[chosen].finding
	return &f, secondaries
}


func explanationFor(attribution finding.Finding, secondaries []finding.Finding, action decision.Action, decisionScore float64, policy Policy) string {
	var explanation string
	if action == decision.ActionAllow {
		explanation = fmt.Sprintf("%s: %s (decision score %.2f, below challenge threshold %.2f; action=ALLOW)",
			attribution.AttackVector, attribution.Explanation, decisionScore, policy.ChallengeThreshold)
	} else {
		explanation = fmt.Sprintf("%s: %s (decision score %.2f; action=%s)",
			attribution.AttackVector, attribution.Explanation, decisionScore, action)
	}
	for _, s := range secondaries {
		explanation = fmt.Sprintf("%s; %s signals were also present (risk score %.2f)",
			explanation, s.AttackVector, s.RiskScore)
	}
	return explanation
}

func (d *BehavioralDecider) Sweep(now time.Time, idleTTL time.Duration) int {
	total := 0
	for _, nd := range d.detectors {
		total += nd.detector.Sweep(now, idleTTL)
	}
	return total
}
