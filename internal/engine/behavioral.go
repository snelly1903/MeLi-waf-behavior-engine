// Package engine (behavioral.go): el Decider real — combina los
// detectores conductuales (internal/credstuffing, internal/slowscan,
// y desde la tarea 1.6, internal/anomaly) en una única
// decision.Decision. Sin LLM, sin ASN real, sin OTel/Grafana/k6/AWS
// todavía — ver docs/decisiones.md, tareas 1.5 y 1.6, para el alcance
// exacto.
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

// Errores centinela de construcción, comprobables individualmente con
// errors.Is.
var (
	ErrNilCredentialStuffingDetector = errors.New("engine: credential stuffing detector is required (use credstuffing.UnavailableNetworkResolver as an explicit placeholder if no real ASN provider exists yet)")
	ErrNilSlowScanDetector           = errors.New("engine: slow scan detector is required")
	ErrNilAnomalyDetector            = errors.New("engine: statistical anomaly detector is required")
)

// detector es la interfaz mínima que BehavioralDecider necesita de
// cada fuente de Finding — privada, definida acá porque acá es donde
// se consume (mismo criterio que engine.Decider, tarea 1.1), y usada
// ÚNICAMENTE para el bucle de combinación interno de Decide/Sweep.
// internal/credstuffing.Detector, internal/slowscan.Detector e
// internal/anomaly.Detector ya la cumplen tal cual — no se les tocó
// ni una firma para esto.
//
// Se agregó recién ahora, con el tercer detector (tarea 1.6): con
// dos, comparar a mano alcanzaba; con tres, la comparación escrita a
// mano ya no puede extenderse sin reescribirse, y una lista + un
// bucle es objetivamente menos código y menos propenso a errores que
// agregar una rama más a mano cada vez que aparezca un detector
// nuevo — la misma "regla de tres" ya aplicada en este proyecto para
// decidir cuándo extraer algo (ver el patrón de ventana con
// watermark, tareas 1.2-1.4).
type detector interface {
	Observe(event.Event)
	Evaluate(event.Event) finding.Finding
	Sweep(now time.Time, idleTTL time.Duration) int
}

// namedDetector empareja un detector con su prioridad de desempate
// (menor número gana un empate exacto de RiskScore) y un nombre solo
// para que quede legible en el código — nunca se expone en la
// Decision.
type namedDetector struct {
	name     string
	detector detector
	priority int
}

// BehavioralDecider combina la evidencia de varios detectores en una
// única decision.Decision. No agrega ningún estado mutable propio —
// los detectores ya son seguros para concurrencia por su cuenta
// (tareas 1.3/1.4/1.6), así que Decide lo es también sin necesitar un
// lock nuevo acá.
type BehavioralDecider struct {
	detectors []namedDetector
	policy    Policy
}

// NewBehavioralDecider construye un BehavioralDecider. Los tres
// detectores son obligatorios — nunca nil: si todavía no existe un
// NetworkResolver real para credential stuffing, se construye ese
// detector igual, con credstuffing.UnavailableNetworkResolver (ver
// docs/decisiones.md, tarea 1.5) — nunca se omite un detector por
// completo, para no tener que ramificar con "if nil" en Decide.
//
// El constructor sigue recibiendo parámetros explícitos y tipados
// (no una lista genérica): el sitio de construcción en cmd/engine se
// mantiene legible — "acá va credential stuffing, acá slow scan, acá
// el detector estadístico". La lista interna (y la interfaz mínima
// detector) es un detalle de implementación de Decide/Sweep, no de
// esta API pública.
//
// Prioridad de desempate, fija y documentada: credential_stuffing
// (0) > slow_scan (1) > statistical_anomaly (2) — el más específico
// gana un empate exacto de RiskScore; el genérico es el último
// recurso. Generaliza la regla ya establecida en la tarea 1.5
// ("credential_stuffing gana empates contra slow_scan").
func NewBehavioralDecider(cs *credstuffing.Detector, ss *slowscan.Detector, an *anomaly.Detector, policy Policy) (*BehavioralDecider, error) {
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
	return &BehavioralDecider{
		detectors: []namedDetector{
			{name: "credential_stuffing", detector: cs, priority: 0},
			{name: "slow_scan", detector: ss, priority: 1},
			{name: "statistical_anomaly", detector: an, priority: 2},
		},
		policy: policy,
	}, nil
}

// Decide implementa engine.Decider.
//
// Flujo: Observe en todos los detectores primero (el orden entre
// ellos no importa, no comparten estado); después Evaluate en todos —
// mismo contrato de dos pasos que cada detector ya exige por
// separado. Con los Finding disparados, selecciona el principal (ver
// selectPrincipal) y aplica la Policy.
func (d *BehavioralDecider) Decide(_ context.Context, e event.Event) decision.Decision {
	for _, nd := range d.detectors {
		nd.detector.Observe(e)
	}

	var triggered []triggeredFinding
	for _, nd := range d.detectors {
		f := nd.detector.Evaluate(e)
		if f.Triggered {
			triggered = append(triggered, triggeredFinding{finding: f, priority: nd.priority})
		}
	}

	principal, secondaries := selectPrincipal(triggered)

	if principal == nil {
		// Ningún detector disparó: el único caso que cae al default
		// "nada que reportar" — AttackVector=unknown, score 0. El
		// EntityID sigue la misma convención que AllowAllDecider
		// (tarea 1.1): nunca vacío, nunca hace fallar
		// decision.Validate().
		return decision.Decision{
			RequestID:    e.RequestID,
			Timestamp:    e.Timestamp,
			EntityID:     "ip:" + e.ClientIP.String(),
			Action:       decision.ActionAllow,
			AttackVector: decision.AttackVectorUnknown,
			Explanation:  "no behavioral detector flagged this request",
		}
	}

	action := d.policy.actionFor(principal.RiskScore)

	// La Decision SIEMPRE refleja la evidencia real observada
	// (AttackVector, ConfidenceScore, EntityID, señales) cuando algún
	// detector disparó — sin importar si Action terminó en ALLOW
	// porque el score no alcanzó ChallengeThreshold. Action refleja
	// qué se hizo con la evidencia; estos campos reflejan qué se
	// observó. Son preguntas distintas — ver docs/decisiones.md,
	// tarea 1.5.
	explanation := explanationFor(*principal, secondaries, action, d.policy)

	return decision.Decision{
		RequestID:           e.RequestID,
		Timestamp:           e.Timestamp,
		EntityID:            principal.EntityID,
		Action:              action,
		ConfidenceScore:     principal.RiskScore,
		AttackVector:        principal.AttackVector,
		ContributingSignals: principal.ContributingSignals,
		Explanation:         explanation,
	}
}

// triggeredFinding empareja un Finding disparado con la prioridad de
// desempate de quien lo produjo.
type triggeredFinding struct {
	finding  finding.Finding
	priority int
}

// selectPrincipal elige, entre los Finding que dispararon, cuál se
// convierte en la evidencia principal de la Decision.
// FinalRiskScore = el mayor RiskScore entre los Triggered — nunca se
// suman ni se promedian scores de detectores distintos, cada uno mide
// algo diferente con su propia escala heurística.
//
// En empate exacto gana el de menor número de prioridad (ver
// NewBehavioralDecider) — regla fija y documentada, no dinámica.
//
// secondaries son los demás Finding que también dispararon (nunca
// nil, puede ser vacío) — se usan únicamente para mencionarlos en la
// explicación (ver explanationFor), nunca para mezclar sus señales en
// la Decision.
func selectPrincipal(triggered []triggeredFinding) (principal *finding.Finding, secondaries []finding.Finding) {
	if len(triggered) == 0 {
		return nil, nil
	}

	best := 0
	for i := 1; i < len(triggered); i++ {
		c, p := triggered[i], triggered[best]
		if c.finding.RiskScore > p.finding.RiskScore ||
			(c.finding.RiskScore == p.finding.RiskScore && c.priority < p.priority) {
			best = i
		}
	}

	for i, t := range triggered {
		if i != best {
			secondaries = append(secondaries, t.finding)
		}
	}
	f := triggered[best].finding
	return &f, secondaries
}

// explanationFor arma el texto determinista de Decision.Explanation:
// la explicación del finding principal, el score y la acción
// resultante, y — por cada detector secundario que también disparó —
// una mención corta de eso, SIN concatenar sus señales (ver
// docs/decisiones.md, tarea 1.5, sobre por qué mezclar
// ContributingSignals de detectores distintos sería engañoso).
func explanationFor(principal finding.Finding, secondaries []finding.Finding, action decision.Action, policy Policy) string {
	var explanation string
	if action == decision.ActionAllow {
		explanation = fmt.Sprintf("%s: %s (risk score %.2f, below challenge threshold %.2f; action=ALLOW)",
			principal.AttackVector, principal.Explanation, principal.RiskScore, policy.ChallengeThreshold)
	} else {
		explanation = fmt.Sprintf("%s: %s (risk score %.2f; action=%s)",
			principal.AttackVector, principal.Explanation, principal.RiskScore, action)
	}
	for _, s := range secondaries {
		explanation = fmt.Sprintf("%s; %s signals were also present (risk score %.2f) but scored lower",
			explanation, s.AttackVector, s.RiskScore)
	}
	return explanation
}

// Sweep reenvía a todos los detectores. Conectarlo a un scheduler
// real queda fuera del alcance de estas tareas.
func (d *BehavioralDecider) Sweep(now time.Time, idleTTL time.Duration) int {
	total := 0
	for _, nd := range d.detectors {
		total += nd.detector.Sweep(now, idleTTL)
	}
	return total
}
