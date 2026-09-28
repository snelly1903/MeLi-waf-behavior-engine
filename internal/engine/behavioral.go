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

// anomalyPriority es la prioridad de desempate de statistical_anomaly
// — la más alta (el desempate más débil) de las tres, y la referencia
// para distinguir "detector específico" (credential_stuffing/
// slow_scan, priority < anomalyPriority) de "genérico" en
// selectAttribution (tarea 1.9, corrección de attribution).
const anomalyPriority = 2

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

// FindingsRecorder es la interfaz mínima que BehavioralDecider usa
// para reportar, por cada detector, si disparó un Finding en este
// evento — sin importar si terminó siendo el principal de la
// Decision o no (tarea 1.8). El nombre del detector es siempre uno
// de los ya registrados explícitamente en namedDetector.name
// ("credential_stuffing", "slow_scan", "statistical_anomaly"): nunca
// se infiere con un type switch sobre el detector concreto.
//
// Exportada porque internal/telemetry la implementa desde otro
// paquete, por tipado estructural — BehavioralDecider nunca importa
// OpenTelemetry directamente, mismo criterio que
// credstuffing.NetworkResolver (tarea 1.3).
type FindingsRecorder interface {
	RecordFinding(detector string)
}

// noopFindingsRecorder es el valor por defecto cuando
// NewBehavioralDecider recibe recorder=nil.
type noopFindingsRecorder struct{}

func (noopFindingsRecorder) RecordFinding(string) {}

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
	recorder  FindingsRecorder
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
// recorder es opcional: si es nil, se usa noopFindingsRecorder — un
// caller que no le importa la telemetría (por ejemplo, la mayoría de
// los tests de este paquete) puede seguir pasando nil.
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

// Decide implementa engine.Decider.
//
// Flujo: Observe en todos los detectores primero (el orden entre
// ellos no importa, no comparten estado); después Evaluate en todos —
// mismo contrato de dos pasos que cada detector ya exige por
// separado. Con los Finding disparados, separa DOS preguntas
// independientes (tarea 1.9, corrección de attribution — ver
// docs/decisiones.md):
//
//   - Qué tan riesgoso es este evento (Action/ConfidenceScore): el
//     mayor RiskScore entre TODOS los Triggered, sin importar qué
//     detector lo produjo — ver selectPrincipal. Esto NUNCA cambió.
//   - De qué ataque se trata (AttackVector/EntityID/
//     ContributingSignals/el Explanation principal): SIEMPRE un
//     detector ESPECÍFICO (credential_stuffing/slow_scan) si alguno
//     disparó, sin importar si statistical_anomaly tiene un RiskScore
//     mayor — ver selectAttribution. statistical_anomaly/unknown
//     queda reservado al caso donde NINGÚN detector específico
//     disparó.
//
// Antes de esta tarea, ambas preguntas las respondía el mismo
// Finding (el de mayor RiskScore) — así que un statistical_anomaly
// con score más alto podía dejar attack_vector=unknown aunque
// credential_stuffing o slow_scan también hubieran disparado, lo cual
// es una attribution engañosa: "no sabemos qué es esto" cuando en
// realidad SÍ había una hipótesis específica activa. Separar las dos
// preguntas corrige eso sin tocar el score ni la Action.
func (d *BehavioralDecider) Decide(_ context.Context, e event.Event) decision.Decision {
	for _, nd := range d.detectors {
		nd.detector.Observe(e)
	}

	var triggered []triggeredFinding
	for _, nd := range d.detectors {
		f := nd.detector.Evaluate(e)
		if f.Triggered {
			d.recorder.RecordFinding(nd.name)
			triggered = append(triggered, triggeredFinding{finding: f, priority: nd.priority})
		}
	}

	scoreSource, _ := selectPrincipal(triggered)

	if scoreSource == nil {
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

	action := d.policy.actionFor(scoreSource.RiskScore)

	// attribution nunca es nil acá: triggered tiene al menos un
	// elemento (scoreSource != nil lo garantiza), y selectAttribution
	// solo devuelve nil cuando triggered está vacío.
	attribution, secondaries := selectAttribution(triggered)

	// La Decision SIEMPRE refleja la evidencia real observada
	// (AttackVector, EntityID, señales) cuando algún detector
	// disparó — sin importar si Action terminó en ALLOW porque el
	// score no alcanzó ChallengeThreshold. Action refleja qué se hizo
	// con el riesgo; estos campos reflejan DE QUÉ ataque se trata. Son
	// preguntas distintas — ver docs/decisiones.md, tareas 1.5 y 1.9.
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

// triggeredFinding empareja un Finding disparado con la prioridad de
// desempate de quien lo produjo.
type triggeredFinding struct {
	finding  finding.Finding
	priority int
}

// bestIndexByScore devuelve el índice, dentro de pool, del
// triggeredFinding con mayor RiskScore — en empate exacto, el de
// menor priority (el más específico gana, ver NewBehavioralDecider).
// Asume len(pool) > 0; usada por selectPrincipal y selectAttribution
// para no duplicar la regla de desempate en dos lugares.
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

// selectPrincipal elige, entre los Finding que dispararon, cuál
// decide Action/ConfidenceScore (tarea 1.9: "qué tan riesgoso es
// esto", nunca "de qué ataque se trata" — ver selectAttribution para
// eso). El mayor RiskScore entre TODOS los Triggered — nunca se
// suman ni se promedian scores de detectores distintos, cada uno mide
// algo diferente con su propia escala heurística.
//
// secondaries son los demás Finding que también dispararon (nunca
// nil, puede ser vacío) — ya no se usan para construir el
// Explanation (ver explanationFor, que ahora recibe los secondaries
// de selectAttribution), se conservan acá solo porque siguen siendo
// parte del contrato de esta función.
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

// selectAttribution elige, entre los Finding que dispararon, cuál
// decide AttackVector/EntityID/ContributingSignals/el Explanation
// principal (tarea 1.9: "de qué ataque se trata", nunca "qué tan
// riesgoso es" — ver selectPrincipal para eso). Prioridad estricta:
// si CUALQUIER detector ESPECÍFICO (credential_stuffing/slow_scan,
// priority < anomalyPriority) disparó, gana el de mayor RiskScore
// ENTRE ESOS — statistical_anomaly nunca es candidato en ese caso,
// sin importar cuánto mayor sea su propio RiskScore. Solo cuando
// NINGÚN detector específico disparó se usa el/los que sí dispararon
// (en la práctica, como mucho statistical_anomaly) — ahí
// AttackVector queda en "unknown" porque ese es el AttackVector
// propio de statistical_anomaly (ver internal/anomaly), no una regla
// especial de acá.
//
// El desempate DENTRO de cada grupo (entre los específicos, o entre
// los genéricos si no hay específicos) es el mismo bestIndexByScore
// de siempre — nunca se introduce una regla de desempate nueva.
//
// secondaries son TODOS los demás Finding que dispararon (incluido
// statistical_anomaly si perdió por esta regla, no solo por score) —
// se mencionan en el Explanation, nunca se mezclan en la Decision.
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

// explanationFor arma el texto determinista de Decision.Explanation:
// la explicación de la evidencia ATRIBUIDA (attribution, ver
// selectAttribution — nunca necesariamente la de mayor RiskScore),
// junto con decisionScore (el score que REALMENTE decidió Action —
// ver selectPrincipal, tarea 1.9) y la acción resultante, y — por
// cada detector secundario que también disparó — una mención corta
// de eso, SIN concatenar sus señales (ver docs/decisiones.md, tarea
// 1.5, sobre por qué mezclar ContributingSignals de detectores
// distintos sería engañoso).
//
// decisionScore puede diferir del RiskScore propio de attribution
// (por ejemplo, cuando statistical_anomaly tiene mayor score pero un
// detector específico gana la attribution) — el texto dice
// deliberadamente "decision score", no "risk score", para no insinuar
// que ese número es el RiskScore propio de la evidencia descrita.
func explanationFor(attribution finding.Finding, secondaries []finding.Finding, action decision.Action, decisionScore float64, policy Policy) string {
	var explanation string
	if action == decision.ActionAllow {
		explanation = fmt.Sprintf("%s: %s (decision score %.2f, below challenge threshold %.2f; action=ALLOW)",
			attribution.AttackVector, attribution.Explanation, decisionScore, policy.ChallengeThreshold)
	} else {
		explanation = fmt.Sprintf("%s: %s (decision score %.2f; action=%s)",
			attribution.AttackVector, attribution.Explanation, decisionScore, action)
	}
	// Nunca se afirma "scored lower" acá: desde esta tarea, un
	// secondary puede tener un RiskScore mayor que decisionScore
	// (por ejemplo, statistical_anomaly perdiendo la attribution
	// frente a un detector específico con score menor) — el texto se
	// limita al score, sin caracterizar la comparación.
	for _, s := range secondaries {
		explanation = fmt.Sprintf("%s; %s signals were also present (risk score %.2f)",
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
