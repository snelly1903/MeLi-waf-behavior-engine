// Package engine (behavioral.go, tarea 1.5): el primer Decider real —
// combina los detectores conductuales (internal/credstuffing,
// internal/slowscan) en una única decision.Decision. Sin anomaly
// detection general, sin LLM, sin ASN real todavía — ver
// docs/decisiones.md, tarea 1.5, para el alcance exacto.
package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

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
)

// BehavioralDecider es el Decider real de la Fase 1: alimenta ambos
// detectores con cada evento, combina la evidencia que produzcan
// (finding.Finding) de forma determinista, y aplica Policy para
// decidir la acción final. No agrega ningún estado mutable propio —
// los dos detectores ya son seguros para concurrencia por su cuenta
// (tareas 1.3/1.4), así que Decide lo es también sin necesitar un
// lock nuevo acá.
type BehavioralDecider struct {
	credstuffing *credstuffing.Detector
	slowscan     *slowscan.Detector
	policy       Policy
}

// NewBehavioralDecider construye un BehavioralDecider. Los dos
// detectores son obligatorios — nunca nil: si todavía no existe un
// NetworkResolver real para credential stuffing, se construye ese
// detector igual, con credstuffing.UnavailableNetworkResolver (ver
// docs/decisiones.md, tarea 1.5) — nunca se omite el detector por
// completo, para no tener que ramificar con "if nil" en Decide.
func NewBehavioralDecider(cs *credstuffing.Detector, ss *slowscan.Detector, policy Policy) (*BehavioralDecider, error) {
	if cs == nil {
		return nil, ErrNilCredentialStuffingDetector
	}
	if ss == nil {
		return nil, ErrNilSlowScanDetector
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &BehavioralDecider{credstuffing: cs, slowscan: ss, policy: policy}, nil
}

// Decide implementa engine.Decider.
//
// Flujo, verificado contra el contrato real de ambos detectores (no
// asumido): primero Observe en los dos (el orden entre ellos no
// importa, no comparten estado), después Evaluate en los dos — mismo
// contrato de dos pasos que internal/credstuffing e internal/slowscan
// ya exigían por separado. Con los Finding resultantes, selecciona el
// principal (ver selectPrincipal) y aplica la Policy.
func (d *BehavioralDecider) Decide(_ context.Context, e event.Event) decision.Decision {
	d.credstuffing.Observe(e)
	d.slowscan.Observe(e)

	csFinding := d.credstuffing.Evaluate(e)
	ssFinding := d.slowscan.Evaluate(e)

	principal, secondary := selectPrincipal(csFinding, ssFinding)

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
	explanation := explanationFor(*principal, secondary, action, d.policy)

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

// selectPrincipal elige, entre los Finding que dispararon, cuál se
// convierte en la evidencia principal de la Decision.
// FinalRiskScore = el mayor RiskScore entre los Triggered — nunca se
// suman ni se promedian scores de detectores distintos, cada uno mide
// algo diferente con su propia escala heurística.
//
// En empate exacto gana credential_stuffing: regla fija y
// documentada, no dinámica — la evidencia de credential stuffing
// distribuido exige corroboración entre múltiples IPs independientes
// (el gate de internal/credstuffing), una forma de evidencia
// estructuralmente más difícil de disparar por casualidad que el
// patrón de una sola entidad que mira internal/slowscan.
//
// secondary es el otro Finding, si también disparó (nil si no) — se
// usa únicamente para mencionarlo en la explicación (ver
// explanationFor), nunca para mezclar sus señales en la Decision.
func selectPrincipal(cs, ss finding.Finding) (principal, secondary *finding.Finding) {
	switch {
	case cs.Triggered && ss.Triggered:
		if ss.RiskScore > cs.RiskScore {
			return &ss, &cs
		}
		return &cs, &ss // empate exacto o cs mayor: gana credential_stuffing
	case cs.Triggered:
		return &cs, nil
	case ss.Triggered:
		return &ss, nil
	default:
		return nil, nil
	}
}

// explanationFor arma el texto determinista de Decision.Explanation:
// la explicación del finding principal, el score y la acción
// resultante, y — si un segundo detector también disparó — una
// mención corta de eso, SIN concatenar sus señales (ver
// docs/decisiones.md, tarea 1.5, sobre por qué mezclar
// ContributingSignals de dos detectores distintos sería engañoso).
func explanationFor(principal finding.Finding, secondary *finding.Finding, action decision.Action, policy Policy) string {
	var explanation string
	if action == decision.ActionAllow {
		explanation = fmt.Sprintf("%s: %s (risk score %.2f, below challenge threshold %.2f; action=ALLOW)",
			principal.AttackVector, principal.Explanation, principal.RiskScore, policy.ChallengeThreshold)
	} else {
		explanation = fmt.Sprintf("%s: %s (risk score %.2f; action=%s)",
			principal.AttackVector, principal.Explanation, principal.RiskScore, action)
	}
	if secondary != nil {
		explanation = fmt.Sprintf("%s; %s signals were also present (risk score %.2f) but scored lower",
			explanation, secondary.AttackVector, secondary.RiskScore)
	}
	return explanation
}

// Sweep reenvía a los dos detectores — ver
// internal/profile.Store.Sweep, internal/credstuffing.Detector.Sweep
// e internal/slowscan.Detector.Sweep para el porqué. Conectarlo a un
// scheduler real queda fuera del alcance de esta tarea.
func (d *BehavioralDecider) Sweep(now time.Time, idleTTL time.Duration) int {
	return d.credstuffing.Sweep(now, idleTTL) + d.slowscan.Sweep(now, idleTTL)
}
