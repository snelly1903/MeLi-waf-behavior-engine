// Package finding define el resultado mínimo que produce UN detector
// sobre UN evento — no es todavía una decisión final. El futuro
// engine.Decider (tarea 1.1, hoy solo AllowAllDecider) va a combinar
// los Finding de varios detectores (credential stuffing, y más
// adelante slow scan) para armar un único decision.Decision.
package finding

import "github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"

// Finding reutiliza decision.AttackVector y decision.ContributingSignal
// tal cual, sin duplicar esos tipos — así combinar varios Finding en un
// Decision es concatenar listas, no convertir tipos.
type Finding struct {
	// Triggered informa si el detector considera que el patrón que
	// busca está presente. Si es false, ningún otro campo de este
	// struct tiene significado — quedan en su valor cero y no deben
	// leerse.
	Triggered bool

	// AttackVector es el tipo de ataque que este detector identifica.
	// Solo válido si Triggered es true.
	AttackVector decision.AttackVector

	// RiskScore es un puntaje heurístico de 0 a 1 — NO una probabilidad
	// estadísticamente calibrada (misma advertencia que
	// decision.Decision.ConfidenceScore, tarea 0.3). Solo válido si
	// Triggered es true; en ese caso, siempre es estrictamente mayor
	// que 0 (ver internal/credstuffing, tarea 1.3, para el porqué).
	RiskScore float64

	// ContributingSignals son las señales crudas que llevaron a este
	// resultado, con su peso configurado. Solo tiene sentido leerlo si
	// Triggered es true.
	ContributingSignals []decision.ContributingSignal

	// Explanation es el texto determinista que explica el resultado.
	// Solo se llena si Triggered es true.
	Explanation string

	// EntityID identifica, de forma estructurada, qué entidad originó
	// este Finding — mismo formato de prefijo que ya usa
	// decision.Decision.EntityID desde la tarea 0.3 ("ip:203.0.113.7",
	// "session:s-9f2a", "network:asn:64512"). Se agregó en la tarea
	// 1.5: antes de esto, esa información solo vivía en texto libre
	// dentro de Explanation, y el futuro engine.Decider no puede
	// depender de parsear texto para saber qué entidad disparó cada
	// detector. Solo válido si Triggered es true.
	//
	// No hay un campo EntityType separado — el prefijo ya lo indica,
	// mismo criterio que decision.Decision, que nunca tuvo uno.
	EntityID string
}
