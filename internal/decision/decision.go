// Package decision define el contrato de salida del motor: lo que
// devuelve por cada evento que analiza. Es el puerto de salida de la
// arquitectura hexagonal, simétrico al puerto de entrada definido en
// internal/event.
package decision

import (
	"errors"
	"math"
	"strings"
	"time"
)

// Action es la acción que el motor toma sobre un request.
type Action string

const (
	// ActionAllow deja pasar el request sin fricción.
	ActionAllow Action = "ALLOW"
	// ActionChallenge le pide al cliente una prueba adicional (por
	// ejemplo un CAPTCHA) antes de continuar. Es la fricción "barata":
	// molesta menos a un cliente legítimo que un bloqueo directo.
	ActionChallenge Action = "CHALLENGE"
	// ActionBlock rechaza el request.
	ActionBlock Action = "BLOCK"
)

// Valid informa si a es una de las tres acciones conocidas.
func (a Action) Valid() bool {
	switch a {
	case ActionAllow, ActionChallenge, ActionBlock:
		return true
	default:
		return false
	}
}

// AttackVector es la categoría de ataque que el motor infiere para una
// decisión. AttackVectorUnknown se usa cuando la decisión se basó en una
// señal general (por ejemplo, el modelo de anomalías) sin que se pueda
// atribuir a una técnica de ataque específica.
type AttackVector string

const (
	AttackVectorCredentialStuffing AttackVector = "credential_stuffing"
	AttackVectorSlowScan           AttackVector = "slow_scan"
	AttackVectorUnknown            AttackVector = "unknown"
)

// Valid informa si v es uno de los vectores de ataque conocidos.
func (v AttackVector) Valid() bool {
	switch v {
	case AttackVectorCredentialStuffing, AttackVectorSlowScan, AttackVectorUnknown:
		return true
	default:
		return false
	}
}

// ContributingSignal describe una señal que alimentó una decisión, y
// cuánto pesó, en relación con las demás, en el resultado final. Un
// BLOCK contra un clúster de credential stuffing podría tener, por
// ejemplo, dos señales: {"cluster_fail_ratio_wilson", 0.81, 0.6} y
// {"cluster_user_diversity", 0.97, 0.4}.
//
// Por ahora Weight no está normalizado a que la suma de todas las
// señales de una decisión dé exactamente 1 — esa regla se define recién
// cuando exista el algoritmo de combinación de señales (Fase 1), que es
// quien sabe si conviene normalizar antes o después de guardar la
// decisión. Lo único que este contrato garantiza hoy es que Weight sea
// un número finito y no negativo.
type ContributingSignal struct {
	// Name identifica la señal, por ejemplo "cluster_fail_ratio_wilson"
	// o "path_entropy_normalized".
	Name string `json:"name"`

	// Value es la lectura cruda de la señal (por ejemplo, un ratio
	// entre 0 y 1, o una puntuación de anomalía).
	Value float64 `json:"value"`

	// Weight es el aporte relativo de esta señal al resultado final.
	Weight float64 `json:"weight"`
}

// Decision es lo que el motor produce por cada evento analizado. Cubre
// tanto lo que necesita el "árbitro" (cmd/eval) para cruzarla con el
// ground truth, como los campos que el PDF del challenge exige en el log
// JSON de auditoría de cada decisión — es un solo tipo, no dos, porque
// el evaluador simplemente ignora los campos que no usa.
type Decision struct {
	// RequestID identifica el request al que corresponde esta decisión.
	// Es también la clave de correlación para la explicación asíncrona
	// del LLM (ver LLMExplanation más abajo) y para el cruce con el
	// ground truth que hace el evaluador.
	RequestID string `json:"request_id"`

	// Timestamp es cuándo se tomó la decisión.
	Timestamp time.Time `json:"timestamp"`

	// EntityID identifica la entidad sobre la que se decidió, por
	// ejemplo "ip:203.0.113.7" o "session:s-9f2a". El prefijo indica de
	// qué tipo de entidad se trata.
	EntityID string `json:"entity_id"`

	// Action es la acción tomada.
	Action Action `json:"action"`

	// ConfidenceScore es un indicador del riesgo de comportamiento
	// malicioso de la entidad para el AttackVector inferido, en una
	// escala de 0 (sin indicios) a 1 (indicios muy fuertes).
	//
	// Deliberadamente NO se define como una probabilidad
	// estadísticamente calibrada — no hay, en esta fase del proyecto,
	// ninguna garantía de que "0.7" signifique literalmente "70% de
	// probabilidad de que sea un ataque". Es un puntaje de riesgo
	// comparable entre decisiones, que la política del motor (Fase 1)
	// corta con dos umbrales configurables para elegir la acción:
	//
	//   score < umbral_challenge                   → ALLOW
	//   umbral_challenge ≤ score < umbral_block     → CHALLENGE
	//   score ≥ umbral_block                        → BLOCK
	//
	// Esos umbrales no viven en este contrato: son configuración del
	// motor, no una propiedad de una decisión ya tomada.
	//
	// Advertencia sobre re-analizar decisiones guardadas con umbrales
	// distintos ("barrido de umbrales"): es útil como primera
	// aproximación, pero solo es exacto si las decisiones no afectan el
	// estado del propio motor. En la práctica sí lo afectan — un ALLOW
	// versus un BLOCK sobre el primer request de un atacante cambia qué
	// eventos siguientes ve el motor (un atacante bloqueado no genera
	// más eventos; uno permitido, sí). Por eso, para validar un cambio
	// de política de verdad, hace falta volver a reproducir el tráfico
	// contra el motor con los nuevos umbrales, no solo reetiquetar las
	// decisiones ya guardadas.
	ConfidenceScore float64 `json:"confidence_score"`

	// AttackVector es la categoría de ataque inferida.
	AttackVector AttackVector `json:"attack_vector"`

	// ContributingSignals lista las señales que alimentaron la
	// decisión. Es obligatorio (al menos una señal) cuando Action es
	// CHALLENGE o BLOCK; para ALLOW puede quedar vacío.
	ContributingSignals []ContributingSignal `json:"contributing_signals,omitempty"`

	// Explanation es la explicación determinista, calculada por reglas
	// a partir de ContributingSignals, en el mismo momento en que se
	// toma la decisión. Es obligatoria cuando Action es CHALLENGE o
	// BLOCK, y es el registro canónico de auditoría: no depende de
	// ningún servicio externo ni puede demorarse.
	Explanation string `json:"explanation"`

	// LLMExplanation es la explicación en lenguaje natural generada por
	// el LLM, cuando esa capacidad esté implementada (todavía no lo
	// está — este campo es solo el contrato). Es un puntero, y no un
	// string simple, porque hacen falta tres estados distintos:
	// "el LLM no corre para esta decisión" (nil, sin capacidad
	// habilitada), "el LLM todavía no respondió" (nil, en decisiones
	// donde sí corre pero de forma asíncrona) y "el LLM respondió esto"
	// (puntero a un string, incluso si ese string fuera "").
	//
	// Nota de diseño para la Fase 1: como el LLM corre de forma
	// asíncrona (ver el análisis general, sección 13), este campo
	// nunca va a completarse modificando el log JSON que ya se emitió
	// para la decisión original — los logs son de solo anexado
	// (append-only) y no se editan en el lugar. En cambio, cuando la
	// explicación del LLM esté lista, se va a emitir un **evento de
	// auditoría separado** (por ejemplo, algo del estilo
	// "decision_explanation"), correlacionado con la decisión original
	// por RequestID (o por un DecisionID dedicado, si en la Fase 1
	// resulta que un request puede generar más de una decisión y hace
	// falta distinguirlas). Quien lea los logs de auditoría necesita
	// poder reconstruir la decisión completa cruzando ambos eventos por
	// esa clave, no esperando que el primero se actualice.
	LLMExplanation *string `json:"llm_explanation,omitempty"`
}

// Errores centinela de validación, comprobables individualmente con
// errors.Is.
var (
	ErrEmptyRequestID         = errors.New("decision: request_id is required")
	ErrInvalidTimestamp       = errors.New("decision: timestamp is required")
	ErrEmptyEntityID          = errors.New("decision: entity_id is required")
	ErrInvalidAction          = errors.New("decision: action must be ALLOW, CHALLENGE or BLOCK")
	ErrInvalidConfidenceScore = errors.New("decision: confidence_score must be between 0 and 1")
	ErrInvalidAttackVector    = errors.New("decision: attack_vector must be credential_stuffing, slow_scan or unknown")

	ErrMissingExplanation         = errors.New("decision: explanation is required for CHALLENGE and BLOCK actions")
	ErrMissingContributingSignals = errors.New("decision: at least one contributing_signal is required for CHALLENGE and BLOCK actions")
	ErrEmptySignalName            = errors.New("decision: contributing_signal name is required")
	ErrInvalidSignalValue         = errors.New("decision: contributing_signal value must be a finite number")
	ErrInvalidSignalWeight        = errors.New("decision: contributing_signal weight must be a finite, non-negative number")
)

// Validate comprueba que d tenga la forma mínima exigible a una
// decisión, y devuelve todos los problemas encontrados unidos con
// errors.Join.
func Validate(d Decision) error {
	var errs []error

	if strings.TrimSpace(d.RequestID) == "" {
		errs = append(errs, ErrEmptyRequestID)
	}
	if d.Timestamp.IsZero() {
		errs = append(errs, ErrInvalidTimestamp)
	}
	if strings.TrimSpace(d.EntityID) == "" {
		errs = append(errs, ErrEmptyEntityID)
	}
	if !d.Action.Valid() {
		errs = append(errs, ErrInvalidAction)
	}
	if d.ConfidenceScore < 0 || d.ConfidenceScore > 1 {
		errs = append(errs, ErrInvalidConfidenceScore)
	}
	if !d.AttackVector.Valid() {
		errs = append(errs, ErrInvalidAttackVector)
	}

	if d.Action == ActionChallenge || d.Action == ActionBlock {
		if strings.TrimSpace(d.Explanation) == "" {
			errs = append(errs, ErrMissingExplanation)
		}
		if len(d.ContributingSignals) == 0 {
			errs = append(errs, ErrMissingContributingSignals)
		}
	}

	for _, sig := range d.ContributingSignals {
		if strings.TrimSpace(sig.Name) == "" {
			errs = append(errs, ErrEmptySignalName)
		}
		if math.IsNaN(sig.Value) || math.IsInf(sig.Value, 0) {
			errs = append(errs, ErrInvalidSignalValue)
		}
		if math.IsNaN(sig.Weight) || math.IsInf(sig.Weight, 0) || sig.Weight < 0 {
			errs = append(errs, ErrInvalidSignalWeight)
		}
	}

	return errors.Join(errs...)
}
