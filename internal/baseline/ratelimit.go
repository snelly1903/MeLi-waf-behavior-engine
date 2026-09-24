// Package baseline implementa una línea base de comparación sencilla
// para el futuro motor conductual de la Fase 1: un rate limiter
// tradicional por IP, con ventana deslizante. Igual que
// internal/datagen, nunca importa internal/groundtruth — solo ve lo
// mismo que vería cualquier detector real (internal/event), la misma
// separación de la tarea 0.2. El objetivo de este paquete no es que
// el detector sea bueno: es tener un punto de comparación conocido y
// documentado, contra el que medir después cuánto aporta el motor
// conductual (ver docs/decisiones.md, tarea 0.9).
package baseline

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

// CountMode decide qué peticiones alimentan el conteo del rate limit.
type CountMode string

const (
	// CountModeAll cuenta todas las peticiones de cada IP, sin
	// distinguir de qué endpoint se trata — como un rate limit
	// genérico de borde (edge/CDN/balanceador).
	CountModeAll CountMode = "all"

	// CountModeAuth cuenta únicamente las peticiones a endpoints de
	// autenticación (ver event.AuthPathMatcher) — como un rate limit
	// específico de /login, la forma más común de mitigación de
	// credential stuffing en la práctica. Una petición que no es de
	// autenticación siempre queda en ALLOW en este modo: este baseline
	// directamente no la evalúa, no cuenta para ninguna IP.
	CountModeAuth CountMode = "auth"
)

// Valid informa si m es un modo de conteo conocido.
func (m CountMode) Valid() bool {
	switch m {
	case CountModeAll, CountModeAuth:
		return true
	default:
		return false
	}
}

// Config configura el rate limit. Ver Detect para el significado
// exacto de MaxRequests y Window.
type Config struct {
	// MaxRequests es cuántas peticiones contadas puede acumular una IP
	// dentro de Window antes de que las siguientes se bloqueen. Debe
	// ser mayor que 0.
	MaxRequests int

	// Window es el tamaño de la ventana deslizante. Debe ser mayor que
	// 0.
	Window time.Duration

	// Mode decide qué peticiones cuenta el límite (ver CountMode).
	Mode CountMode

	// AuthMatcher decide qué rutas son de autenticación cuando Mode es
	// CountModeAuth. Si es nil, se usa event.DefaultAuthPathMatcher().
	// Se ignora cuando Mode es CountModeAll. No duplica ninguna lógica
	// de reconocimiento de rutas: reutiliza tal cual el matcher de la
	// tarea 0.2.
	AuthMatcher *event.AuthPathMatcher
}

// Errores centinela de configuración, comprobables individualmente
// con errors.Is.
var (
	ErrInvalidMaxRequests = errors.New("baseline: max_requests must be greater than 0")
	ErrInvalidWindow      = errors.New("baseline: window must be greater than 0")
	ErrInvalidMode        = errors.New("baseline: mode must be \"all\" or \"auth\"")
)

// Validate comprueba que cfg tenga valores utilizables, y devuelve
// todos los problemas encontrados unidos con errors.Join.
func (cfg Config) Validate() error {
	var errs []error
	if cfg.MaxRequests <= 0 {
		errs = append(errs, ErrInvalidMaxRequests)
	}
	if cfg.Window <= 0 {
		errs = append(errs, ErrInvalidWindow)
	}
	if !cfg.Mode.Valid() {
		errs = append(errs, ErrInvalidMode)
	}
	return errors.Join(errs...)
}

// ErrEventsOutOfOrder se devuelve cuando events no está ordenado por
// Timestamp de forma no decreciente. Detect nunca reordena su entrada
// ni asume ningún reloj real: si los eventos no llegan en el mismo
// orden cronológico en que "ocurrieron", el resultado de una ventana
// deslizante no tendría ningún sentido — Detect prefiere fallar
// explícitamente antes que calcular algo incorrecto en silencio.
var ErrEventsOutOfOrder = errors.New("baseline: events must be sorted by timestamp, ascending")

// Detect aplica el rate limit configurado en cfg sobre events, y
// devuelve exactamente una decision.Decision por cada evento de
// entrada, en el mismo orden — así decisions.jsonl siempre tiene el
// mismo conjunto de request_id que events.jsonl/labels.jsonl, sin
// generar problemas de integridad artificiales al evaluarlo (ver
// internal/eval, tareas 0.7/0.8).
//
// Ventana: para el evento actual, con timestamp t, de la IP X, Detect
// cuenta cuántas peticiones "contadas" de X (según cfg.Mode) tienen
// timestamp en el intervalo cerrado [t-cfg.Window, t] — que siempre
// incluye al propio evento actual, o sea que el evento que dispara el
// límite se cuenta a sí mismo. Si ese conteo supera cfg.MaxRequests,
// la decisión es BLOCK; si no, ALLOW.
//
// "Contada" depende de cfg.Mode: en CountModeAll, toda petición
// cuenta y puede bloquearse; en CountModeAuth, solo las que
// cfg.AuthMatcher reconoce como ruta de autenticación cuentan y
// pueden bloquearse — el resto siempre es ALLOW, con
// ConfidenceScore 0, y ni siquiera entra en el conteo de ninguna IP.
//
// Detect nunca consulta ningún reloj real: el único tiempo que existe
// es event.Event.Timestamp. Tampoco importa ni consulta
// internal/groundtruth — el rate limit decide únicamente con lo que
// ve en Event, igual que exigiría cualquier detector real.
func Detect(events []event.Event, cfg Config) ([]decision.Decision, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	for i := 1; i < len(events); i++ {
		if events[i].Timestamp.Before(events[i-1].Timestamp) {
			return nil, fmt.Errorf("%w: event %d (request_id=%q) is before event %d (request_id=%q)",
				ErrEventsOutOfOrder, i, events[i].RequestID, i-1, events[i-1].RequestID)
		}
	}

	matcher := cfg.AuthMatcher
	if matcher == nil {
		matcher = event.DefaultAuthPathMatcher()
	}

	// windows guarda, por IP, los timestamps de sus peticiones
	// contadas todavía dentro de la ventana — una cola: se recorta por
	// adelante (lo que ya salió de la ventana) y se agrega por atrás
	// (el evento actual), lo que mantiene el costo por evento bajo en
	// vez de recorrer todo el historial de la IP en cada petición.
	windows := make(map[netip.Addr][]time.Time)
	decisions := make([]decision.Decision, 0, len(events))

	for _, e := range events {
		counted := cfg.Mode == CountModeAll || matcher.IsAuthPath(e.Path)
		if !counted {
			decisions = append(decisions, allowDecision(e))
			continue
		}

		queue := windows[e.ClientIP]
		cutoff := e.Timestamp.Add(-cfg.Window)
		start := 0
		for start < len(queue) && queue[start].Before(cutoff) {
			start++
		}
		queue = append(queue[start:], e.Timestamp)
		windows[e.ClientIP] = queue

		count := len(queue)
		if count > cfg.MaxRequests {
			decisions = append(decisions, blockDecision(e, count, cfg.MaxRequests))
		} else {
			decisions = append(decisions, allowDecision(e))
		}
	}

	return decisions, nil
}

func entityID(e event.Event) string {
	return "ip:" + e.ClientIP.String()
}

func allowDecision(e event.Event) decision.Decision {
	return decision.Decision{
		RequestID:    e.RequestID,
		Timestamp:    e.Timestamp,
		EntityID:     entityID(e),
		Action:       decision.ActionAllow,
		AttackVector: decision.AttackVectorUnknown,
	}
}

// confidenceScore mide cuántas veces se superó el límite, no si el
// tráfico "es" un ataque: es una heurística legible y determinista,
// NO una probabilidad estadísticamente calibrada (misma advertencia
// que decision.Decision.ConfidenceScore documenta desde la tarea
// 0.3). La fórmula 1 - MaxRequests/count se eligió en vez de
// min(count/MaxRequests, 1.0) porque esa segunda versión "satura" de
// golpe: con el doble del límite ya da 1.0 y no distingue más entre
// el doble y las cien veces el límite. Con esta fórmula:
//
//	count = MaxRequests+1 (recién se cruzó el límite) → score ≈ 0
//	count = 2×MaxRequests                             → score = 0.5
//	count = 10×MaxRequests                             → score = 0.9
//	count → ∞                                          → score → 1 (nunca lo toca)
//
// así que el score sigue creciendo, cada vez más despacio, a medida
// que el tráfico se aleja más del límite — nunca se "achata" en 1.0
// de entrada.
func confidenceScore(count, maxRequests int) float64 {
	score := 1 - float64(maxRequests)/float64(count)
	if score < 0 {
		return 0
	}
	return score
}

func blockDecision(e event.Event, count, maxRequests int) decision.Decision {
	return decision.Decision{
		RequestID:       e.RequestID,
		Timestamp:       e.Timestamp,
		EntityID:        entityID(e),
		Action:          decision.ActionBlock,
		ConfidenceScore: confidenceScore(count, maxRequests),
		AttackVector:    decision.AttackVectorUnknown,
		ContributingSignals: []decision.ContributingSignal{
			{Name: "requests_in_window", Value: float64(count), Weight: 1},
		},
		Explanation: fmt.Sprintf("%d requests from this IP in the configured window (limit: %d)", count, maxRequests),
	}
}
