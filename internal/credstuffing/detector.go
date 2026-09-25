// Package credstuffing es el primer detector real del motor (tarea
// 1.3): busca credential stuffing distribuido de bajo volumen por IP,
// correlacionando actividad entre múltiples IPs de un mismo grupo de
// red (ASN) dentro de una ventana temporal. Deliberadamente no
// depende de que ninguna IP individual supere ningún umbral por sí
// sola — el baseline de la Fase 0 (internal/baseline, tarea 0.9) ya
// demostró con datos reales que esa técnica no alcanza contra este
// patrón de ataque.
//
// Este paquete nunca importa internal/groundtruth ni internal/datagen
// — decide únicamente con lo que ve en event.Event y con lo que le
// informe el NetworkResolver inyectado, igual que exige el resto del
// motor desde la tarea 0.2.
package credstuffing

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
)

// NetworkResolver resuelve un identificador opaco de grupo de red
// (por ejemplo, un ASN) a partir de una IP. El detector nunca
// interpreta el contenido de group — solo lo usa como clave de
// agrupación. ok=false significa "no se pudo resolver"; ver
// Detector.Observe para qué hace el detector en ese caso.
//
// Definida acá, en el paquete que la consume, no en quien la
// implementa — mismo criterio que engine.Decider (tarea 1.1). En esta
// tarea no existe ninguna implementación real: los tests usan un fake
// determinista. La integración con una fuente real de ASN queda para
// una tarea posterior.
type NetworkResolver interface {
	Resolve(ip netip.Addr) (group string, ok bool)
}

// UnavailableNetworkResolver es un NetworkResolver de PRODUCCIÓN (no
// un fake de test) para usar mientras no exista ningún proveedor real
// de ASN/grupo de red — ver docs/decisiones.md, tarea 1.5. Resolve
// siempre devuelve ok=false, así que, según la propia regla de
// Detector.Observe, ninguna IP entra jamás a ninguna correlación: el
// detector queda estructuralmente inerte (Triggered siempre false),
// pero corriendo de verdad — Observe/Evaluate se siguen llamando en
// cada evento, la degradación es explícita y segura, no un bypass
// oculto. Reemplazar esto por un NetworkResolver real (cuando exista
// un proveedor) es un cambio de una sola línea en quien construye el
// Detector — no requiere tocar nada de este paquete.
type UnavailableNetworkResolver struct{}

// Resolve implementa NetworkResolver.
func (UnavailableNetworkResolver) Resolve(netip.Addr) (string, bool) {
	return "", false
}

// ScoreWeights son los pesos relativos de cada señal en el cálculo de
// RiskScore (ver Detector.Evaluate). No hace falta que sumen 1 — se
// normalizan por su suma en el momento de calcular el score, mismo
// criterio que decision.ContributingSignal.Weight desde la tarea 0.3.
type ScoreWeights struct {
	IPs      float64
	Accounts float64
	Attempts float64
	Ratio    float64
}

// Config configura el detector. Ningún valor tiene un default
// "recomendado" en este archivo a propósito: los umbrales se calibran
// en una tarea posterior contra un dataset separado del de reporte
// (mismo criterio que internal/baseline, tarea 0.9) — no se eligen
// mirando la semilla 42.
type Config struct {
	// Window es la ventana de correlación por grupo de red.
	Window time.Duration

	// MinDistinctIPs, MinDistinctAccounts, MinAttempts y
	// MinFailedRatio son las cuatro condiciones del gate — TODAS deben
	// cumplirse a la vez para que Evaluate dispare (ver Evaluate).
	// MinDistinctIPs y MinAttempts deben ser mayores que 0.
	// MinDistinctAccounts puede ser 0 (deshabilita esa condición del
	// gate; documentado como válido pero inusual). MinFailedRatio debe
	// estar en [0,1].
	MinDistinctIPs      int
	MinDistinctAccounts int
	MinAttempts         int
	MinFailedRatio      float64

	// Weights pondera las cuatro señales al combinar el RiskScore.
	Weights ScoreWeights

	// ScoreFloor es el piso de RiskScore cuando Triggered es true —
	// ver Evaluate para el porqué existe. Debe estar estrictamente
	// entre 0 y 1.
	ScoreFloor float64

	// AuthMatcher decide qué rutas cuentan como intentos de
	// autenticación. Si es nil, se usa event.DefaultAuthPathMatcher().
	// Reutilizado tal cual de la tarea 0.2, sin ninguna lógica nueva de
	// reconocimiento de rutas.
	AuthMatcher *event.AuthPathMatcher

	// Resolver resuelve el grupo de red de una IP. Obligatorio.
	Resolver NetworkResolver
}

// Errores centinela de configuración, comprobables individualmente
// con errors.Is.
var (
	ErrInvalidWindow              = errors.New("credstuffing: window must be greater than 0")
	ErrInvalidMinDistinctIPs      = errors.New("credstuffing: min_distinct_ips must be greater than 0")
	ErrInvalidMinDistinctAccounts = errors.New("credstuffing: min_distinct_accounts must not be negative")
	ErrInvalidMinAttempts         = errors.New("credstuffing: min_attempts must be greater than 0")
	ErrInvalidMinFailedRatio      = errors.New("credstuffing: min_failed_ratio must be between 0 and 1")
	ErrInvalidScoreFloor          = errors.New("credstuffing: score_floor must be strictly between 0 and 1")
	ErrInvalidWeights             = errors.New("credstuffing: weights must be finite, non-negative, and sum to more than 0")
	ErrNilResolver                = errors.New("credstuffing: resolver is required")
)

// Validate comprueba que cfg tenga valores utilizables, y devuelve
// todos los problemas encontrados unidos con errors.Join.
func (cfg Config) Validate() error {
	var errs []error
	if cfg.Window <= 0 {
		errs = append(errs, ErrInvalidWindow)
	}
	if cfg.MinDistinctIPs <= 0 {
		errs = append(errs, ErrInvalidMinDistinctIPs)
	}
	if cfg.MinDistinctAccounts < 0 {
		errs = append(errs, ErrInvalidMinDistinctAccounts)
	}
	if cfg.MinAttempts <= 0 {
		errs = append(errs, ErrInvalidMinAttempts)
	}
	if cfg.MinFailedRatio < 0 || cfg.MinFailedRatio > 1 {
		errs = append(errs, ErrInvalidMinFailedRatio)
	}
	if cfg.ScoreFloor <= 0 || cfg.ScoreFloor >= 1 {
		errs = append(errs, ErrInvalidScoreFloor)
	}
	w := cfg.Weights
	weightsFinite := isFiniteNonNegative(w.IPs) && isFiniteNonNegative(w.Accounts) &&
		isFiniteNonNegative(w.Attempts) && isFiniteNonNegative(w.Ratio)
	if !weightsFinite || (w.IPs+w.Accounts+w.Attempts+w.Ratio) <= 0 {
		errs = append(errs, ErrInvalidWeights)
	}
	if cfg.Resolver == nil {
		errs = append(errs, ErrNilResolver)
	}
	return errors.Join(errs...)
}

func isFiniteNonNegative(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

// observation es lo mínimo que se retiene por evento de autenticación:
// suficiente para las cuatro señales del gate, nada más.
type observation struct {
	timestamp     time.Time
	ip            netip.Addr
	loginUserHash string
	statusCode    int
}

// groupState es el estado retenido de un grupo de red: su watermark
// (el timestamp más reciente observado, que nunca retrocede) y las
// observaciones todavía dentro de la ventana relativa a ese watermark
// — mismo concepto de la tarea 1.2 (internal/profile), reimplementado
// acá de forma autocontenida porque la agregación es distinta (por
// grupo de red, no por IP/sesión) y para no modificar un componente ya
// probado. Ver docs/decisiones.md, tarea 1.3.
type groupState struct {
	watermark time.Time
	queue     []observation
}

// Detector es el detector de credential stuffing distribuido. Es
// seguro para uso concurrente.
type Detector struct {
	cfg     Config
	matcher *event.AuthPathMatcher

	mu     sync.Mutex
	groups map[string]groupState
}

// NewDetector construye un Detector. Devuelve error si cfg no es
// utilizable (ver Config.Validate).
func NewDetector(cfg Config) (*Detector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	matcher := cfg.AuthMatcher
	if matcher == nil {
		matcher = event.DefaultAuthPathMatcher()
	}
	return &Detector{
		cfg:     cfg,
		matcher: matcher,
		groups:  make(map[string]groupState),
	}, nil
}

// Observe registra e en el grupo de red de e.ClientIP, si y solo si e
// es una petición a una ruta de autenticación (según cfg.AuthMatcher)
// y cfg.Resolver puede resolver un grupo de red para e.ClientIP. Si
// cualquiera de las dos condiciones falla, Observe no hace nada — un
// evento que no es de autenticación no le interesa a este detector, y
// un IP no resoluble queda deliberadamente excluido de toda
// correlación (ver docs/decisiones.md, tarea 1.3: agrupar direcciones
// "desconocidas" juntas sería mezclar tráfico no relacionado de todo
// el mundo en una falsa campaña).
//
// No asume que los eventos llegan ordenados por timestamp — mismo
// mecanismo de watermark que internal/profile (tarea 1.2): cada grupo
// de red mantiene el máximo timestamp visto, que nunca retrocede, y la
// ventana se interpreta siempre respecto a ese watermark.
func (d *Detector) Observe(e event.Event) {
	if !d.matcher.IsAuthPath(e.Path) {
		return
	}
	group, ok := d.cfg.Resolver.Resolve(e.ClientIP)
	if !ok {
		return
	}

	obs := observation{
		timestamp:     e.Timestamp,
		ip:            e.ClientIP,
		loginUserHash: e.LoginUserHash,
		statusCode:    e.StatusCode,
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	state := d.groups[group]
	if obs.timestamp.After(state.watermark) {
		state.watermark = obs.timestamp
	}
	cutoff := state.watermark.Add(-d.cfg.Window)

	kept := make([]observation, 0, len(state.queue)+1)
	for _, o := range state.queue {
		if !o.timestamp.Before(cutoff) {
			kept = append(kept, o)
		}
	}
	if !obs.timestamp.Before(cutoff) {
		kept = append(kept, obs)
	}
	state.queue = kept

	d.groups[group] = state
}

// Evaluate decide si, a partir del estado actual del grupo de red de
// e.ClientIP, hay evidencia de una campaña de credential stuffing
// distribuido. Devuelve un finding.Finding{} (Triggered=false) sin
// tocar ningún estado si e no es una petición de autenticación o si
// e.ClientIP no se pudo resolver a un grupo de red — este detector
// solo tiene una opinión sobre intentos de autenticación con grupo de
// red conocido; combinar esto con el resto del tráfico de una entidad
// es responsabilidad del futuro engine.Decider, no de este detector.
//
// Se espera que quien llama haya llamado Observe(e) antes de
// Evaluate(e) para el mismo evento, así el propio e ya está incluido
// en el agregado que se evalúa — mismo contrato de dos pasos que
// internal/profile.Store (tarea 1.2).
func (d *Detector) Evaluate(e event.Event) finding.Finding {
	if !d.matcher.IsAuthPath(e.Path) {
		return finding.Finding{}
	}
	group, ok := d.cfg.Resolver.Resolve(e.ClientIP)
	if !ok {
		return finding.Finding{}
	}

	d.mu.Lock()
	state := d.groups[group]
	obs := make([]observation, len(state.queue))
	copy(obs, state.queue)
	d.mu.Unlock()

	return d.evaluateGroup(group, obs)
}

// evaluateGroup aplica el gate y, si dispara, calcula RiskScore y las
// señales — sin tocar ningún estado compartido (obs ya es una copia).
func (d *Detector) evaluateGroup(group string, obs []observation) finding.Finding {
	distinctIPs := make(map[netip.Addr]struct{})
	distinctAccounts := make(map[string]struct{})
	var failed int

	for _, o := range obs {
		distinctIPs[o.ip] = struct{}{}
		if o.loginUserHash != "" {
			distinctAccounts[o.loginUserHash] = struct{}{}
		}
		if o.statusCode == 401 || o.statusCode == 403 {
			failed++
		}
	}
	total := len(obs)

	var failedRatio float64
	if total > 0 {
		failedRatio = float64(failed) / float64(total)
	}

	triggered := len(distinctIPs) >= d.cfg.MinDistinctIPs &&
		len(distinctAccounts) >= d.cfg.MinDistinctAccounts &&
		total >= d.cfg.MinAttempts &&
		failedRatio >= d.cfg.MinFailedRatio

	if !triggered {
		return finding.Finding{}
	}

	cIPs := excessComponent(float64(len(distinctIPs)), float64(d.cfg.MinDistinctIPs))
	cAccounts := excessComponent(float64(len(distinctAccounts)), float64(d.cfg.MinDistinctAccounts))
	cAttempts := excessComponent(float64(total), float64(d.cfg.MinAttempts))
	cRatio := ratioComponent(failedRatio, d.cfg.MinFailedRatio)

	w := d.cfg.Weights
	weightSum := w.IPs + w.Accounts + w.Attempts + w.Ratio
	avg := (cIPs*w.IPs + cAccounts*w.Accounts + cAttempts*w.Attempts + cRatio*w.Ratio) / weightSum

	// RiskScore = piso + (1-piso)*promedio. Con las cuatro señales
	// exactamente en su umbral, cada componente da 0, así que sin este
	// piso el score sería 0 pese a que Triggered es true — un detector
	// que disparó no puede reportar riesgo cero, sería contradictorio
	// para quien lea la decisión. El piso garantiza RiskScore ∈
	// [ScoreFloor, 1) siempre que Triggered sea true: sigue siendo una
	// heurística legible (arranca en ScoreFloor apenas se cruzan los
	// cuatro umbrales, y crece hacia 1 cuanto más se los supera), nunca
	// una probabilidad calibrada.
	riskScore := d.cfg.ScoreFloor + (1-d.cfg.ScoreFloor)*avg

	return finding.Finding{
		Triggered:    true,
		AttackVector: decision.AttackVectorCredentialStuffing,
		RiskScore:    riskScore,
		ContributingSignals: []decision.ContributingSignal{
			{Name: "distinct_ips_in_window", Value: float64(len(distinctIPs)), Weight: w.IPs},
			{Name: "distinct_accounts_in_window", Value: float64(len(distinctAccounts)), Weight: w.Accounts},
			{Name: "auth_attempts_in_window", Value: float64(total), Weight: w.Attempts},
			{Name: "failed_auth_ratio", Value: failedRatio, Weight: w.Ratio},
		},
		// El grupo de red ya queda identificado en EntityID — acá no se
		// repite, Explanation se enfoca en el porqué (tarea 1.5).
		Explanation: fmt.Sprintf(
			"%d distinct IPs, %d distinct accounts, %d auth attempts, %.0f%% failed (401/403) within the window",
			len(distinctIPs), len(distinctAccounts), total, failedRatio*100,
		),
		EntityID: "network:" + group,
	}
}

// excessComponent es la misma heurística "cuánto se superó el umbral"
// ya usada y justificada en internal/baseline (tarea 0.9):
// 1 - umbral/valor, siempre en [0,1), 0 justo en el umbral, creciendo
// cada vez más despacio a medida que valor se aleja de threshold, sin
// tocar nunca 1.
func excessComponent(actual, threshold float64) float64 {
	if actual <= 0 {
		return 0
	}
	score := 1 - threshold/actual
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

// ratioComponent normaliza un ratio ya acotado en [0,1] contra su
// mínimo: 0 justo en el mínimo, 1 cuando el ratio llega a 1.
func ratioComponent(actual, min float64) float64 {
	if min >= 1 {
		return 0
	}
	score := (actual - min) / (1 - min)
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

// Sweep elimina cualquier grupo de red cuyo watermark tenga más de
// idleTTL de antigüedad respecto a now, y devuelve cuántos eliminó.
// now se recibe como parámetro (nunca time.Now() internamente), así
// que sigue siendo determinista y testeable — mismo criterio que
// internal/profile.Store.Sweep (tarea 1.2). La cardinalidad de grupos
// de red es naturalmente chica (a lo sumo unos pocos miles de ASN en
// el mundo real), así que el riesgo de crecimiento sin límite acá es
// mucho menor que en internal/profile; Sweep se ofrece igual, por
// consistencia y por si hiciera falta.
func (d *Detector) Sweep(now time.Time, idleTTL time.Duration) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	removed := 0
	for group, state := range d.groups {
		if now.Sub(state.watermark) > idleTTL {
			delete(d.groups, group)
			removed++
		}
	}
	return removed
}
