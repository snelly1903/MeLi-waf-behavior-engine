// Package slowscan es el segundo detector real del motor (tarea 1.4):
// busca escaneo/enumeración lenta de rutas HTTP — un atacante que
// mantiene una tasa baja de requests, precisamente para evitar
// cualquier rate limiter, pero deja un patrón de exploración
// acumulado a lo largo de una ventana. A diferencia de
// internal/credstuffing (tarea 1.3), esta señal es por entidad
// individual (IP y/o sesión), nunca correlacionada entre IPs — mismo
// criterio que usa internal/datagen para generar el tráfico de
// escaneo lento.
//
// Este paquete nunca importa internal/groundtruth ni internal/datagen.
package slowscan

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
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/profile"
)

// ScoreWeights son los pesos relativos de cada señal en el cálculo de
// RiskScore (ver evaluateMetrics). No hace falta que sumen 1 — se
// normalizan por su suma, mismo criterio que internal/credstuffing.
type ScoreWeights struct {
	Requests float64
	Paths    float64
	NotFound float64
	Entropy  float64
	Novelty  float64
	Referer  float64
}

// Config configura el detector. Igual que internal/baseline (tarea
// 0.9) e internal/credstuffing (tarea 1.3), ningún valor tiene acá un
// default "recomendado": los umbrales se calibran en una tarea
// posterior contra un dataset separado del de reporte, nunca mirando
// la semilla 42.
type Config struct {
	// Window es la ventana de acumulación por entidad (IP o sesión) Y
	// la ventana del índice de popularidad de rutas (ver
	// NovelPathRatio) — una sola ventana para las dos cosas, mismo
	// criterio de simplicidad que profile.Store (tarea 1.2).
	Window time.Duration

	// MinRequests, MinDistinctPaths, MinNotFoundRatio, MinRouteEntropy
	// y MinNovelPathRatio son las cinco condiciones del gate — TODAS
	// deben cumplirse a la vez para que una entidad dispare (ver
	// evaluateMetrics). MinRequests y MinDistinctPaths deben ser
	// mayores que 0. Los tres ratios deben estar en [0,1].
	MinRequests       int
	MinDistinctPaths  int
	MinNotFoundRatio  float64
	MinRouteEntropy   float64
	MinNovelPathRatio float64

	// MaxVisitorsForNovelPath es el umbral de popularidad: una ruta se
	// considera "novel" (poco habitual) si, dentro de la ventana, la
	// vieron como máximo esta cantidad de IPs distintas en todo el
	// tráfico observado por este detector. Debe ser al menos 1.
	MaxVisitorsForNovelPath int

	// Weights pondera las seis señales al combinar el RiskScore.
	// Referer nunca participa del gate — solo del score (ver
	// evaluateMetrics).
	Weights ScoreWeights

	// ScoreFloor es el piso de RiskScore cuando Triggered es true.
	// Debe estar estrictamente entre 0 y 1 — mismo mecanismo y misma
	// razón que internal/credstuffing (tarea 1.3): en el borde exacto
	// del gate, los componentes normalizados de las cinco señales del
	// gate dan 0, y un detector que disparó no puede reportar riesgo
	// cero.
	ScoreFloor float64
}

// Errores centinela de configuración, comprobables individualmente
// con errors.Is.
var (
	ErrInvalidWindow                  = errors.New("slowscan: window must be greater than 0")
	ErrInvalidMinRequests             = errors.New("slowscan: min_requests must be greater than 0")
	ErrInvalidMinDistinctPaths        = errors.New("slowscan: min_distinct_paths must be greater than 0")
	ErrInvalidMinNotFoundRatio        = errors.New("slowscan: min_not_found_ratio must be between 0 and 1")
	ErrInvalidMinRouteEntropy         = errors.New("slowscan: min_route_entropy must be between 0 and 1")
	ErrInvalidMinNovelPathRatio       = errors.New("slowscan: min_novel_path_ratio must be between 0 and 1")
	ErrInvalidMaxVisitorsForNovelPath = errors.New("slowscan: max_visitors_for_novel_path must be at least 1")
	ErrInvalidScoreFloor              = errors.New("slowscan: score_floor must be strictly between 0 and 1")
	ErrInvalidWeights                 = errors.New("slowscan: weights must be finite, non-negative, and sum to more than 0")
)

// Validate comprueba que cfg tenga valores utilizables, y devuelve
// todos los problemas encontrados unidos con errors.Join.
func (cfg Config) Validate() error {
	var errs []error
	if cfg.Window <= 0 {
		errs = append(errs, ErrInvalidWindow)
	}
	if cfg.MinRequests <= 0 {
		errs = append(errs, ErrInvalidMinRequests)
	}
	if cfg.MinDistinctPaths <= 0 {
		errs = append(errs, ErrInvalidMinDistinctPaths)
	}
	if cfg.MinNotFoundRatio < 0 || cfg.MinNotFoundRatio > 1 {
		errs = append(errs, ErrInvalidMinNotFoundRatio)
	}
	if cfg.MinRouteEntropy < 0 || cfg.MinRouteEntropy > 1 {
		errs = append(errs, ErrInvalidMinRouteEntropy)
	}
	if cfg.MinNovelPathRatio < 0 || cfg.MinNovelPathRatio > 1 {
		errs = append(errs, ErrInvalidMinNovelPathRatio)
	}
	if cfg.MaxVisitorsForNovelPath < 1 {
		errs = append(errs, ErrInvalidMaxVisitorsForNovelPath)
	}
	if cfg.ScoreFloor <= 0 || cfg.ScoreFloor >= 1 {
		errs = append(errs, ErrInvalidScoreFloor)
	}
	w := cfg.Weights
	weightsFinite := isFiniteNonNegative(w.Requests) && isFiniteNonNegative(w.Paths) &&
		isFiniteNonNegative(w.NotFound) && isFiniteNonNegative(w.Entropy) &&
		isFiniteNonNegative(w.Novelty) && isFiniteNonNegative(w.Referer)
	sum := w.Requests + w.Paths + w.NotFound + w.Entropy + w.Novelty + w.Referer
	if !weightsFinite || sum <= 0 {
		errs = append(errs, ErrInvalidWeights)
	}
	return errors.Join(errs...)
}

func isFiniteNonNegative(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

// pathVisit es lo mínimo retenido en el índice de popularidad de
// rutas: cuándo y desde qué IP se pidió una ruta.
type pathVisit struct {
	timestamp time.Time
	ip        netip.Addr
}

// pathState es el estado retenido de una ruta: su watermark (nunca
// retrocede — mismo mecanismo que internal/profile, tarea 1.2, y
// internal/credstuffing, tarea 1.3) y las visitas todavía dentro de la
// ventana relativa a ese watermark.
type pathState struct {
	watermark time.Time
	visits    []pathVisit
}

// pathPopularity es el ÚNICO estado nuevo de esta tarea: cuántas IPs
// distintas, en todo el tráfico observado, pidieron cada ruta dentro
// de la ventana — la pieza que internal/profile.Store no puede dar,
// necesaria para NovelPathRatio (ver Detector.novelPathRatio).
// Reimplementado de forma autocontenida con el mismo mecanismo de
// watermark, por la misma razón que internal/credstuffing: la
// agregación acá es por ruta, no por IP/sesión, así que no hay nada
// que reutilizar de profile.Store para esto específicamente.
type pathPopularity struct {
	mu     sync.Mutex
	window time.Duration
	data   map[string]pathState
}

func newPathPopularity(window time.Duration) *pathPopularity {
	return &pathPopularity{window: window, data: make(map[string]pathState)}
}

func (p *pathPopularity) observe(path string, ip netip.Addr, timestamp time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	state := p.data[path]
	if timestamp.After(state.watermark) {
		state.watermark = timestamp
	}
	cutoff := state.watermark.Add(-p.window)

	kept := make([]pathVisit, 0, len(state.visits)+1)
	for _, v := range state.visits {
		if !v.timestamp.Before(cutoff) {
			kept = append(kept, v)
		}
	}
	visit := pathVisit{timestamp: timestamp, ip: ip}
	if !visit.timestamp.Before(cutoff) {
		kept = append(kept, visit)
	}
	state.visits = kept

	p.data[path] = state
}

// distinctVisitors devuelve cuántas IPs distintas visitaron path
// dentro de la ventana retenida.
func (p *pathPopularity) distinctVisitors(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	seen := make(map[netip.Addr]struct{})
	for _, v := range p.data[path].visits {
		seen[v.ip] = struct{}{}
	}
	return len(seen)
}

func (p *pathPopularity) sweep(now time.Time, idleTTL time.Duration) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	removed := 0
	for path, state := range p.data {
		if now.Sub(state.watermark) > idleTTL {
			delete(p.data, path)
			removed++
		}
	}
	return removed
}

// Detector es el detector de escaneo/enumeración lenta. Es seguro
// para uso concurrente.
type Detector struct {
	cfg      Config
	profiles *profile.Store // reutilizado tal cual de la tarea 1.2 — ver docs/decisiones.md, tarea 1.4
	paths    *pathPopularity
}

// NewDetector construye un Detector. Devuelve error si cfg no es
// utilizable.
func NewDetector(cfg Config) (*Detector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	profiles, err := profile.NewStore(cfg.Window)
	if err != nil {
		// No debería pasar nunca — Validate ya exige Window > 0 — pero
		// se propaga en vez de asumirlo, por si profile.NewStore agrega
		// alguna otra regla en el futuro.
		return nil, err
	}
	return &Detector{
		cfg:      cfg,
		profiles: profiles,
		paths:    newPathPopularity(cfg.Window),
	}, nil
}

// Observe registra e tanto en los perfiles de comportamiento (IP y,
// si corresponde, sesión — internal/profile, tarea 1.2) como en el
// índice de popularidad de rutas.
func (d *Detector) Observe(e event.Event) {
	d.profiles.Observe(e)
	d.paths.observe(e.Path, e.ClientIP, e.Timestamp)
}

// scope identifica, solo para el texto de Explanation, si un
// candidato de Finding salió de la perspectiva de IP o de sesión.
//
// PENDIENTE EXPLÍCITO PARA LA TAREA 1.5: finding.Finding no tiene hoy
// ningún campo estructurado para esto — el futuro engine.Decider va a
// necesitar saber, de forma estructurada (no parseando el texto de
// Explanation), qué entidad originó cada Finding, para poder correlar
// varios detectores sobre la misma entidad o auditar decisiones. Se
// mantiene Finding sin campos nuevos en esta tarea, según lo acordado
// — este comentario es el registro explícito de la deuda, ver también
// docs/decisiones.md.
type scope struct {
	label string // "ip" o "session"
	key   string
}

// Evaluate decide si, a partir del estado actual de la IP de e y,
// si existe, de su sesión, hay evidencia de escaneo lento — evaluando
// SIEMPRE la IP y, cuando e.SessionID no está vacío, TAMBIÉN la
// sesión, y devolviendo como máximo un único Finding (ver
// docs/decisiones.md, tarea 1.4, para por qué evaluar siempre la IP
// —incluso habiendo sesión— es necesario para atrapar a un atacante
// que rota session_id para quedar bajo los umbrales por sesión, sin
// por eso reintroducir falsos positivos de un NAT legítimo: el mismo
// gate completo de cinco condiciones se le aplica a la IP).
//
// Regla de desempate cuando las dos perspectivas disparan: gana la de
// mayor RiskScore; en caso de empate exacto, gana sesión, por ser la
// entidad más específica — evita atribuir el hallazgo a todo el NAT
// cuando alcanza con señalar la sesión concreta.
func (d *Detector) Evaluate(e event.Event) finding.Finding {
	ipFinding := d.evaluateMetrics(d.profiles.SnapshotIP(e.ClientIP), scope{label: "ip", key: e.ClientIP.String()})

	haveSession := e.SessionID != ""
	var sessionFinding finding.Finding
	if haveSession {
		sessionFinding = d.evaluateMetrics(d.profiles.SnapshotSession(e.SessionID), scope{label: "session", key: e.SessionID})
	}

	switch {
	case haveSession && sessionFinding.Triggered && ipFinding.Triggered:
		if ipFinding.RiskScore > sessionFinding.RiskScore {
			return ipFinding
		}
		return sessionFinding // empate o sesión mayor: gana sesión
	case haveSession && sessionFinding.Triggered:
		return sessionFinding
	case ipFinding.Triggered:
		return ipFinding
	default:
		return finding.Finding{}
	}
}

// evaluateMetrics aplica el gate y, si dispara, calcula RiskScore y
// las señales, a partir de un profile.Metrics ya calculado (por IP o
// por sesión — evaluateMetrics no distingue, solo usa los números).
func (d *Detector) evaluateMetrics(m profile.Metrics, sc scope) finding.Finding {
	total := m.Total
	distinctPaths := len(m.PathCounts)

	var notFoundRatio, withoutRefererRatio float64
	if total > 0 {
		notFoundRatio = float64(m.Status404) / float64(total)
		withoutRefererRatio = float64(m.WithoutReferer) / float64(total)
	}
	routeEntropy := normalizedEntropy(m.PathCounts, total, distinctPaths)
	novelPathRatio := d.novelPathRatio(m.PathCounts, distinctPaths)

	triggered := total >= d.cfg.MinRequests &&
		distinctPaths >= d.cfg.MinDistinctPaths &&
		notFoundRatio >= d.cfg.MinNotFoundRatio &&
		routeEntropy >= d.cfg.MinRouteEntropy &&
		novelPathRatio >= d.cfg.MinNovelPathRatio

	if !triggered {
		return finding.Finding{}
	}

	cRequests := excessComponent(float64(total), float64(d.cfg.MinRequests))
	cPaths := excessComponent(float64(distinctPaths), float64(d.cfg.MinDistinctPaths))
	cNotFound := ratioComponent(notFoundRatio, d.cfg.MinNotFoundRatio)
	cEntropy := ratioComponent(routeEntropy, d.cfg.MinRouteEntropy)
	cNovelty := ratioComponent(novelPathRatio, d.cfg.MinNovelPathRatio)
	cReferer := withoutRefererRatio // sin umbral: aporta al score tal cual, nunca al gate

	w := d.cfg.Weights
	weightSum := w.Requests + w.Paths + w.NotFound + w.Entropy + w.Novelty + w.Referer
	avg := (cRequests*w.Requests + cPaths*w.Paths + cNotFound*w.NotFound +
		cEntropy*w.Entropy + cNovelty*w.Novelty + cReferer*w.Referer) / weightSum

	// Mismo mecanismo de piso que internal/credstuffing (tarea 1.3):
	// sin él, las cinco señales del gate exactamente en su umbral
	// darían componentes en 0, y un Finding disparado no puede
	// reportar riesgo cero.
	riskScore := d.cfg.ScoreFloor + (1-d.cfg.ScoreFloor)*avg

	return finding.Finding{
		Triggered:    true,
		AttackVector: decision.AttackVectorSlowScan,
		RiskScore:    riskScore,
		ContributingSignals: []decision.ContributingSignal{
			{Name: "total_requests", Value: float64(total), Weight: w.Requests},
			{Name: "distinct_paths", Value: float64(distinctPaths), Weight: w.Paths},
			{Name: "not_found_ratio", Value: notFoundRatio, Weight: w.NotFound},
			{Name: "route_entropy_normalized", Value: routeEntropy, Weight: w.Entropy},
			{Name: "novel_path_ratio", Value: novelPathRatio, Weight: w.Novelty},
			{Name: "without_referer_ratio", Value: withoutRefererRatio, Weight: w.Referer},
		},
		Explanation: fmt.Sprintf(
			"%s:%s: %d requests across %d distinct paths, %.0f%% not-found, entropy=%.2f, %.0f%% novel paths within the window",
			sc.label, sc.key, total, distinctPaths, notFoundRatio*100, routeEntropy, novelPathRatio*100,
		),
	}
}

// novelPathRatio es la fracción de las rutas distintas de m que son
// "novel" según el índice global de popularidad — ver el tipo
// pathPopularity y docs/decisiones.md, tarea 1.4, para la definición
// completa y por qué esta es la opción mínima técnicamente correcta
// dado lo que el motor puede observar hoy (sin catálogo externo de
// rutas reales, sin ground truth).
func (d *Detector) novelPathRatio(pathCounts map[string]int, distinctPaths int) float64 {
	if distinctPaths == 0 {
		return 0
	}
	novel := 0
	for path := range pathCounts {
		if d.paths.distinctVisitors(path) <= d.cfg.MaxVisitorsForNovelPath {
			novel++
		}
	}
	return float64(novel) / float64(distinctPaths)
}

// normalizedEntropy es la entropía de Shannon de la distribución de
// rutas de pathCounts, normalizada a [0,1] dividiendo por
// log2(distinctPaths) — así perfiles con distinta cantidad de rutas
// distintas siguen siendo comparables con el mismo umbral (ver
// docs/decisiones.md, tarea 1.4, con dos ejemplos calculados a mano).
// Da 0 si hay una sola ruta distinta o ninguna — sin diversidad que
// medir, por definición.
func normalizedEntropy(pathCounts map[string]int, total, distinctPaths int) float64 {
	if distinctPaths <= 1 || total == 0 {
		return 0
	}
	var h float64
	for _, count := range pathCounts {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(total)
		h -= p * math.Log2(p)
	}
	max := math.Log2(float64(distinctPaths))
	if max <= 0 {
		return 0
	}
	return h / max
}

// excessComponent es la misma heurística "cuánto se superó el umbral"
// ya usada y justificada en internal/baseline (tarea 0.9) e
// internal/credstuffing (tarea 1.3): 1 - umbral/valor, siempre en
// [0,1), 0 justo en el umbral.
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

// Sweep elimina, tanto de los perfiles de comportamiento como del
// índice de popularidad de rutas, cualquier clave inactiva por más de
// idleTTL respecto a now, y devuelve cuántas eliminó en total. now se
// recibe como parámetro (nunca time.Now() internamente), así que
// sigue siendo determinista y testeable — mismo criterio que
// internal/profile.Store.Sweep e internal/credstuffing.Detector.Sweep.
func (d *Detector) Sweep(now time.Time, idleTTL time.Duration) int {
	return d.profiles.Sweep(now, idleTTL) + d.paths.sweep(now, idleTTL)
}
