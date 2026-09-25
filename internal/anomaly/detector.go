// Package anomaly es el tercer detector real del motor (tarea 1.6):
// un modelo estadístico online — media/varianza calculadas con el
// algoritmo de Welford y z-scores unilaterales — que aprende cómo se
// ve "normal" un perfil de comportamiento y puntúa cuánto se aleja
// cada observación de esa línea de base. A diferencia de
// internal/credstuffing e internal/slowscan (que exigen varias
// señales CRUDAS cruzando SUS PROPIOS umbrales a la vez), este
// detector combina evidencia entre features en una única medida de
// "qué tan raro es esto" — es la diferencia de fondo entre un
// detector de reglas y uno genuinamente estadístico.
//
// Este paquete nunca importa internal/groundtruth ni internal/datagen.
package anomaly

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/profile"
)

// featureIndex enumera las cinco features estadísticas — ver
// extractFeatures para su definición exacta y docs/decisiones.md
// (tarea 1.6) para por qué se eligieron estas cinco y no otras.
type featureIndex int

const (
	featureNotFound featureIndex = iota
	featureFailedAuth
	featurePathDiversity
	featureReferer
	featureAccountDiversity
	featureCount
)

var featureNames = [featureCount]string{
	"not_found_ratio_z",
	"failed_auth_ratio_z",
	"path_diversity_ratio_z",
	"without_referer_ratio_z",
	"account_diversity_ratio_z",
}

// FeatureWeights son los pesos relativos de cada feature al combinar
// el score final. No hace falta que sumen 1 — se normalizan por su
// suma, mismo criterio que en internal/credstuffing e
// internal/slowscan.
type FeatureWeights struct {
	NotFound         float64
	FailedAuth       float64
	PathDiversity    float64
	Referer          float64
	AccountDiversity float64
}

func (w FeatureWeights) asArray() [featureCount]float64 {
	return [featureCount]float64{w.NotFound, w.FailedAuth, w.PathDiversity, w.Referer, w.AccountDiversity}
}

// Config configura el detector. Ningún valor acá está calibrado
// todavía contra un dataset real — mismo criterio que
// internal/baseline (tarea 0.9), internal/credstuffing (tarea 1.3) e
// internal/slowscan (tarea 1.4).
type Config struct {
	// Window es la ventana de retención del profile.Store privado de
	// este detector (ver docs/decisiones.md, tarea 1.6, sobre por qué
	// tiene su propia copia en vez de compartir la de otro detector).
	Window time.Duration

	// MinSamples es cuántas muestras necesita el baseline global antes
	// de que Evaluate empiece a puntuar (warm-up). Debe ser al menos
	// 2 — con menos, la varianza muestral (M2/(n-1)) ni siquiera está
	// definida.
	MinSamples int

	// ZSaturation es el z-score al que el componente normalizado de
	// una feature llega a 0.5 (component = z/(z+ZSaturation)). Debe
	// ser mayor que 0.
	ZSaturation float64

	// TriggerThreshold es el umbral sobre el score combinado (no sobre
	// cada feature por separado) que decide Triggered. Debe estar
	// estrictamente entre 0 y 1: en 0 dispararía con cualquier
	// desviación (incluida ninguna), en 1 nunca podría disparar
	// (combined siempre es < 1).
	TriggerThreshold float64

	// Weights pondera las cinco features al combinar el score.
	Weights FeatureWeights

	// ScoreFloor es el piso de RiskScore cuando Triggered es true —
	// mismo mecanismo que internal/credstuffing/internal/slowscan, acá
	// más una defensa adicional que la única barrera: como
	// TriggerThreshold > 0 ya es obligatorio, RiskScore queda > 0 en
	// el borde exacto solo por eso. Se mantiene por consistencia de
	// diseño entre los tres detectores. Debe estar estrictamente entre
	// 0 y 1.
	ScoreFloor float64
}

// Errores centinela de configuración, comprobables individualmente
// con errors.Is.
var (
	ErrInvalidWindow           = errors.New("anomaly: window must be greater than 0")
	ErrInvalidMinSamples       = errors.New("anomaly: min_samples must be at least 2")
	ErrInvalidZSaturation      = errors.New("anomaly: z_saturation must be greater than 0")
	ErrInvalidTriggerThreshold = errors.New("anomaly: trigger_threshold must be strictly between 0 and 1")
	ErrInvalidScoreFloor       = errors.New("anomaly: score_floor must be strictly between 0 and 1")
	ErrInvalidWeights          = errors.New("anomaly: weights must be finite, non-negative, and sum to more than 0")
)

// Validate comprueba que cfg tenga valores utilizables, y devuelve
// todos los problemas encontrados unidos con errors.Join.
func (cfg Config) Validate() error {
	var errs []error
	if cfg.Window <= 0 {
		errs = append(errs, ErrInvalidWindow)
	}
	if cfg.MinSamples < 2 {
		errs = append(errs, ErrInvalidMinSamples)
	}
	if cfg.ZSaturation <= 0 {
		errs = append(errs, ErrInvalidZSaturation)
	}
	if cfg.TriggerThreshold <= 0 || cfg.TriggerThreshold >= 1 {
		errs = append(errs, ErrInvalidTriggerThreshold)
	}
	if cfg.ScoreFloor <= 0 || cfg.ScoreFloor >= 1 {
		errs = append(errs, ErrInvalidScoreFloor)
	}
	w := cfg.Weights.asArray()
	sum := 0.0
	finite := true
	for _, v := range w {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			finite = false
		}
		sum += v
	}
	if !finite || sum <= 0 {
		errs = append(errs, ErrInvalidWeights)
	}
	return errors.Join(errs...)
}

// featureStats es el estado de Welford de UNA feature: su media y M2
// (suma de cuadrados de las diferencias respecto a la media
// incremental — de ahí sale la varianza: M2/(n-1)).
type featureStats struct {
	mean float64
	m2   float64
}

// baselineSnapshot es una copia inmutable del estado del baseline en
// un instante — nunca comparte memoria con el estado interno.
type baselineSnapshot struct {
	n     int
	stats [featureCount]featureStats
}

// baseline es el estado estadístico GLOBAL — no indexado por entidad
// (ver docs/decisiones.md, tarea 1.6, sobre por qué la población es
// global y no por IP/sesión). Es un puñado de escalares: nunca crece
// con la cantidad de entidades vistas, a diferencia de
// internal/profile.Store.
//
// Dos limitaciones conocidas, documentadas explícitamente (ver
// docs/decisiones.md, tarea 1.6):
//
//  1. Al ser una única población global, mezcla comportamientos
//     naturalmente distintos (por ejemplo, un cliente de API y un
//     navegador humano tienen formas de tráfico distintas por
//     definición, no porque uno sea sospechoso) en una sola media y
//     varianza. Además, cada evento evaluado aporta una muestra —
//     una entidad muy activa contribuye muchas muestras
//     correlacionadas entre sí, pudiendo sesgar el baseline hacia su
//     propia forma de tráfico.
//  2. Este detector excluye deliberadamente el volumen crudo (Total)
//     de sus features — solo mira ratios/proporciones. Por diseño, se
//     enfoca en anomalías de la FORMA del comportamiento, y no
//     pretende detectar por sí solo un incremento puramente
//     volumétrico (eso ya es responsabilidad de
//     internal/credstuffing/internal/slowscan, y de un futuro
//     enriquecimiento si hiciera falta).
type baseline struct {
	mu    sync.Mutex
	n     int
	stats [featureCount]featureStats
}

// snapshot devuelve una copia del estado actual, para puntuar contra
// él SIN mantener el lock tomado y sin que una actualización
// concurrente lo cambie a mitad de un cálculo.
func (b *baseline) snapshot() baselineSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return baselineSnapshot{n: b.n, stats: b.stats}
}

// update aplica el paso de actualización de Welford para las cinco
// features de x, en una sola pasada — n es compartido entre las
// cinco porque siempre se actualizan juntas, una vez por muestra.
func (b *baseline) update(x [featureCount]float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.n++
	n := float64(b.n)
	for i := range x {
		delta := x[i] - b.stats[i].mean
		b.stats[i].mean += delta / n
		delta2 := x[i] - b.stats[i].mean
		b.stats[i].m2 += delta * delta2
	}
}

// zEpsilon es el umbral por debajo del cual una desviación estándar
// se trata como "todavía cero" — evita NaN/Inf al dividir. Con
// varianza (todavía) cero, no se puede calcular de forma significativa
// "cuántos desvíos estándar" de algo que no tiene desvío: se trata esa
// feature como no informativa esta ronda (z=0), la opción conservadora,
// no una que haya que adivinar.
const zEpsilon = 1e-9

// scope identifica si un candidato de Finding salió de la perspectiva
// de IP o de sesión — mismo formato que internal/slowscan (tarea 1.4),
// reimplementado acá de forma autocontenida (ver
// docs/decisiones.md, tarea 1.6).
type scope struct {
	label string // "ip" o "session"
	key   string
}

// Detector es el detector estadístico de anomalías. Es seguro para
// uso concurrente.
type Detector struct {
	cfg      Config
	profiles *profile.Store
	baseline *baseline
}

// NewDetector construye un Detector. Devuelve error si cfg no es
// utilizable.
func NewDetector(cfg Config) (*Detector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	profiles, err := profile.NewStore(cfg.Window)
	if err != nil {
		return nil, err
	}
	return &Detector{cfg: cfg, profiles: profiles, baseline: &baseline{}}, nil
}

// Observe registra e en los perfiles de comportamiento (IP y, si
// corresponde, sesión — internal/profile, tarea 1.2). El baseline
// estadístico NO se toca acá — se actualiza dentro de Evaluate,
// después de puntuar, por la razón que explica Evaluate.
func (d *Detector) Observe(e event.Event) {
	d.profiles.Observe(e)
}

// Evaluate calcula las features de la IP de e y, si existe, de su
// sesión, las puntúa contra el baseline estadístico ACTUAL (tomado
// como una única foto al principio, antes de que ninguna de las dos
// evaluaciones lo actualice), decide un Finding por cada una, y recién
// después actualiza el baseline — con la muestra de cada scope, salvo
// que esa muestra en particular haya resultado Triggered después del
// warm-up (ver el bloque de actualización más abajo).
//
// Puntuar contra el baseline previo y actualizar después es
// deliberado (preferencia explícita del diseño, ver
// docs/decisiones.md, tarea 1.6): así el propio punto anómalo nunca
// reduce artificialmente su propio z-score por haberse promediado a
// sí mismo dentro de la media antes de calcularlo. Es una excepción
// documentada al patrón "Observe muta, Evaluate solo lee" que sí
// siguen internal/credstuffing e internal/slowscan — el contrato
// público hacia quien llama (Observe y después Evaluate) no cambia.
//
// Igual que internal/slowscan, evalúa SIEMPRE la IP y, si
// e.SessionID no está vacío, TAMBIÉN la sesión, y devuelve como
// máximo un único Finding: gana el de mayor RiskScore; en empate
// exacto, gana sesión, por ser la entidad más específica — mismo
// criterio que la tarea 1.4.
func (d *Detector) Evaluate(e event.Event) finding.Finding {
	bl := d.baseline.snapshot()
	warm := bl.n < d.cfg.MinSamples

	ipFeatures := extractFeatures(d.profiles.SnapshotIP(e.ClientIP))
	var ipFinding finding.Finding
	if !warm {
		ipFinding = d.evaluateFeatures(ipFeatures, bl, scope{label: "ip", key: e.ClientIP.String()})
	}

	haveSession := e.SessionID != ""
	var sessionFeatures [featureCount]float64
	var sessionFinding finding.Finding
	if haveSession {
		sessionFeatures = extractFeatures(d.profiles.SnapshotSession(e.SessionID))
		if !warm {
			sessionFinding = d.evaluateFeatures(sessionFeatures, bl, scope{label: "session", key: e.SessionID})
		}
	}

	// Actualización del baseline: cada snapshot (IP y, si existe,
	// sesión) es su propia muestra poblacional independiente. Durante
	// el warm-up se agrega SIEMPRE (todavía no hay ningún juicio de
	// "anómalo" que hacer). Después del warm-up, una muestra que
	// resultó Triggered NO se agrega — así una anomalía real nunca
	// termina absorbida como si fuera parte de lo normal
	// (baseline poisoning). Si el tráfico ya es mayormente ataque
	// desde el arranque, esta protección no puede hacer nada por sí
	// sola — limitación conocida de cualquier baseline aprendido sin
	// supervisión, documentada, no resuelta acá.
	if warm || !ipFinding.Triggered {
		d.baseline.update(ipFeatures)
	}
	if haveSession && (warm || !sessionFinding.Triggered) {
		d.baseline.update(sessionFeatures)
	}

	switch {
	case haveSession && sessionFinding.Triggered && ipFinding.Triggered:
		if ipFinding.RiskScore > sessionFinding.RiskScore {
			return ipFinding
		}
		return sessionFinding
	case haveSession && sessionFinding.Triggered:
		return sessionFinding
	case ipFinding.Triggered:
		return ipFinding
	default:
		return finding.Finding{}
	}
}

// extractFeatures deriva las cinco features de m, todas como ratios
// (nunca conteos crudos — ver docs/decisiones.md, tarea 1.6, sobre
// por qué: este detector se enfoca en la FORMA/proporciones del
// comportamiento, no pretende detectar por sí solo un incremento
// puramente volumétrico, eso ya es trabajo de
// internal/credstuffing/internal/slowscan). Si m.Total es 0, las
// cinco quedan en 0 — no hay ninguna proporción que calcular todavía.
func extractFeatures(m profile.Metrics) [featureCount]float64 {
	var f [featureCount]float64
	if m.Total == 0 {
		return f
	}
	total := float64(m.Total)
	f[featureNotFound] = float64(m.Status404) / total
	f[featureFailedAuth] = float64(m.Status401Or403) / total
	f[featurePathDiversity] = float64(len(m.PathCounts)) / total
	f[featureReferer] = float64(m.WithoutReferer) / total
	f[featureAccountDiversity] = float64(m.DistinctAccounts) / total
	return f
}

// evaluateFeatures calcula el z-score unilateral de cada feature de x
// contra bl, los normaliza y combina, y arma el Finding si el score
// combinado cruza cfg.TriggerThreshold.
func (d *Detector) evaluateFeatures(x [featureCount]float64, bl baselineSnapshot, sc scope) finding.Finding {
	var zs, components [featureCount]float64
	for i := range x {
		var stddev float64
		if bl.n > 1 {
			variance := bl.stats[i].m2 / float64(bl.n-1)
			stddev = math.Sqrt(variance)
		}
		var z float64
		if stddev > zEpsilon {
			z = (x[i] - bl.stats[i].mean) / stddev
			if z < 0 {
				z = 0 // z-score unilateral: solo un incremento es sospechoso
			}
		}
		zs[i] = z
		components[i] = z / (z + d.cfg.ZSaturation)
	}

	weights := d.cfg.Weights.asArray()
	var weightedSum, weightSum float64
	for i := range components {
		weightedSum += components[i] * weights[i]
		weightSum += weights[i]
	}
	combined := weightedSum / weightSum

	if combined < d.cfg.TriggerThreshold {
		return finding.Finding{}
	}

	riskScore := d.cfg.ScoreFloor + (1-d.cfg.ScoreFloor)*combined

	signals := make([]decision.ContributingSignal, featureCount)
	for i := range zs {
		signals[i] = decision.ContributingSignal{Name: featureNames[i], Value: zs[i], Weight: weights[i]}
	}

	return finding.Finding{
		Triggered: true,
		// Deliberadamente "unknown", nunca un vector inventado: este
		// detector identifica una anomalía genérica en la forma del
		// comportamiento, no sabe de qué ataque específico se trata.
		// decision.AttackVectorUnknown ya es un caso de primera clase
		// en el evaluador desde la tarea 0.7
		// (internal/eval/vector.go, EvaluateVectorAttribution): se
		// excluye del balde "Incorrecto" y se cuenta aparte como
		// "Desconocido" — la semántica honesta que corresponde.
		// Inventar un vector nuevo (por ejemplo "anomaly") rompería
		// eso: como el ground truth del evaluador solo conoce
		// legit/credential_stuffing/slow_scan, cualquier decisión con
		// un vector nuevo caería siempre en "Incorrecto" en esa
		// comparación, penalizando injustamente a un detector que
		// está siendo honesto sobre sus límites.
		AttackVector:        decision.AttackVectorUnknown,
		RiskScore:           riskScore,
		ContributingSignals: signals,
		Explanation: fmt.Sprintf(
			"statistical anomaly (combined score %.2f, n=%d): not_found z=%.2f, failed_auth z=%.2f, path_diversity z=%.2f, without_referer z=%.2f, account_diversity z=%.2f",
			combined, bl.n, zs[featureNotFound], zs[featureFailedAuth], zs[featurePathDiversity], zs[featureReferer], zs[featureAccountDiversity],
		),
		EntityID: sc.label + ":" + sc.key,
	}
}

// Sweep reenvía al profile.Store privado — el baseline estadístico en
// sí (un puñado de escalares globales, no indexados por entidad) no
// necesita ninguna limpieza: nunca crece con la cantidad de entidades
// vistas.
func (d *Detector) Sweep(now time.Time, idleTTL time.Duration) int {
	return d.profiles.Sweep(now, idleTTL)
}
