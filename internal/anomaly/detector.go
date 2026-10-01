// Detecta anomalías estadísticas por IP y sesión con z-scores sobre una línea base online (Welford).
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

type Config struct {
	Window time.Duration

	MinSamples int

	ZSaturation float64

	TriggerThreshold float64

	Weights FeatureWeights

	ScoreFloor float64
}

var (
	ErrInvalidWindow           = errors.New("anomaly: window must be greater than 0")
	ErrInvalidMinSamples       = errors.New("anomaly: min_samples must be at least 2")
	ErrInvalidZSaturation      = errors.New("anomaly: z_saturation must be greater than 0")
	ErrInvalidTriggerThreshold = errors.New("anomaly: trigger_threshold must be strictly between 0 and 1")
	ErrInvalidScoreFloor       = errors.New("anomaly: score_floor must be strictly between 0 and 1")
	ErrInvalidWeights          = errors.New("anomaly: weights must be finite, non-negative, and sum to more than 0")
)

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

type featureStats struct {
	mean float64
	m2   float64
}

type baselineSnapshot struct {
	n     int
	stats [featureCount]featureStats
}

type baseline struct {
	mu    sync.Mutex
	n     int
	stats [featureCount]featureStats
}

func (b *baseline) snapshot() baselineSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return baselineSnapshot{n: b.n, stats: b.stats}
}

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

const zEpsilon = 1e-9

type scope struct {
	label string
	key   string
}
type Detector struct {
	cfg      Config
	profiles *profile.Store
	baseline *baseline
}

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

func (d *Detector) Observe(e event.Event) {
	d.profiles.Observe(e)
}

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

func (d *Detector) scoreFeatures(x [featureCount]float64, bl baselineSnapshot) (combined float64, zs [featureCount]float64) {
	var components [featureCount]float64
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
				z = 0
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
	return weightedSum / weightSum, zs
}

func (d *Detector) evaluateFeatures(x [featureCount]float64, bl baselineSnapshot, sc scope) finding.Finding {
	combined, zs := d.scoreFeatures(x, bl)

	if combined < d.cfg.TriggerThreshold {
		return finding.Finding{}
	}

	riskScore := d.cfg.ScoreFloor + (1-d.cfg.ScoreFloor)*combined

	weights := d.cfg.Weights.asArray()
	signals := make([]decision.ContributingSignal, featureCount)
	for i := range zs {
		signals[i] = decision.ContributingSignal{Name: featureNames[i], Value: zs[i], Weight: weights[i]}
	}

	return finding.Finding{
		Triggered:           true,
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

type DebugEvaluation struct {
	Scope         string
	CombinedScore float64
	Triggered     bool
	RiskScore     float64
	ZScores       map[string]float64
}

func (d *Detector) EvaluateDebug(e event.Event) []DebugEvaluation {
	bl := d.baseline.snapshot()
	warm := bl.n < d.cfg.MinSamples

	ipFeatures := extractFeatures(d.profiles.SnapshotIP(e.ClientIP))
	ipCombined, ipZs := d.scoreFeatures(ipFeatures, bl)
	ipTriggered := !warm && ipCombined >= d.cfg.TriggerThreshold
	var ipRisk float64
	if ipTriggered {
		ipRisk = d.cfg.ScoreFloor + (1-d.cfg.ScoreFloor)*ipCombined
	}
	evals := []DebugEvaluation{{
		Scope:         "ip:" + e.ClientIP.String(),
		CombinedScore: ipCombined,
		Triggered:     ipTriggered,
		RiskScore:     ipRisk,
		ZScores:       zScoreMap(ipZs),
	}}

	haveSession := e.SessionID != ""
	var sessionFeatures [featureCount]float64
	if haveSession {
		sessionFeatures = extractFeatures(d.profiles.SnapshotSession(e.SessionID))
		sessionCombined, sessionZs := d.scoreFeatures(sessionFeatures, bl)
		sessionTriggered := !warm && sessionCombined >= d.cfg.TriggerThreshold
		var sessionRisk float64
		if sessionTriggered {
			sessionRisk = d.cfg.ScoreFloor + (1-d.cfg.ScoreFloor)*sessionCombined
		}
		evals = append(evals, DebugEvaluation{
			Scope:         "session:" + e.SessionID,
			CombinedScore: sessionCombined,
			Triggered:     sessionTriggered,
			RiskScore:     sessionRisk,
			ZScores:       zScoreMap(sessionZs),
		})
	}

	if warm || !evals[0].Triggered {
		d.baseline.update(ipFeatures)
	}
	if haveSession && (warm || !evals[1].Triggered) {
		d.baseline.update(sessionFeatures)
	}

	return evals
}

func zScoreMap(zs [featureCount]float64) map[string]float64 {
	m := make(map[string]float64, featureCount)
	for i, name := range featureNames {
		m[name] = zs[i]
	}
	return m
}

func (d *Detector) Sweep(now time.Time, idleTTL time.Duration) int {
	return d.profiles.Sweep(now, idleTTL)
}
