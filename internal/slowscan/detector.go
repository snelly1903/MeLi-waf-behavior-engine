// Detecta escaneos lentos usando diversidad, entropía, errores 404 y novedad de rutas.
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

type ScoreWeights struct {
	Requests float64
	Paths    float64
	NotFound float64
	Entropy  float64
	Novelty  float64
	Referer  float64
}

type Config struct {
	Window time.Duration

	MinRequests       int
	MinDistinctPaths  int
	MinNotFoundRatio  float64
	MinRouteEntropy   float64
	MinNovelPathRatio float64

	MaxVisitorsForNovelPath int

	Weights ScoreWeights

	ScoreFloor float64
}

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

type pathVisit struct {
	timestamp time.Time
	ip        netip.Addr
}

type pathState struct {
	watermark time.Time
	visits    []pathVisit
}

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

type Detector struct {
	cfg      Config
	profiles *profile.Store
	paths    *pathPopularity
}

func NewDetector(cfg Config) (*Detector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	profiles, err := profile.NewStore(cfg.Window)
	if err != nil {
		return nil, err
	}
	return &Detector{
		cfg:      cfg,
		profiles: profiles,
		paths:    newPathPopularity(cfg.Window),
	}, nil
}

func (d *Detector) Observe(e event.Event) {
	d.profiles.Observe(e)
	d.paths.observe(e.Path, e.ClientIP, e.Timestamp)
}

type scope struct {
	label string
	key   string
}

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
		return sessionFinding
	case haveSession && sessionFinding.Triggered:
		return sessionFinding
	case ipFinding.Triggered:
		return ipFinding
	default:
		return finding.Finding{}
	}
}

func (d *Detector) evaluateMetrics(m profile.Metrics, sc scope) finding.Finding {
	gate := d.gateMetricsFor(m, sc.label+":"+sc.key)
	if !gate.Triggered {
		return finding.Finding{}
	}

	total := m.Total
	var withoutRefererRatio float64
	if total > 0 {
		withoutRefererRatio = float64(m.WithoutReferer) / float64(total)
	}

	cRequests := excessComponent(float64(gate.TotalRequests), float64(d.cfg.MinRequests))
	cPaths := excessComponent(float64(gate.DistinctPaths), float64(d.cfg.MinDistinctPaths))
	cNotFound := ratioComponent(gate.NotFoundRatio, d.cfg.MinNotFoundRatio)
	cEntropy := ratioComponent(gate.RouteEntropy, d.cfg.MinRouteEntropy)
	cNovelty := ratioComponent(gate.NovelPathRatio, d.cfg.MinNovelPathRatio)
	cReferer := withoutRefererRatio

	w := d.cfg.Weights
	weightSum := w.Requests + w.Paths + w.NotFound + w.Entropy + w.Novelty + w.Referer
	avg := (cRequests*w.Requests + cPaths*w.Paths + cNotFound*w.NotFound +
		cEntropy*w.Entropy + cNovelty*w.Novelty + cReferer*w.Referer) / weightSum

	riskScore := d.cfg.ScoreFloor + (1-d.cfg.ScoreFloor)*avg

	return finding.Finding{
		Triggered:    true,
		AttackVector: decision.AttackVectorSlowScan,
		RiskScore:    riskScore,
		ContributingSignals: []decision.ContributingSignal{
			{Name: "total_requests", Value: float64(total), Weight: w.Requests},
			{Name: "distinct_paths", Value: float64(gate.DistinctPaths), Weight: w.Paths},
			{Name: "not_found_ratio", Value: gate.NotFoundRatio, Weight: w.NotFound},
			{Name: "route_entropy_normalized", Value: gate.RouteEntropy, Weight: w.Entropy},
			{Name: "novel_path_ratio", Value: gate.NovelPathRatio, Weight: w.Novelty},
			{Name: "without_referer_ratio", Value: withoutRefererRatio, Weight: w.Referer},
		},
		Explanation: fmt.Sprintf(
			"%d requests across %d distinct paths, %.0f%% not-found, entropy=%.2f, %.0f%% novel paths within the window",
			total, gate.DistinctPaths, gate.NotFoundRatio*100, gate.RouteEntropy, gate.NovelPathRatio*100,
		),
		EntityID: sc.label + ":" + sc.key,
	}
}

type GateMetrics struct {
	Scope string

	TotalRequests  int
	DistinctPaths  int
	NotFoundRatio  float64
	RouteEntropy   float64
	NovelPathRatio float64

	Triggered bool
}

func (d *Detector) EvaluateGateMetrics(e event.Event) []GateMetrics {
	result := []GateMetrics{d.gateMetricsFor(d.profiles.SnapshotIP(e.ClientIP), "ip:"+e.ClientIP.String())}
	if e.SessionID != "" {
		result = append(result, d.gateMetricsFor(d.profiles.SnapshotSession(e.SessionID), "session:"+e.SessionID))
	}
	return result
}

func (d *Detector) gateMetricsFor(m profile.Metrics, scopeLabel string) GateMetrics {
	total := m.Total
	distinctPaths := len(m.PathCounts)

	var notFoundRatio float64
	if total > 0 {
		notFoundRatio = float64(m.Status404) / float64(total)
	}
	routeEntropy := normalizedEntropy(m.PathCounts, total, distinctPaths)
	novelPathRatio := d.novelPathRatio(m.PathCounts, distinctPaths)

	triggered := total >= d.cfg.MinRequests &&
		distinctPaths >= d.cfg.MinDistinctPaths &&
		notFoundRatio >= d.cfg.MinNotFoundRatio &&
		routeEntropy >= d.cfg.MinRouteEntropy &&
		novelPathRatio >= d.cfg.MinNovelPathRatio

	return GateMetrics{
		Scope:          scopeLabel,
		TotalRequests:  total,
		DistinctPaths:  distinctPaths,
		NotFoundRatio:  notFoundRatio,
		RouteEntropy:   routeEntropy,
		NovelPathRatio: novelPathRatio,
		Triggered:      triggered,
	}
}

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

func (d *Detector) Sweep(now time.Time, idleTTL time.Duration) int {
	return d.profiles.Sweep(now, idleTTL) + d.paths.sweep(now, idleTTL)
}
