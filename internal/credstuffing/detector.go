// Implementa la detección de credential stuffing correlacionando intentos por ASN.
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

type NetworkResolver interface {
	Resolve(ip netip.Addr) (group string, ok bool)
}

type UnavailableNetworkResolver struct{}

func (UnavailableNetworkResolver) Resolve(netip.Addr) (string, bool) {
	return "", false
}

type ScoreWeights struct {
	IPs      float64
	Accounts float64
	Attempts float64
	Ratio    float64
}
type Config struct {
	Window time.Duration

	MinDistinctIPs      int
	MinDistinctAccounts int
	MinAttempts         int
	MinFailedRatio      float64

	Weights ScoreWeights

	ScoreFloor float64

	AuthMatcher *event.AuthPathMatcher

	Resolver NetworkResolver
}

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

type observation struct {
	timestamp     time.Time
	ip            netip.Addr
	loginUserHash string
	statusCode    int
}
type groupState struct {
	watermark time.Time
	queue     []observation
}
type Detector struct {
	cfg     Config
	matcher *event.AuthPathMatcher

	mu     sync.Mutex
	groups map[string]groupState
}

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

type GateMetrics struct {
	Group string

	DistinctIPs      int
	DistinctAccounts int
	TotalAttempts    int
	FailedRatio      float64

	Triggered bool
}

func (d *Detector) EvaluateGateMetrics(e event.Event) (metrics GateMetrics, found bool) {
	if !d.matcher.IsAuthPath(e.Path) {
		return GateMetrics{}, false
	}
	group, ok := d.cfg.Resolver.Resolve(e.ClientIP)
	if !ok {
		return GateMetrics{}, false
	}

	d.mu.Lock()
	state := d.groups[group]
	obs := make([]observation, len(state.queue))
	copy(obs, state.queue)
	d.mu.Unlock()

	return d.gateMetricsFor(group, obs), true
}

func (d *Detector) gateMetricsFor(group string, obs []observation) GateMetrics {
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

	return GateMetrics{
		Group:            "network:" + group,
		DistinctIPs:      len(distinctIPs),
		DistinctAccounts: len(distinctAccounts),
		TotalAttempts:    total,
		FailedRatio:      failedRatio,
		Triggered:        triggered,
	}
}

func (d *Detector) evaluateGroup(group string, obs []observation) finding.Finding {
	gate := d.gateMetricsFor(group, obs)
	if !gate.Triggered {
		return finding.Finding{}
	}

	cIPs := excessComponent(float64(gate.DistinctIPs), float64(d.cfg.MinDistinctIPs))
	cAccounts := excessComponent(float64(gate.DistinctAccounts), float64(d.cfg.MinDistinctAccounts))
	cAttempts := excessComponent(float64(gate.TotalAttempts), float64(d.cfg.MinAttempts))
	cRatio := ratioComponent(gate.FailedRatio, d.cfg.MinFailedRatio)

	w := d.cfg.Weights
	weightSum := w.IPs + w.Accounts + w.Attempts + w.Ratio
	avg := (cIPs*w.IPs + cAccounts*w.Accounts + cAttempts*w.Attempts + cRatio*w.Ratio) / weightSum

	riskScore := d.cfg.ScoreFloor + (1-d.cfg.ScoreFloor)*avg

	return finding.Finding{
		Triggered:    true,
		AttackVector: decision.AttackVectorCredentialStuffing,
		RiskScore:    riskScore,
		ContributingSignals: []decision.ContributingSignal{
			{Name: "distinct_ips_in_window", Value: float64(gate.DistinctIPs), Weight: w.IPs},
			{Name: "distinct_accounts_in_window", Value: float64(gate.DistinctAccounts), Weight: w.Accounts},
			{Name: "auth_attempts_in_window", Value: float64(gate.TotalAttempts), Weight: w.Attempts},
			{Name: "failed_auth_ratio", Value: gate.FailedRatio, Weight: w.Ratio},
		},
		Explanation: fmt.Sprintf(
			"%d distinct IPs, %d distinct accounts, %d auth attempts, %.0f%% failed (401/403) within the window",
			gate.DistinctIPs, gate.DistinctAccounts, gate.TotalAttempts, gate.FailedRatio*100,
		),
		EntityID: "network:" + group,
	}
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
