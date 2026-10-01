// Package asn implementa un credstuffing.NetworkResolver real,
// consultando RIPEstat (RIPE NCC) para mapear una IP a su ASN
package asn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)


const DefaultBaseURL = "https://stat.ripe.net/data/network-info/data.json"

type Config struct {
	BaseURL string

	SourceApp string

	Timeout time.Duration

	MaxConcurrentRequests int

	SuccessTTL time.Duration

	FailureTTL time.Duration

	Clock event.Clock

	HTTPClient *http.Client

	Metrics MetricsRecorder
}

type MetricsRecorder interface {
	RecordCacheResult(hit bool)

	RecordResolveResult(result string)

	RecordProviderDuration(result string, d time.Duration)
}

type noopMetricsRecorder struct{}

func (noopMetricsRecorder) RecordCacheResult(bool)                       {}
func (noopMetricsRecorder) RecordResolveResult(string)                   {}
func (noopMetricsRecorder) RecordProviderDuration(string, time.Duration) {}


var (
	ErrInvalidBaseURL               = errors.New("asn: base_url is required")
	ErrInvalidSourceApp             = errors.New("asn: source_app is required")
	ErrInvalidTimeout               = errors.New("asn: timeout must be greater than 0")
	ErrInvalidMaxConcurrentRequests = errors.New("asn: max_concurrent_requests must be greater than 0")
	ErrInvalidSuccessTTL            = errors.New("asn: success_ttl must be greater than 0")
	ErrInvalidFailureTTL            = errors.New("asn: failure_ttl must be greater than 0")
)


func (cfg Config) Validate() error {
	var errs []error
	if strings.TrimSpace(cfg.BaseURL) == "" {
		errs = append(errs, ErrInvalidBaseURL)
	}
	if strings.TrimSpace(cfg.SourceApp) == "" {
		errs = append(errs, ErrInvalidSourceApp)
	}
	if cfg.Timeout <= 0 {
		errs = append(errs, ErrInvalidTimeout)
	}
	if cfg.MaxConcurrentRequests <= 0 {
		errs = append(errs, ErrInvalidMaxConcurrentRequests)
	}
	if cfg.SuccessTTL <= 0 {
		errs = append(errs, ErrInvalidSuccessTTL)
	}
	if cfg.FailureTTL <= 0 {
		errs = append(errs, ErrInvalidFailureTTL)
	}
	return errors.Join(errs...)
}

// cacheEntry es lo que se retiene por IP: el resultado (positivo o
// negativo) y cuándo vence.
type cacheEntry struct {
	group     string
	ok        bool
	expiresAt time.Time
}

type Resolver struct {
	cfg        Config
	httpClient *http.Client
	clock      event.Clock
	metrics    MetricsRecorder

	sem chan struct{}

	mu    sync.Mutex
	cache map[netip.Addr]cacheEntry
}

func NewResolver(cfg Config) (*Resolver, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	clock := cfg.Clock
	if clock == nil {
		clock = event.SystemClock{}
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = noopMetricsRecorder{}
	}
	return &Resolver{
		cfg:        cfg,
		httpClient: httpClient,
		clock:      clock,
		metrics:    metrics,
		sem:        make(chan struct{}, cfg.MaxConcurrentRequests),
		cache:      make(map[netip.Addr]cacheEntry),
	}, nil
}

type networkInfoResponse struct {
	Status string `json:"status"`
	Data   struct {
		ASNs []string `json:"asns"`
	} `json:"data"`
}

func (r *Resolver) Resolve(ip netip.Addr) (string, bool) {
	if group, ok, found := r.cacheGet(ip); found {
		r.metrics.RecordCacheResult(true)
		return group, ok
	}
	r.metrics.RecordCacheResult(false)

	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
	defer cancel()

	if !r.acquire(ctx) {
		r.metrics.RecordResolveResult("capacity_timeout")
		return "", false
	}
	defer r.release()

	start := time.Now()
	group, ok := r.fetch(ctx, ip)
	r.metrics.RecordProviderDuration(resultLabel(ok), time.Since(start))
	r.metrics.RecordResolveResult(resultLabel(ok))

	r.cacheSet(ip, group, ok)
	return group, ok
}

func resultLabel(ok bool) string {
	if ok {
		return "success"
	}
	return "failure"
}

func (r *Resolver) acquire(ctx context.Context) bool {
	select {
	case r.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (r *Resolver) release() {
	<-r.sem
}

func (r *Resolver) fetch(ctx context.Context, ip netip.Addr) (string, bool) {
	url := fmt.Sprintf("%s?resource=%s&sourceapp=%s", r.cfg.BaseURL, ip.String(), r.cfg.SourceApp)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}

	var parsed networkInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", false
	}
	if parsed.Status != "ok" {
		return "", false
	}

	return parseASNs(parsed.Data.ASNs)
}

func parseASNs(asns []string) (string, bool) {
	if len(asns) != 1 {
		return "", false
	}
	number := strings.TrimPrefix(strings.TrimPrefix(asns[0], "AS"), "as")
	number = strings.TrimSpace(number)
	if number == "" {
		return "", false
	}
	return "asn:" + number, true
}

func (r *Resolver) cacheGet(ip netip.Addr) (group string, ok, found bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.cache[ip]
	if !exists {
		return "", false, false
	}
	if r.clock.Now().After(entry.expiresAt) {
		delete(r.cache, ip)
		return "", false, false
	}
	return entry.group, entry.ok, true
}

func (r *Resolver) cacheSet(ip netip.Addr, group string, ok bool) {
	ttl := r.cfg.FailureTTL
	if ok {
		ttl = r.cfg.SuccessTTL
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[ip] = cacheEntry{group: group, ok: ok, expiresAt: r.clock.Now().Add(ttl)}
}

func (r *Resolver) Sweep(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	removed := 0
	for ip, entry := range r.cache {
		if now.After(entry.expiresAt) {
			delete(r.cache, ip)
			removed++
		}
	}
	return removed
}
