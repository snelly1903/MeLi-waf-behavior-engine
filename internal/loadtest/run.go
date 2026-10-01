// Ejecuta una corrida de carga HTTP concurrente con warmup y registro de latencias.
package loadtest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

const PerfSeed uint64 = 901

const DefaultMaxIdleConnsPerHost = 256

func NewClient(concurrency int) *http.Client {
	maxConns := DefaultMaxIdleConnsPerHost
	if concurrency > maxConns {
		maxConns = concurrency * 2
	}
	transport := &http.Transport{
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: maxConns,
		IdleConnTimeout:     90 * time.Second,
	}
	return &http.Client{Transport: transport}
}

type sample struct {
	latency time.Duration
	ok      bool
}

type RunConfig struct {
	BaseURL string

	Events []event.Event

	Concurrency int
	Warmup      time.Duration
	Measurement time.Duration

	Client *http.Client
}

type RunResult struct {
	Requests  int
	Errors    int
	Latencies []time.Duration

	ActualDuration time.Duration
}

func (r RunResult) Throughput() float64 {
	if r.ActualDuration <= 0 {
		return 0
	}
	return float64(r.Requests) / r.ActualDuration.Seconds()
}

func (r RunResult) ErrorRate() float64 {
	if r.Requests == 0 {
		return 0
	}
	return float64(r.Errors) / float64(r.Requests)
}

func (r RunResult) P50() time.Duration { return percentile(r.Latencies, 50) }
func (r RunResult) P95() time.Duration { return percentile(r.Latencies, 95) }
func (r RunResult) P99() time.Duration { return percentile(r.Latencies, 99) }

func Run(ctx context.Context, cfg RunConfig) RunResult {
	var cursor int64

	fireWorkers(ctx, cfg, &cursor, time.Now().Add(cfg.Warmup), false)

	measureStart := time.Now()
	results := fireWorkers(ctx, cfg, &cursor, measureStart.Add(cfg.Measurement), true)
	actualEnd := time.Now()

	var res RunResult
	for _, ls := range results {
		for _, s := range ls {
			res.Requests++
			if !s.ok {
				res.Errors++
			}
			res.Latencies = append(res.Latencies, s.latency)
		}
	}
	res.ActualDuration = actualEnd.Sub(measureStart)
	if res.ActualDuration < 0 {
		res.ActualDuration = 0
	}
	return res
}

func fireWorkers(ctx context.Context, cfg RunConfig, cursor *int64, deadline time.Time, record bool) [][]sample {
	results := make([][]sample, cfg.Concurrency)

	var wg sync.WaitGroup
	wg.Add(cfg.Concurrency)
	for w := 0; w < cfg.Concurrency; w++ {
		go func(w int) {
			defer wg.Done()
			var local []sample
			for {
				select {
				case <-ctx.Done():
					results[w] = local
					return
				default:
				}
				if !time.Now().Before(deadline) {
					break
				}

				n := atomic.AddInt64(cursor, 1) - 1
				e := cfg.Events[int(n)%len(cfg.Events)]
				e.Timestamp = time.Now()
				body, _ := json.Marshal(e)

				reqStart := time.Now()
				resp, err := cfg.Client.Post(cfg.BaseURL+"/v1/events", "application/json", bytes.NewReader(body))
				lat := time.Since(reqStart)

				ok := err == nil
				if resp != nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						ok = false
					}
				}

				if record {
					local = append(local, sample{latency: lat, ok: ok})
				}
			}
			results[w] = local
		}(w)
	}
	wg.Wait()
	return results
}
