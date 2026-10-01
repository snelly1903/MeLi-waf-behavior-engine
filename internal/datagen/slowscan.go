// Genera sesiones y campañas sintéticas de escaneo lento de rutas.
package datagen

import (
	"net/netip"
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type SlowScanProfile struct {
	Pool IPPool

	MinRequests, MaxRequests int

	MinGap, MaxGap time.Duration

	SensitivePaths []string

	ValidPaths []string

	ValidPathProbability float64

	FuzzParams []string

	FuzzParamProbability float64

	UserAgents []string

	Methods                    []string
	MethodDiversityProbability float64

	IPs []netip.Addr
}

var DefaultValidScanPaths = append([]string{DefaultLoginPath}, ProfileNavegante.Paths...)

var DefaultSlowScanProfile = SlowScanProfile{
	Pool:                 PoolHostingSim,
	MinRequests:          20,
	MaxRequests:          60,
	MinGap:               20 * time.Second,
	MaxGap:               3 * time.Minute,
	SensitivePaths:       SensitivePaths,
	ValidPaths:           DefaultValidScanPaths,
	ValidPathProbability: 0.15,
	FuzzParams:           FuzzParams,
	FuzzParamProbability: 0.20,
	UserAgents: []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"python-requests/2.31.0",
		"Go-http-client/1.1",
		"Mozilla/5.0 (compatible; scanner/1.0)",
	},
	Methods:                    []string{"GET", "GET", "GET", "GET", "HEAD", "OPTIONS"},
	MethodDiversityProbability: 0.08,
}

func GenerateSlowScanSession(rng *RNG, profile SlowScanProfile, start time.Time, clientIP netip.Addr) []groundtruth.LabeledEvent {
	clock := event.NewManualClock(start)
	requestCount := rng.IntRange(profile.MinRequests, profile.MaxRequests)

	var events []groundtruth.LabeledEvent
	for i := 0; i < requestCount; i++ {
		var path string
		var status int
		var params []string

		if rng.Bool(profile.ValidPathProbability) {
			path = Pick(rng, profile.ValidPaths)
			status = 200
			if rng.Bool(profile.FuzzParamProbability) {
				n := rng.IntRange(1, 3)
				params = make([]string, 0, n)
				for j := 0; j < n; j++ {
					params = append(params, Pick(rng, profile.FuzzParams))
				}
			}
		} else {
			path = Pick(rng, profile.SensitivePaths)
			status = 404
		}

		method := "GET"
		if rng.Bool(profile.MethodDiversityProbability) {
			method = Pick(rng, profile.Methods)
		}

		e := event.Event{
			RequestID:   rng.ID("r-"),
			Timestamp:   clock.Now(),
			ClientIP:    clientIP,
			Method:      method,
			Path:        path,
			QueryParams: params,
			StatusCode:  status,
			UserAgent:   Pick(rng, profile.UserAgents),
		}
		events = append(events, groundtruth.LabeledEvent{Label: groundtruth.LabelSlowScan, Event: e})
		clock.Advance(rng.DurationRange(profile.MinGap, profile.MaxGap))
	}

	return events
}

func GenerateSlowScanCampaign(rng *RNG, profile SlowScanProfile, scanners int, campaignStart time.Time, startJitter time.Duration) []groundtruth.LabeledEvent {
	ips := profile.IPs
	if ips == nil {
		ips = profile.Pool.DistinctAddrs(rng, scanners)
	}

	var all []groundtruth.LabeledEvent
	for _, ip := range ips {
		scannerStart := campaignStart.Add(rng.DurationRange(0, startJitter))
		all = append(all, GenerateSlowScanSession(rng, profile, scannerStart, ip)...)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Event.Timestamp.Before(all[j].Event.Timestamp)
	})
	return all
}
