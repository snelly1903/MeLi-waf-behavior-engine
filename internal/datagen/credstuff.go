// Genera campañas sintéticas de credential stuffing distribuidas entre muchas IPs.
package datagen

import (
	"net/netip"
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type CredentialStuffingCampaign struct {
	Pool IPPool

	IPCount int

	IPs []netip.Addr

	MinAttemptsPerIP, MaxAttemptsPerIP int

	Window time.Duration

	LoginPath string

	SuccessProbability float64

	AccountReuseProbability float64

	UserAgents []string
}

var DefaultCredentialStuffingCampaign = CredentialStuffingCampaign{
	Pool:                    PoolHostingSim,
	IPCount:                 150,
	MinAttemptsPerIP:        1,
	MaxAttemptsPerIP:        3,
	Window:                  3 * time.Hour,
	LoginPath:               DefaultLoginPath,
	SuccessProbability:      0.01,
	AccountReuseProbability: 0.05,
	UserAgents: []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15",
		"python-requests/2.31.0",
		"curl/8.4.0",
	},
}

func GenerateCredentialStuffingCampaign(rng *RNG, cfg CredentialStuffingCampaign, start time.Time) []groundtruth.LabeledEvent {
	ips := cfg.IPs
	if ips == nil {
		ips = cfg.Pool.DistinctAddrs(rng, cfg.IPCount)
	}

	var usedAccounts []string
	var events []groundtruth.LabeledEvent

	for _, ip := range ips {
		attempts := rng.IntRange(cfg.MinAttemptsPerIP, cfg.MaxAttemptsPerIP)

		offsets := make([]time.Duration, attempts)
		for i := range offsets {
			offsets[i] = rng.DurationRange(0, cfg.Window)
		}
		sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })

		for _, offset := range offsets {
			var accountHash string
			if len(usedAccounts) > 0 && rng.Bool(cfg.AccountReuseProbability) {
				accountHash = Pick(rng, usedAccounts)
			} else {
				accountHash = rng.HexHash(64)
				usedAccounts = append(usedAccounts, accountHash)
			}
			status := 401
			if rng.Bool(cfg.SuccessProbability) {
				status = 200
			} else if rng.Bool(0.3) {
				status = 403
			}

			e := event.Event{
				RequestID:     rng.ID("r-"),
				Timestamp:     start.Add(offset),
				ClientIP:      ip,
				Method:        "POST",
				Path:          cfg.LoginPath,
				StatusCode:    status,
				UserAgent:     Pick(rng, cfg.UserAgents),
				LoginUserHash: accountHash,
			}
			events = append(events, groundtruth.LabeledEvent{Label: groundtruth.LabelCredentialStuffing, Event: e})
		}
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Event.Timestamp.Before(events[j].Event.Timestamp)
	})
	return events
}
