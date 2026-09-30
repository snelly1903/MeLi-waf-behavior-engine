package datagen

import (
	"math"
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// ScenarioConfig configura un escenario de prueba completo: una
// combinación de tráfico legítimo y, opcionalmente, los dos ataques, en
// las proporciones exigidas por el challenge (0%, 10%, 30% de tráfico
// malicioso)
type ScenarioConfig struct {
	Seed   uint64
	Start  time.Time
	Window time.Duration

	NavegSessions             int
	APIClientSessions         int
	HostedTenantSessions      int
	OfficeClusters            int
	OfficeEmployeesPerCluster int
	OfficeStartJitter         time.Duration

	TargetMaliciousRatio float64

	StuffingShareOfMalicious float64

	StuffingIPCap int //capacidad de ip, max 254
	ScanIPCap     int

	StuffingBase    CredentialStuffingCampaign
	StuffingWindow  time.Duration
	ScanBase        SlowScanProfile
	ScanStartJitter time.Duration
}

func DefaultScenarioConfig(seed uint64, targetMaliciousRatio float64) ScenarioConfig {
	return ScenarioConfig{
		Seed:   seed,
		Start:  time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC),
		Window: 6 * time.Hour,

		NavegSessions:             35,
		APIClientSessions:         20,
		HostedTenantSessions:      8,
		OfficeClusters:            3,
		OfficeEmployeesPerCluster: 6,
		OfficeStartJitter:         20 * time.Minute,

		TargetMaliciousRatio:     targetMaliciousRatio,
		StuffingShareOfMalicious: 0.3,
		StuffingIPCap:            150,
		ScanIPCap:                90,

		StuffingBase:    DefaultCredentialStuffingCampaign,
		StuffingWindow:  3 * time.Hour,
		ScanBase:        DefaultSlowScanProfile,
		ScanStartJitter: 3 * time.Hour,
	}
}

type ScenarioStats struct {
	Seed                     uint64  `json:"seed"`
	TargetMaliciousRatio     float64 `json:"target_malicious_ratio"`
	AchievedMaliciousRatio   float64 `json:"achieved_malicious_ratio"`
	TotalEvents              int     `json:"total_events"`
	LegitEvents              int     `json:"legit_events"`
	CredentialStuffingEvents int     `json:"credential_stuffing_events"`
	SlowScanEvents           int     `json:"slow_scan_events"`
	CredentialStuffingIPs    int     `json:"credential_stuffing_ips"`
	SlowScanScanners         int     `json:"slow_scan_scanners"`
}

type Scenario struct {
	Events []groundtruth.LabeledEvent
	Stats  ScenarioStats
}

func BuildScenario(cfg ScenarioConfig) Scenario {
	rng := NewRNG(cfg.Seed)

	var legit []groundtruth.LabeledEvent

	for i := 0; i < cfg.NavegSessions; i++ {
		start := cfg.Start.Add(rng.DurationRange(0, cfg.Window))
		ip := ProfileNavegante.Pool.RandomAddr(rng)
		legit = append(legit, GenerateLegitSession(rng, ProfileNavegante, start, ip)...)
	}
	for i := 0; i < cfg.APIClientSessions; i++ {
		start := cfg.Start.Add(rng.DurationRange(0, cfg.Window))
		ip := ProfileAPIClient.Pool.RandomAddr(rng)
		legit = append(legit, GenerateLegitSession(rng, ProfileAPIClient, start, ip)...)
	}
	for i := 0; i < cfg.OfficeClusters; i++ {
		clusterStart := cfg.Start.Add(rng.DurationRange(0, cfg.Window))
		legit = append(legit, GenerateOfficeCluster(rng, cfg.OfficeEmployeesPerCluster, clusterStart, cfg.OfficeStartJitter)...)
	}

	tenantIPs := PoolHostingSim.DistinctAddrs(rng, cfg.HostedTenantSessions)
	for _, ip := range tenantIPs {
		start := cfg.Start.Add(rng.DurationRange(0, cfg.Window))
		legit = append(legit, GenerateLegitSession(rng, ProfileHostedTenant, start, ip)...)
	}

	sort.SliceStable(legit, func(i, j int) bool {
		return legit[i].Event.Timestamp.Before(legit[j].Event.Timestamp)
	})

	stats := ScenarioStats{
		Seed:                 cfg.Seed,
		TargetMaliciousRatio: cfg.TargetMaliciousRatio,
		LegitEvents:          len(legit),
	}

	var malicious []groundtruth.LabeledEvent

	if cfg.TargetMaliciousRatio > 0 {
		L := len(legit)
		mTarget := int(math.Round(float64(L) * cfg.TargetMaliciousRatio / (1 - cfg.TargetMaliciousRatio)))

		avgAttempts := float64(cfg.StuffingBase.MinAttemptsPerIP+cfg.StuffingBase.MaxAttemptsPerIP) / 2
		stuffBudget := int(math.Round(float64(mTarget) * cfg.StuffingShareOfMalicious))
		ipCount := clampInt(int(math.Round(float64(stuffBudget)/avgAttempts)), 1, cfg.StuffingIPCap)

		avgReq := float64(cfg.ScanBase.MinRequests+cfg.ScanBase.MaxRequests) / 2
		scanBudget := mTarget - stuffBudget
		scanners := clampInt(int(math.Round(float64(scanBudget)/avgReq)), 1, cfg.ScanIPCap)

		attackerIPs := PoolHostingSim.DistinctAddrsExcluding(rng, ipCount+scanners, tenantIPs)
		stuffIPs := attackerIPs[:ipCount]
		scanIPs := attackerIPs[ipCount:]

		stuffCfg := cfg.StuffingBase
		stuffCfg.IPCount = ipCount
		stuffCfg.Window = cfg.StuffingWindow
		stuffCfg.IPs = stuffIPs
		stuffing := GenerateCredentialStuffingCampaign(rng, stuffCfg, cfg.Start)

		scanCfg := cfg.ScanBase
		scanCfg.IPs = scanIPs
		scanning := GenerateSlowScanCampaign(rng, scanCfg, scanners, cfg.Start, cfg.ScanStartJitter)

		malicious = append(malicious, stuffing...)
		malicious = append(malicious, scanning...)
		sort.SliceStable(malicious, func(i, j int) bool {
			return malicious[i].Event.Timestamp.Before(malicious[j].Event.Timestamp)
		})

		stats.CredentialStuffingEvents = len(stuffing)
		stats.SlowScanEvents = len(scanning)
		stats.CredentialStuffingIPs = ipCount
		stats.SlowScanScanners = scanners
	}

	all := make([]groundtruth.LabeledEvent, 0, len(legit)+len(malicious))
	all = append(all, legit...)
	all = append(all, malicious...)
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].Event.Timestamp.Before(all[j].Event.Timestamp)
	})

	stats.TotalEvents = len(all)
	if stats.TotalEvents > 0 {
		stats.AchievedMaliciousRatio = float64(len(malicious)) / float64(stats.TotalEvents)
	}

	return Scenario{Events: all, Stats: stats}
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
