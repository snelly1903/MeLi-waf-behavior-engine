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
// malicioso). Todos los valores son configurables y ninguno es un
// umbral de detección — son parámetros de generación de datos de
// prueba, documentados en docs/decisiones.md (tarea 0.6).
type ScenarioConfig struct {
	Seed   uint64
	Start  time.Time
	Window time.Duration // duración total simulada del escenario

	// Composición del tráfico legítimo base.
	NavegSessions             int
	APIClientSessions         int
	HostedTenantSessions      int
	OfficeClusters            int
	OfficeEmployeesPerCluster int
	OfficeStartJitter         time.Duration

	// TargetMaliciousRatio es la fracción de eventos maliciosos deseada
	// (0, 0.10, 0.30...). No se fuerza de forma exacta: se calcula un
	// volumen de ataque que debería acercarse a este objetivo, se
	// genera, y el resultado REAL queda en ScenarioStats — ver
	// docs/decisiones.md para por qué no se fuerza el número exacto.
	TargetMaliciousRatio float64

	// StuffingShareOfMalicious es el tope de qué fracción del volumen
	// malicioso objetivo puede aportar como máximo el credential
	// stuffing — el resto lo cubre el escaneo lento. Refleja que el
	// stuffing es, por diseño, de bajo volumen (tarea 0.5): no se infla
	// artificialmente para "completar" el porcentaje pedido.
	StuffingShareOfMalicious float64

	// StuffingIPCap / ScanIPCap topan la cantidad de IPs atacantes de
	// cada ataque, además del límite físico del pool (254 direcciones
	// para un /24). Los valores por defecto están elegidos para que,
	// junto con HostedTenantSessions, nunca se pueda superar esa
	// capacidad física (ver DefaultScenarioConfig).
	StuffingIPCap int
	ScanIPCap     int

	StuffingBase    CredentialStuffingCampaign
	StuffingWindow  time.Duration
	ScanBase        SlowScanProfile
	ScanStartJitter time.Duration
}

// DefaultScenarioConfig son los valores acordados para el dataset
// funcional de prueba del challenge (ver docs/decisiones.md, tarea
// 0.6): una población pensada para generarse y evaluarse rápido, no
// para las pruebas de carga — esas van a reutilizar estos mismos
// generadores desde una herramienta distinta (k6), más adelante.
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

// ScenarioStats resume cómo salió la generación: parámetros, semilla y
// conteos reales. Se escribe tal cual en manifest.json (ver
// WriteScenario, en write.go) — no lleva ninguna marca de tiempo real
// de generación, así el propio manifiesto también es reproducible byte
// a byte con la misma semilla.
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

// Scenario es el resultado de BuildScenario: los eventos ya mezclados y
// ordenados por Timestamp, junto con las estadísticas de la generación.
type Scenario struct {
	Events []groundtruth.LabeledEvent
	Stats  ScenarioStats
}

// BuildScenario genera un escenario completo: tráfico legítimo
// (incluido tráfico legítimo que comparte ASN simulado con los
// atacantes, vía ProfileHostedTenant) y, si
// cfg.TargetMaliciousRatio > 0, las dos campañas de ataque, con un
// volumen calculado para acercarse al porcentaje objetivo. El
// resultado queda ordenado por Timestamp.
//
// Las direcciones de ProfileHostedTenant y las de los dos ataques se
// sortean de forma coordinada (DistinctAddrsExcluding, en ipspace.go)
// para que sean SIEMPRE disjuntas dentro de un mismo escenario — así
// ninguna dirección simulada tiene, en este dataset controlado, más de
// una identidad a la vez. Es una simplificación deliberada para tener
// un primer escenario limpio de evaluar; queda anotado en
// docs/decisiones.md que una extensión natural, más adelante, es
// generar a propósito IPs compartidas entre tráfico legítimo y
// malicioso — la evaluación siempre se hace por request_id, nunca
// asumiendo que una IP tiene una única etiqueta.
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

	// Tenants legítimos sobre el mismo ASN simulado que los atacantes.
	// Se sortean ahora, antes que las IPs atacantes, para poder
	// excluirlas de ese sorteo más abajo.
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

		// Los dos volúmenes se estiman en paralelo a partir de
		// promedios esperados (intentos por IP, requests por escáner),
		// no midiendo el resultado real del stuffing antes de calcular
		// el escaneo — es más simple, y la diferencia práctica es
		// chica porque ambos promedios son razonablemente estables con
		// las cantidades de esta tarea (ver docs/decisiones.md).
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
