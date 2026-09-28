// Package engine (defaults.go): los valores de configuración por
// defecto de los tres detectores y de la Policy — los mismos que usa
// cmd/engine en producción. Viven acá, no repetidos como literales en
// cmd/engine/main.go y en internal/tuning (tarea 1.9) por separado:
// un único lugar de verdad evita que la evaluación de "baseline"
// pueda desincronizarse silenciosamente de lo que el motor real
// sirve — ver TestBaselineCandidate_MatchesEngineDefaults en
// internal/tuning.
//
// NINGÚN valor acá está calibrado todavía contra un dataset real (esa
// calibración es, precisamente, el objeto de la tarea 1.9). Son
// puntos de partida razonables para que el servicio corra de punta a
// punta — mismo criterio ya aplicado a internal/baseline en la tarea
// 0.9.
package engine

import (
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

// DefaultCredentialStuffingConfig devuelve la configuración por
// defecto de internal/credstuffing — sin Resolver: quien la use
// (cmd/engine, internal/tuning) le asigna el suyo después, porque el
// resolver es la única pieza que cambia entre producción (RIPEstat,
// tarea 1.7) y evaluación offline (un resolver determinista, tarea
// 1.9).
func DefaultCredentialStuffingConfig() credstuffing.Config {
	return credstuffing.Config{
		Window:              30 * time.Minute,
		MinDistinctIPs:      20,
		MinDistinctAccounts: 15,
		MinAttempts:         25,
		MinFailedRatio:      0.6,
		Weights:             credstuffing.ScoreWeights{IPs: 0.25, Accounts: 0.25, Attempts: 0.25, Ratio: 0.25},
		ScoreFloor:          0.2,
	}
}

// DefaultSlowScanConfig devuelve la configuración por defecto de
// internal/slowscan.
func DefaultSlowScanConfig() slowscan.Config {
	return slowscan.Config{
		Window:                  time.Hour,
		MinRequests:             15,
		MinDistinctPaths:        10,
		MinNotFoundRatio:        0.5,
		MinRouteEntropy:         0.6,
		MinNovelPathRatio:       0.5,
		MaxVisitorsForNovelPath: 2,
		Weights:                 slowscan.ScoreWeights{Requests: 1, Paths: 1, NotFound: 1, Entropy: 1, Novelty: 1, Referer: 1},
		ScoreFloor:              0.2,
	}
}

// DefaultAnomalyConfig devuelve la configuración por defecto de
// internal/anomaly. TriggerThreshold queda deliberadamente bajo
// (0.15) porque, con las cinco features pesadas por igual, una
// desviación clara en una sola de ellas nunca puede empujar el score
// combinado mucho más allá de ~0.2 (el resto de las features, cerca
// de su media, aportan ~0 al promedio) — ver docs/decisiones.md,
// tarea 1.6.
func DefaultAnomalyConfig() anomaly.Config {
	return anomaly.Config{
		Window:           time.Hour,
		MinSamples:       50,
		ZSaturation:      2.0,
		TriggerThreshold: 0.15,
		Weights:          anomaly.FeatureWeights{NotFound: 1, FailedAuth: 1, PathDiversity: 1, Referer: 1, AccountDiversity: 1},
		ScoreFloor:       0.2,
	}
}

// DefaultPolicy devuelve la Policy por defecto — los umbrales que usa
// cmd/engine si no se pasan --challenge-threshold/--block-threshold
// explícitos.
func DefaultPolicy() Policy {
	return Policy{ChallengeThreshold: 0.5, BlockThreshold: 0.8}
}
