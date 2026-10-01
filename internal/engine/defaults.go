// Define las configuraciones por defecto de los detectores y de la política de acciones.
package engine

import (
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

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

func DefaultPolicy() Policy {
	return Policy{ChallengeThreshold: 0.5, BlockThreshold: 0.8}
}
