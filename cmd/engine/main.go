// Command engine levanta el servicio HTTP de ingestión y decisión.
// Desde la tarea 1.5, POST /v1/events ya no depende de
// engine.AllowAllDecider: usa engine.BehavioralDecider, que combina
// internal/credstuffing, internal/slowscan y (desde la tarea 1.6)
// internal/anomaly detrás de una Policy configurable. El detector de
// credential stuffing corre con credstuffing.UnavailableNetworkResolver
// mientras no exista un proveedor real de ASN/grupo de red — ver
// buildServer y docs/decisiones.md, tarea 1.5, para el porqué.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/httpapi"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

// Configuración de los tres detectores — NINGÚN valor acá está
// calibrado todavía contra un dataset real (esa calibración es una
// tarea posterior, mismo criterio que ya se aplicó a
// internal/baseline en la tarea 0.9). Son puntos de partida
// razonables para que el servicio corra de punta a punta.
var (
	credentialStuffingConfig = credstuffing.Config{
		Window:              30 * time.Minute,
		MinDistinctIPs:      20,
		MinDistinctAccounts: 15,
		MinAttempts:         25,
		MinFailedRatio:      0.6,
		Weights:             credstuffing.ScoreWeights{IPs: 0.25, Accounts: 0.25, Attempts: 0.25, Ratio: 0.25},
		ScoreFloor:          0.2,
		// Resolver se completa en buildServer con
		// credstuffing.UnavailableNetworkResolver — ver ahí el porqué.
	}

	slowScanConfig = slowscan.Config{
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

	// anomalyConfig: TriggerThreshold queda deliberadamente bajo
	// (0.15) porque, con las cinco features pesadas por igual, una
	// desviación clara en una sola de ellas nunca puede empujar el
	// score combinado mucho más allá de ~0.2 (el resto de las
	// features, cerca de su media, aportan ~0 al promedio) — ver
	// docs/decisiones.md, tarea 1.6.
	anomalyConfig = anomaly.Config{
		Window:           time.Hour,
		MinSamples:       50,
		ZSaturation:      2.0,
		TriggerThreshold: 0.15,
		Weights:          anomaly.FeatureWeights{NotFound: 1, FailedAuth: 1, PathDiversity: 1, Referer: 1, AccountDiversity: 1},
		ScoreFloor:       0.2,
	}
)

// buildServer arma el *httpapi.Server real, con los dos detectores y
// la Policy configurada — separado de main() para poder probarlo con
// httptest sin levantar un servidor real (mismo patrón que
// cmd/eval/main.go, tarea 0.8, con su función run()).
//
// credential stuffing corre con credstuffing.UnavailableNetworkResolver:
// todavía no existe ningún proveedor real de ASN/grupo de red. Se
// evaluaron tres alternativas (ver docs/decisiones.md, tarea 1.5): (1)
// este resolver placeholder explícito, de producción — la elegida:
// el detector corre de verdad (Observe/Evaluate se llaman en cada
// evento) pero queda estructuralmente inerte, porque ninguna IP se
// puede resolver a un grupo; (2) un *credstuffing.Detector nulable en
// BehavioralDecider, tratado como "desactivado" — descartada, obliga
// a chequeos de nil en cada punto de uso; (3) reutilizar el fake de
// los tests — descartada explícitamente, sería un fake de test
// terminando en producción. Reemplazar por un NetworkResolver real,
// cuando exista un proveedor, es cambiar esta única línea.
func buildServer(challengeThreshold, blockThreshold float64) (*httpapi.Server, error) {
	csCfg := credentialStuffingConfig
	csCfg.Resolver = credstuffing.UnavailableNetworkResolver{}
	csDetector, err := credstuffing.NewDetector(csCfg)
	if err != nil {
		return nil, fmt.Errorf("engine: credential stuffing detector: %w", err)
	}

	ssDetector, err := slowscan.NewDetector(slowScanConfig)
	if err != nil {
		return nil, fmt.Errorf("engine: slow scan detector: %w", err)
	}

	anomalyDetector, err := anomaly.NewDetector(anomalyConfig)
	if err != nil {
		return nil, fmt.Errorf("engine: anomaly detector: %w", err)
	}

	policy := engine.Policy{ChallengeThreshold: challengeThreshold, BlockThreshold: blockThreshold}
	decider, err := engine.NewBehavioralDecider(csDetector, ssDetector, anomalyDetector, policy)
	if err != nil {
		return nil, fmt.Errorf("engine: behavioral decider: %w", err)
	}

	validator := event.NewValidator(event.SystemClock{})
	return httpapi.NewServer(validator, decider), nil
}

func main() {
	addr := flag.String("addr", ":8080", "dirección donde escuchar (host:puerto)")
	challengeThreshold := flag.Float64("challenge-threshold", 0.5, "score mínimo (RiskScore) para CHALLENGE — sin calibrar todavía")
	blockThreshold := flag.Float64("block-threshold", 0.8, "score mínimo (RiskScore) para BLOCK — sin calibrar todavía")
	flag.Parse()

	server, err := buildServer(*challengeThreshold, *blockThreshold)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}

	log.Printf(
		"engine: escuchando en %s (POST /v1/events, GET /healthz) — decider=BehavioralDecider (credential_stuffing+slow_scan+statistical_anomaly; credential_stuffing sin ASN real: UnavailableNetworkResolver; challenge=%.2f block=%.2f, sin calibrar)",
		*addr, *challengeThreshold, *blockThreshold,
	)
	if err := http.ListenAndServe(*addr, server.Routes()); err != nil {
		log.Fatalf("engine: %v", err)
	}
}
