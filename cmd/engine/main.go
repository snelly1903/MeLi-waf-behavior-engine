// Command engine levanta el servicio HTTP de ingestión y decisión.
// Desde la tarea 1.5, POST /v1/events ya no depende de
// engine.AllowAllDecider: usa engine.BehavioralDecider, que combina
// internal/credstuffing, internal/slowscan y (desde la tarea 1.6)
// internal/anomaly detrás de una Policy configurable. Desde la tarea
// 1.7, el resolver de ASN de credential stuffing es configurable vía
// --asn-provider: "none" (default seguro, credstuffing.UnavailableNetworkResolver)
// o "ripestat" (internal/asn, un enriquecimiento real). Ver
// buildCredentialStuffingResolver y docs/decisiones.md, tareas 1.5 y
// 1.7, para el porqué de cada uno.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/asn"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/httpapi"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

// Nombres válidos de --asn-provider.
const (
	asnProviderNone     = "none"
	asnProviderRIPEStat = "ripestat"
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

// buildCredentialStuffingResolver arma el credstuffing.NetworkResolver
// según --asn-provider. Se evaluaron tres alternativas para el caso
// "todavía no hay proveedor" (ver docs/decisiones.md, tarea 1.5): (1)
// un resolver placeholder explícito de producción,
// credstuffing.UnavailableNetworkResolver — la elegida por defecto:
// el detector corre de verdad (Observe/Evaluate se llaman en cada
// evento) pero queda estructuralmente inerte, porque ninguna IP se
// puede resolver a un grupo; (2) un *credstuffing.Detector nulable en
// BehavioralDecider — descartada, obliga a chequeos de nil; (3)
// reutilizar el fake de los tests — descartada explícitamente.
//
// "ripestat" (tarea 1.7) conecta internal/asn, que consulta RIPEstat
// de verdad (https://stat.ripe.net) — una fuente pública y gratuita
// apropiada para este challenge/prototipo, pero cuyos términos de uso
// actuales restringen ciertos usos comerciales sin permiso explícito;
// no se presenta como el proveedor definitivo de un despliegue de
// producción. El default sigue siendo "none": el servicio nunca hace
// tráfico de salida a Internet a menos que se lo pida explícitamente.
func buildCredentialStuffingResolver(provider string, timeout time.Duration, successTTL time.Duration) (credstuffing.NetworkResolver, error) {
	switch provider {
	case "", asnProviderNone:
		return credstuffing.UnavailableNetworkResolver{}, nil
	case asnProviderRIPEStat:
		return asn.NewResolver(asn.Config{
			BaseURL:               asn.DefaultBaseURL,
			SourceApp:             "meli-waf-behavior-engine-challenge",
			Timeout:               timeout,
			MaxConcurrentRequests: 5,
			SuccessTTL:            successTTL,
			FailureTTL:            5 * time.Minute,
		})
	default:
		return nil, fmt.Errorf("engine: unknown --asn-provider %q (want %q or %q)", provider, asnProviderNone, asnProviderRIPEStat)
	}
}

// buildServer arma el *httpapi.Server real, con los tres detectores y
// la Policy configurada — separado de main() para poder probarlo con
// httptest sin levantar un servidor real (mismo patrón que
// cmd/eval/main.go, tarea 0.8, con su función run()).
func buildServer(challengeThreshold, blockThreshold float64, asnProvider string, asnTimeout, asnCacheTTL time.Duration) (*httpapi.Server, error) {
	resolver, err := buildCredentialStuffingResolver(asnProvider, asnTimeout, asnCacheTTL)
	if err != nil {
		return nil, err
	}

	csCfg := credentialStuffingConfig
	csCfg.Resolver = resolver
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
	asnProvider := flag.String("asn-provider", asnProviderNone, `proveedor de ASN para credential stuffing: "none" (default seguro, sin tráfico de salida) o "ripestat"`)
	asnTimeout := flag.Duration("asn-timeout", 2*time.Second, "timeout total de cada consulta de ASN (incluye espera de cupo de concurrencia)")
	asnCacheTTL := flag.Duration("asn-cache-ttl", time.Hour, "TTL del caché positivo de resoluciones de ASN")
	flag.Parse()

	server, err := buildServer(*challengeThreshold, *blockThreshold, *asnProvider, *asnTimeout, *asnCacheTTL)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}

	log.Printf(
		"engine: escuchando en %s (POST /v1/events, GET /healthz) — decider=BehavioralDecider (credential_stuffing+slow_scan+statistical_anomaly; asn-provider=%s; challenge=%.2f block=%.2f, sin calibrar)",
		*addr, *asnProvider, *challengeThreshold, *blockThreshold,
	)
	if err := http.ListenAndServe(*addr, server.Routes()); err != nil {
		log.Fatalf("engine: %v", err)
	}
}
