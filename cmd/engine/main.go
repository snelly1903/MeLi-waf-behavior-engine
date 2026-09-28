// Command engine levanta el servicio HTTP de ingestión y decisión.
// Desde la tarea 1.5, POST /v1/events ya no depende de
// engine.AllowAllDecider: usa engine.BehavioralDecider, que combina
// internal/credstuffing, internal/slowscan y (desde la tarea 1.6)
// internal/anomaly detrás de una Policy configurable. Desde la tarea
// 1.7, el resolver de ASN de credential stuffing es configurable vía
// --asn-provider: "none" (default seguro, credstuffing.UnavailableNetworkResolver)
// o "ripestat" (internal/asn, un enriquecimiento real). Desde la
// tarea 1.8, el proceso puede exportar métricas por OpenTelemetry
// (OTLP/gRPC) hacia un Collector, vía --otel-endpoint -- "fail-open"
// por diseño: si el Collector no responde al arrancar, el motor cae
// a instrumentación no-op y sirve tráfico igual. Ver
// docs/decisiones.md, tareas 1.5, 1.7 y 1.8, para el porqué de cada
// una.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/asn"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/httpapi"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/telemetry"
)

// Nombres válidos de --asn-provider.
const (
	asnProviderNone     = "none"
	asnProviderRIPEStat = "ripestat"
)

// Configuración de los tres detectores — los valores concretos viven
// en internal/engine.Default*Config (tarea 1.9): un único lugar de
// verdad, para que la evaluación offline de internal/tuning nunca
// pueda desincronizarse de lo que este binario sirve de verdad. Acá
// solo falta completar credentialStuffingConfig.Resolver, que se hace
// en buildServer con credstuffing.UnavailableNetworkResolver o
// internal/asn.Resolver según --asn-provider — es la única pieza que
// cambia entre producción y evaluación offline.
var (
	credentialStuffingConfig = engine.DefaultCredentialStuffingConfig()
	slowScanConfig           = engine.DefaultSlowScanConfig()
	anomalyConfig            = engine.DefaultAnomalyConfig()
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
//
// metrics (tarea 1.8) es opcional (nil = sin instrumentación) — se
// cablea directo dentro del asn.Resolver cuando el proveedor es
// "ripestat"; el placeholder "none" no genera ninguna métrica porque
// nunca hace ningún trabajo que medir.
func buildCredentialStuffingResolver(provider string, timeout time.Duration, successTTL time.Duration, metrics asn.MetricsRecorder) (credstuffing.NetworkResolver, error) {
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
			Metrics:               metrics,
		})
	default:
		return nil, fmt.Errorf("engine: unknown --asn-provider %q (want %q or %q)", provider, asnProviderNone, asnProviderRIPEStat)
	}
}

// buildServer arma el *httpapi.Server real, con los tres detectores y
// la Policy configurada — separado de main() para poder probarlo con
// httptest sin levantar un servidor real (mismo patrón que
// cmd/eval/main.go, tarea 0.8, con su función run()).
//
// recorders (tarea 1.8) es opcional: nil es válido y significa "sin
// telemetría" — cada componente (BehavioralDecider, asn.Resolver,
// httpapi.Server) ya sabe degradar a un recorder no-op por su cuenta
// cuando recibe nil, así que buildServer nunca necesita construir uno
// él mismo.
func buildServer(challengeThreshold, blockThreshold float64, asnProvider string, asnTimeout, asnCacheTTL time.Duration, recorders *telemetry.Recorders) (*httpapi.Server, error) {
	var engineRecorder engine.FindingsRecorder
	var asnRecorder asn.MetricsRecorder
	var httpRecorder httpapi.DecisionRecorder
	if recorders != nil {
		engineRecorder = recorders.Engine
		asnRecorder = recorders.ASN
		httpRecorder = recorders.HTTP
	}

	resolver, err := buildCredentialStuffingResolver(asnProvider, asnTimeout, asnCacheTTL, asnRecorder)
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
	decider, err := engine.NewBehavioralDecider(csDetector, ssDetector, anomalyDetector, policy, engineRecorder)
	if err != nil {
		return nil, fmt.Errorf("engine: behavioral decider: %w", err)
	}

	validator := event.NewValidator(event.SystemClock{})
	return httpapi.NewServer(validator, decider, httpRecorder), nil
}

func main() {
	addr := flag.String("addr", ":8080", "dirección donde escuchar (host:puerto)")
	defaultPolicy := engine.DefaultPolicy()
	challengeThreshold := flag.Float64("challenge-threshold", defaultPolicy.ChallengeThreshold, "score mínimo (RiskScore) para CHALLENGE — sin calibrar todavía")
	blockThreshold := flag.Float64("block-threshold", defaultPolicy.BlockThreshold, "score mínimo (RiskScore) para BLOCK — sin calibrar todavía")
	asnProvider := flag.String("asn-provider", asnProviderNone, `proveedor de ASN para credential stuffing: "none" (default seguro, sin tráfico de salida) o "ripestat"`)
	asnTimeout := flag.Duration("asn-timeout", 2*time.Second, "timeout total de cada consulta de ASN (incluye espera de cupo de concurrencia)")
	asnCacheTTL := flag.Duration("asn-cache-ttl", time.Hour, "TTL del caché positivo de resoluciones de ASN")
	otelEndpoint := flag.String("otel-endpoint", "", `host:puerto de un OpenTelemetry Collector OTLP/gRPC (por ejemplo "localhost:4317") — vacío (default) deshabilita la telemetría, sin ningún tráfico de salida`)
	otelInsecure := flag.Bool("otel-insecure", true, "desactiva TLS en la conexión gRPC hacia --otel-endpoint — pensado solo para un Collector local de desarrollo; un endpoint remoto de producción debería usar TLS (--otel-insecure=false)")
	otelConnectTimeout := flag.Duration("otel-connect-timeout", 3*time.Second, "cuánto espera el motor, al arrancar, a que --otel-endpoint quede alcanzable antes de caer a métricas no-op (fail-open: nunca impide arrancar)")
	flag.Parse()

	// signal.NotifyContext (no un simple ListenAndServe bloqueante)
	// para que SIGINT/SIGTERM disparen un apagado ordenado: sin esto,
	// matar el proceso nunca le daría a telemetry.Init la oportunidad
	// de hacer un último flush/Shutdown del MeterProvider (tarea 1.8,
	// ajuste 8).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	recorders, shutdownTelemetry, usedNoop := telemetry.Init(ctx, telemetry.Config{
		Endpoint:       *otelEndpoint,
		Insecure:       *otelInsecure,
		ConnectTimeout: *otelConnectTimeout,
	})
	if *otelEndpoint != "" && usedNoop {
		log.Printf("engine: WARNING telemetry collector at %q unreachable within %s at startup — falling back to no-op metrics, serving traffic normally", *otelEndpoint, *otelConnectTimeout)
	}

	server, err := buildServer(*challengeThreshold, *blockThreshold, *asnProvider, *asnTimeout, *asnCacheTTL, recorders)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}

	// otelhttp envuelve el *http.ServeMux con la métrica HTTP estándar
	// de OpenTelemetry (http.server.request.duration) — recorders.Provider
	// se pasa explícito, en vez de depender del MeterProvider global
	// (tarea 1.8, ajuste 5).
	handler := otelhttp.NewHandler(server.Routes(), "waf-engine", otelhttp.WithMeterProvider(recorders.Provider))
	httpServer := &http.Server{Addr: *addr, Handler: handler}

	go func() {
		<-ctx.Done()
		log.Print("engine: señal de apagado recibida, cerrando ordenadamente")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("engine: http server shutdown: %v", err)
		}
	}()

	log.Printf(
		"engine: escuchando en %s (POST /v1/events, GET /healthz) — decider=BehavioralDecider (credential_stuffing+slow_scan+statistical_anomaly; asn-provider=%s; challenge=%.2f block=%.2f, sin calibrar; otel-endpoint=%q)",
		*addr, *asnProvider, *challengeThreshold, *blockThreshold, *otelEndpoint,
	)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("engine: %v", err)
	}

	// Contexto nuevo y acotado para el Shutdown del MeterProvider
	// (tarea 1.8, ajuste 8) — nunca el ctx ya cancelado por la señal
	// de apagado, que dejaría a Shutdown sin ningún margen para el
	// flush final.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdownTelemetry(shutdownCtx); err != nil {
		log.Printf("engine: telemetry shutdown: %v", err)
	}
}
