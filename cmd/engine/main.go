// Command engine levanta el servicio HTTP de ingestión y decisión.
// POST /v1/events usa engine.BehavioralDecider, que combina
// internal/credstuffing, internal/slowscan e internal/anomaly detrás
// de una Policy configurable. El resolver de ASN de credential
// stuffing es configurable vía --asn-provider: "none" (default
// seguro, credstuffing.UnavailableNetworkResolver) o "ripestat"
// (internal/asn, un enriquecimiento real). El proceso puede exportar
// métricas por OpenTelemetry (OTLP/gRPC) hacia un Collector, vía
// --otel-endpoint -- "fail-open" por diseño: si el Collector no
// responde al arrancar, el motor cae a instrumentación no-op y sirve
// tráfico igual. La construcción del stack (detectores +
// BehavioralDecider + httpapi.Server) vive en internal/wiring, para
// que cmd/loadtest y los microbenchmarks de internal/engine la
// reutilicen sin duplicar configuración. Ver docs/decisiones.md.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/telemetry"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/wiring"
)

func main() {
	addr := flag.String("addr", ":8080", "dirección donde escuchar (host:puerto)")
	// wiring.FinalPolicy() (Challenge=0.50/Block=0.75) — la Policy
	// congelada tras el holdout, nunca engine.DefaultPolicy()
	// (0.50/0.80, sin calibrar): cmd/engine y cmd/loadtest tienen que
	// servir/medir exactamente la misma configuración. Los flags
	// siguen permitiendo overridear en runtime si hiciera falta.
	finalPolicy := wiring.FinalPolicy()
	challengeThreshold := flag.Float64("challenge-threshold", finalPolicy.ChallengeThreshold, "score mínimo (RiskScore) para CHALLENGE")
	blockThreshold := flag.Float64("block-threshold", finalPolicy.BlockThreshold, "score mínimo (RiskScore) para BLOCK")
	asnProvider := flag.String("asn-provider", wiring.ASNProviderNone, `proveedor de ASN para credential stuffing: "none" (default seguro, sin tráfico de salida) o "ripestat"`)
	asnTimeout := flag.Duration("asn-timeout", 2*time.Second, "timeout total de cada consulta de ASN (incluye espera de cupo de concurrencia)")
	asnCacheTTL := flag.Duration("asn-cache-ttl", time.Hour, "TTL del caché positivo de resoluciones de ASN")
	otelEndpoint := flag.String("otel-endpoint", "", `host:puerto de un OpenTelemetry Collector OTLP/gRPC (por ejemplo "localhost:4317") — vacío (default) deshabilita la telemetría, sin ningún tráfico de salida`)
	otelInsecure := flag.Bool("otel-insecure", true, "desactiva TLS en la conexión gRPC hacia --otel-endpoint — pensado solo para un Collector local de desarrollo; un endpoint remoto de producción debería usar TLS (--otel-insecure=false)")
	otelConnectTimeout := flag.Duration("otel-connect-timeout", 3*time.Second, "cuánto espera el motor, al arrancar, a que --otel-endpoint quede alcanzable antes de caer a métricas no-op (fail-open: nunca impide arrancar)")
	flag.Parse()

	// signal.NotifyContext (no un simple ListenAndServe bloqueante)
	// para que SIGINT/SIGTERM disparen un apagado ordenado: sin esto,
	// matar el proceso nunca le daría a telemetry.Init la oportunidad
	// de hacer un último flush/Shutdown del MeterProvider.
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

	server, err := wiring.BuildServer(*challengeThreshold, *blockThreshold, *asnProvider, *asnTimeout, *asnCacheTTL, recorders)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}

	// otelhttp envuelve el *http.ServeMux con la métrica HTTP estándar
	// de OpenTelemetry (http.server.request.duration) — recorders.Provider
	// se pasa explícito, en vez de depender del MeterProvider global.
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
		"engine: escuchando en %s (POST /v1/events, GET /healthz) — decider=BehavioralDecider (credential_stuffing+slow_scan+statistical_anomaly; asn-provider=%s; challenge=%.2f block=%.2f; otel-endpoint=%q)",
		*addr, *asnProvider, *challengeThreshold, *blockThreshold, *otelEndpoint,
	)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("engine: %v", err)
	}

	// Contexto nuevo y acotado para el Shutdown del MeterProvider —
	// nunca el ctx ya cancelado por la señal de apagado, que dejaría a
	// Shutdown sin ningún margen para el flush final.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdownTelemetry(shutdownCtx); err != nil {
		log.Printf("engine: telemetry shutdown: %v", err)
	}
}
