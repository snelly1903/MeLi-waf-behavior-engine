// Levanta la API HTTP del motor conductual y coordina su apagado ordenado.
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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdownTelemetry(shutdownCtx); err != nil {
		log.Printf("engine: telemetry shutdown: %v", err)
	}
}
