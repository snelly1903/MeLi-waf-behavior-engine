// Inicializa el MeterProvider de OpenTelemetry con exportación OTLP y fallback no-op.
package telemetry

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/asn"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/httpapi"
)

const serviceName = "waf-behavior-engine"

const exportInterval = 15 * time.Second

type Config struct {
	Endpoint string

	Insecure bool

	ConnectTimeout time.Duration
}

type Recorders struct {
	Provider metric.MeterProvider

	Engine engine.FindingsRecorder
	ASN    asn.MetricsRecorder
	HTTP   httpapi.DecisionRecorder
}

func Init(ctx context.Context, cfg Config) (recorders *Recorders, shutdown func(context.Context) error, usedNoop bool) {
	provider, shutdown, usedNoop := newMeterProvider(ctx, cfg)
	meter := provider.Meter(serviceName)
	return &Recorders{
		Provider: provider,
		Engine:   newEngineRecorder(meter),
		ASN:      newASNRecorder(meter),
		HTTP:     newHTTPRecorder(meter),
	}, shutdown, usedNoop
}

func newMeterProvider(ctx context.Context, cfg Config) (metric.MeterProvider, func(context.Context) error, bool) {
	noopShutdown := func(context.Context) error { return nil }

	if cfg.Endpoint == "" {
		return noop.NewMeterProvider(), noopShutdown, false
	}

	conn, err := dial(ctx, cfg)
	if err != nil {
		return noop.NewMeterProvider(), noopShutdown, true
	}

	exporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
	if err != nil {
		_ = conn.Close()
		return noop.NewMeterProvider(), noopShutdown, true
	}

	res, err := resource.New(ctx, resource.WithAttributes(attribute.String("service.name", serviceName)))
	if err != nil {
		res = resource.Default()
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(exportInterval))),
	)

	shutdown := func(shutdownCtx context.Context) error {
		err := provider.Shutdown(shutdownCtx)
		if closeErr := conn.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		return err
	}
	return provider, shutdown, false
}

func dial(ctx context.Context, cfg Config) (*grpc.ClientConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()

	var creds credentials.TransportCredentials
	if cfg.Insecure {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(&tls.Config{})
	}

	conn, err := grpc.NewClient(cfg.Endpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("telemetry: creating grpc client for %q: %w", cfg.Endpoint, err)
	}

	conn.Connect()
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return conn, nil
		}
		if !conn.WaitForStateChange(dialCtx, state) {
			_ = conn.Close()
			return nil, fmt.Errorf("telemetry: collector at %q not ready within %s (last state: %s)", cfg.Endpoint, cfg.ConnectTimeout, state)
		}
	}
}
