// Package telemetry conecta el motor con OpenTelemetry: arma un
// *sdkmetric.MeterProvider real, exportando por OTLP/gRPC
// hacia un Collector, o -- si no hay Collector configurado, o no se
// lo puede alcanzar al arrancar -- un MeterProvider no-op. Ninguno de
// los dos casos impide que el motor sirva tráfico ("fail-open"): un
// Collector caído nunca es un motivo para no arrancar ni para dejar
// de responder requests, solo para quedarse sin métricas.
//
// Es el único paquete del proyecto que importa el SDK de
// OpenTelemetry para las métricas de dominio propias de este
// challenge. internal/engine, internal/asn e internal/httpapi solo
// conocen interfaces mínimas definidas en sí mismos
// (engine.FindingsRecorder, asn.MetricsRecorder,
// httpapi.DecisionRecorder); este paquete las implementa desde
// afuera, por tipado estructural de Go -- mismo criterio que
// internal/asn.Resolver satisface credstuffing.NetworkResolver.
// Ninguno de esos tres paquetes importa OpenTelemetry.
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

// serviceName identifica a este proceso en los atributos de recurso
// de toda métrica exportada (service.name).
const serviceName = "waf-behavior-engine"

// exportInterval es cada cuánto se exportan las métricas acumuladas
// al Collector -- el default del SDK (60s) es razonable para
// producción, pero deja una demo local viendo un dashboard "en vivo"
// esperando hasta un minuto para el primer punto; verificado
// directamente en la demo manual. 15s es un balance simple: sigue
// siendo una fracción chica de la sobrecarga total del proceso, y
// hace que Grafana se vea responder casi de inmediato.
const exportInterval = 15 * time.Second

// Config configura Init.
type Config struct {
	// Endpoint es el host:puerto del Collector OTLP/gRPC (por
	// ejemplo "localhost:4317") -- nunca con esquema (ni "http://" ni
	// "https://"), el mismo formato "host:puerto" que espera
	// grpc.NewClient. Vacío = telemetría deshabilitada: Init devuelve
	// directamente instrumentación no-op, sin intentar conectar con
	// nadie.
	Endpoint string

	// Insecure, si es true, desactiva TLS en la conexión gRPC hacia
	// Endpoint. Pensado ÚNICAMENTE para un Collector local en la
	// misma máquina o red de confianza -- como el de
	// docker-compose.yml --, nunca para un endpoint remoto de
	// producción, que debería usar TLS de verdad (ver
	// docs/decisiones.md).
	Insecure bool

	// ConnectTimeout acota cuánto espera Init a que la conexión gRPC
	// hacia Endpoint quede lista antes de darse por vencido y caer a
	// instrumentación no-op. Debe ser mayor que 0 si Endpoint no está
	// vacío; si Endpoint está vacío, no se usa.
	ConnectTimeout time.Duration
}

// Recorders agrupa el MeterProvider real (o no-op) junto con las
// implementaciones concretas de las interfaces mínimas que
// internal/engine, internal/asn e internal/httpapi definen para sus
// propias métricas de dominio.
type Recorders struct {
	// Provider es el metric.MeterProvider construido por Init --
	// cmd/engine lo pasa explícitamente a
	// otelhttp.WithMeterProvider(...) para la métrica HTTP estándar,
	// en vez de depender del proveedor global (ver
	// docs/decisiones.md).
	Provider metric.MeterProvider

	Engine engine.FindingsRecorder
	ASN    asn.MetricsRecorder
	HTTP   httpapi.DecisionRecorder
}

// Init arma la telemetría del proceso. Nunca devuelve un estado que
// le impida a cmd/engine arrancar y servir tráfico -- ver el
// comentario del paquete sobre "fail-open":
//
//   - cfg.Endpoint == ""            -> instrumentación no-op, sin
//     ningún intento de red. usedNoop=false: no es un fallback, es
//     la configuración por defecto explícita.
//   - cfg.Endpoint != "" pero el Collector no responde dentro de
//     cfg.ConnectTimeout -> instrumentación no-op. usedNoop=true --
//     quien llama (cmd/engine) decide cómo loguear esta advertencia;
//     este paquete nunca escribe logs por su cuenta, para quedar
//     testeable sin tener que capturar stdout.
//   - cfg.Endpoint alcanzable      -> MeterProvider real, exportando
//     de verdad por OTLP/gRPC.
//
// shutdown nunca es nil y siempre es seguro de llamar, incluso en el
// caso no-op (ahí no hace nada).
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

	// WithGRPCConn documenta explícitamente que Exporter.Shutdown NO
	// cierra conn -- es responsabilidad de quien la creó. Por eso
	// cerramos conn nosotros, después de que MeterProvider.Shutdown
	// (que hace flush del exportador) termine.
	shutdown := func(shutdownCtx context.Context) error {
		err := provider.Shutdown(shutdownCtx)
		if closeErr := conn.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		return err
	}
	return provider, shutdown, false
}

// dial arma una conexión gRPC hacia cfg.Endpoint y espera, acotado
// por cfg.ConnectTimeout, a que quede lista (connectivity.Ready)
// antes de devolverla -- este chequeo síncrono es justamente lo que
// permite el comportamiento "fail-open" de Init: si el Collector no
// responde a tiempo, Init lo sabe ACÁ, antes de construir ningún
// MeterProvider real, y cae a no-op.
//
// grpc.NewClient (la forma moderna de crear un *grpc.ClientConn, que
// remplazó a grpc.Dial) nunca conecta por sí solo -- por eso se llama
// conn.Connect() explícitamente y se espera el cambio de estado con
// WaitForStateChange, en vez de usar la antigua grpc.WithBlock()
// (documentada como no soportada por NewClient).
func dial(ctx context.Context, cfg Config) (*grpc.ClientConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()

	var creds credentials.TransportCredentials
	if cfg.Insecure {
		creds = insecure.NewCredentials()
	} else {
		// TLS con la configuración por defecto de la librería estándar
		// (verificación normal de certificado contra las CA del
		// sistema) -- suficiente para un endpoint remoto que ya tenga
		// un certificado válido. Un despliegue con CA propia
		// necesitaría extender esto; no es el caso de este challenge.
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
