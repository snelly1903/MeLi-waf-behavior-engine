package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// asnRecorder implementa asn.MetricsRecorder registrando tres
// métricas, todas con atributos de baja cardinalidad (nunca un
// número de ASN individual -- ver docs/decisiones.md, tarea 1.8):
//
//   - waf.asn.cache: Counter, atributo "result" (hit/miss).
//   - waf.asn.resolve: Counter, atributo "result"
//     (success/failure/capacity_timeout).
//   - waf.asn.provider.duration: Histogram en segundos, atributo
//     "result" (success/failure) -- mide específicamente la llamada
//     HTTP real al proveedor (ver asn.Resolver.Resolve), nunca la
//     espera de capacidad ni el tiempo de caché.
type asnRecorder struct {
	cache            metric.Int64Counter
	resolve          metric.Int64Counter
	providerDuration metric.Float64Histogram
}

func newASNRecorder(meter metric.Meter) asnRecorder {
	cache, err := meter.Int64Counter(
		"waf.asn.cache",
		metric.WithDescription("Resultados del caché de resoluciones de ASN (hit o miss, incluye TTL vencido)."),
		metric.WithUnit("1"),
	)
	if err != nil {
		cache = noop.Int64Counter{}
	}

	resolve, err := meter.Int64Counter(
		"waf.asn.resolve",
		metric.WithDescription("Resultado de cada resolución de ASN que no vino de caché: success, failure o capacity_timeout."),
		metric.WithUnit("1"),
	)
	if err != nil {
		resolve = noop.Int64Counter{}
	}

	providerDuration, err := meter.Float64Histogram(
		"waf.asn.provider.duration",
		metric.WithDescription("Duración de la llamada HTTP real al proveedor de ASN (RIPEstat) -- no incluye espera de capacidad ni caché."),
		metric.WithUnit("s"),
	)
	if err != nil {
		providerDuration = noop.Float64Histogram{}
	}

	return asnRecorder{cache: cache, resolve: resolve, providerDuration: providerDuration}
}

// RecordCacheResult implementa asn.MetricsRecorder.
func (r asnRecorder) RecordCacheResult(hit bool) {
	result := "miss"
	if hit {
		result = "hit"
	}
	r.cache.Add(context.Background(), 1, metric.WithAttributes(attribute.String("result", result)))
}

// RecordResolveResult implementa asn.MetricsRecorder.
func (r asnRecorder) RecordResolveResult(result string) {
	r.resolve.Add(context.Background(), 1, metric.WithAttributes(attribute.String("result", result)))
}

// RecordProviderDuration implementa asn.MetricsRecorder.
func (r asnRecorder) RecordProviderDuration(result string, d time.Duration) {
	r.providerDuration.Record(context.Background(), d.Seconds(), metric.WithAttributes(attribute.String("result", result)))
}
