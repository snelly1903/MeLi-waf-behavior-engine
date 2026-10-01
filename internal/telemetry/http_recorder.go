// Registra métricas OpenTelemetry de las decisiones servidas por la API HTTP.
package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

type httpRecorder struct {
	decisions metric.Int64Counter
}

func newHTTPRecorder(meter metric.Meter) httpRecorder {
	decisions, err := meter.Int64Counter(
		"waf.decisions",
		metric.WithDescription("Decisiones tomadas por el motor, por action y attack_vector."),
		metric.WithUnit("1"),
	)
	if err != nil {
		decisions = noop.Int64Counter{}
	}
	return httpRecorder{decisions: decisions}
}

func (r httpRecorder) RecordDecision(action, attackVector string) {
	r.decisions.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("action", action),
		attribute.String("attack_vector", attackVector),
	))
}
