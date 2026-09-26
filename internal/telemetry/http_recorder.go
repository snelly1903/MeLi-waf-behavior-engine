package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// httpRecorder implementa httpapi.DecisionRecorder registrando la
// métrica waf.decisions: un Counter con dos atributos de baja
// cardinalidad, "action" (3 valores) y "attack_vector" (3 valores) --
// 9 combinaciones como máximo. Nunca lleva EntityID ni RequestID.
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

// RecordDecision implementa httpapi.DecisionRecorder.
func (r httpRecorder) RecordDecision(action, attackVector string) {
	r.decisions.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("action", action),
		attribute.String("attack_vector", attackVector),
	))
}
