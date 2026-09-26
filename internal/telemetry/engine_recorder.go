package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// engineRecorder implementa engine.FindingsRecorder registrando la
// métrica waf.detector.findings: un Counter con un único atributo de
// baja cardinalidad, "detector" (3 valores posibles). Nunca lleva
// EntityID, RequestID ni ninguna otra señal de alto cardinal -- ver
// docs/decisiones.md, tarea 1.8.
type engineRecorder struct {
	findings metric.Int64Counter
}

func newEngineRecorder(meter metric.Meter) engineRecorder {
	findings, err := meter.Int64Counter(
		"waf.detector.findings",
		metric.WithDescription("Findings disparados por cada detector conductual, incluso cuando no terminan siendo la evidencia principal de la Decision."),
		metric.WithUnit("1"),
	)
	if err != nil {
		// Solo puede fallar por un nombre/unidad de instrumento
		// inválido -- un error de programación nuestro, nunca algo
		// que dependa del entorno. Degradar a no-op es más seguro que
		// entrar en pánico por esto.
		findings = noop.Int64Counter{}
	}
	return engineRecorder{findings: findings}
}

// RecordFinding implementa engine.FindingsRecorder.
func (r engineRecorder) RecordFinding(detector string) {
	r.findings.Add(context.Background(), 1, metric.WithAttributes(attribute.String("detector", detector)))
}
