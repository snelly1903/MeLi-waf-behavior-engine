package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// engineRecorder implementa engine.FindingsRecorder registrando dos
// métricas, ambas de baja cardinalidad:
//
//   - waf.detector.findings: Counter, atributo "detector" (3 valores
//     posibles). Nunca lleva EntityID, RequestID ni ninguna otra señal
//     de alto cardinal -- ver docs/decisiones.md.
//   - waf.anomaly.score: Histogram del RiskScore de
//     statistical_anomaly en CADA evaluación (dispare o no). Sin
//     atributos -- ya es específico de un único detector, agregar
//     "detector" acá sería redundante.
type engineRecorder struct {
	findings     metric.Int64Counter
	anomalyScore metric.Float64Histogram
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

	anomalyScore, err := meter.Float64Histogram(
		"waf.anomaly.score",
		metric.WithDescription("RiskScore de statistical_anomaly en cada evaluación (0 si no disparó, incluido igual -- nunca excluido, mismo criterio que el reporte offline de tuning/holdout)."),
		metric.WithUnit("1"),
	)
	if err != nil {
		anomalyScore = noop.Float64Histogram{}
	}

	return engineRecorder{findings: findings, anomalyScore: anomalyScore}
}

// RecordFinding implementa engine.FindingsRecorder.
func (r engineRecorder) RecordFinding(detector string) {
	r.findings.Add(context.Background(), 1, metric.WithAttributes(attribute.String("detector", detector)))
}

// RecordAnomalyScore implementa engine.FindingsRecorder.
func (r engineRecorder) RecordAnomalyScore(score float64) {
	r.anomalyScore.Record(context.Background(), score)
}
