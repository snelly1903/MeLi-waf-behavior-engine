// Registra métricas OpenTelemetry de findings y anomaly score del motor.
package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

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

func (r engineRecorder) RecordFinding(detector string) {
	r.findings.Add(context.Background(), 1, metric.WithAttributes(attribute.String("detector", detector)))
}

func (r engineRecorder) RecordAnomalyScore(score float64) {
	r.anomalyScore.Record(context.Background(), score)
}
