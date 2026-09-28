package tuning

import (
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// OptionalFloat es un número que puede no tener sentido calcular —
// por ejemplo, el promedio de requests-hasta-detección cuando ninguna
// campaña fue detectada nunca. Mismo criterio que eval.Ratio: N/A
// nunca se disimula con un 0.
type OptionalFloat struct {
	Value   float64
	Defined bool
}

// OptionalDuration es el equivalente de OptionalFloat para
// time.Duration.
type OptionalDuration struct {
	Value   time.Duration
	Defined bool
}

// DelaySummary resume, para UN vector de ataque, todas sus campañas
// dentro de una corrida: cuántas hubo, cuántas se detectaron alguna
// vez ("eventual campaign detection"), y el promedio de
// requests/tiempo hasta la primera detección — calculado solo sobre
// las campañas SÍ detectadas (promediar sobre "nunca" no tiene
// sentido numérico). EventualDetectionRate es la fracción de
// campañas detectadas sobre el total — esa sí incluye las no
// detectadas en su denominador, es la métrica que no debe ocultar
// falsos negativos iniciales.
type DelaySummary struct {
	Vector                  groundtruth.Label
	Campaigns               int
	DetectedCampaigns       int
	EventualDetectionRate   eval.Ratio
	MeanRequestsToDetection OptionalFloat
	MeanTimeToDetection     OptionalDuration
}

// SummarizeDelay agrupa delays (de UNA corrida, ver
// ComputeDetectionDelay) por Vector y calcula un DelaySummary por
// cada uno presente.
func SummarizeDelay(delays []CampaignDelay) []DelaySummary {
	type acc struct {
		campaigns          int
		detected           int
		sumRequests        int
		sumTime            time.Duration
		detectedWithValues int
	}
	byVector := make(map[groundtruth.Label]*acc)
	var order []groundtruth.Label

	for _, d := range delays {
		a, exists := byVector[d.Vector]
		if !exists {
			a = &acc{}
			byVector[d.Vector] = a
			order = append(order, d.Vector)
		}
		a.campaigns++
		if d.Detected {
			a.detected++
			a.sumRequests += d.RequestsToDetection
			a.sumTime += d.TimeToDetection
			a.detectedWithValues++
		}
	}

	summaries := make([]DelaySummary, 0, len(order))
	for _, v := range order {
		a := byVector[v]
		s := DelaySummary{
			Vector:                v,
			Campaigns:             a.campaigns,
			DetectedCampaigns:     a.detected,
			EventualDetectionRate: ratioOf(a.detected, a.campaigns),
		}
		if a.detectedWithValues > 0 {
			s.MeanRequestsToDetection = OptionalFloat{Value: float64(a.sumRequests) / float64(a.detectedWithValues), Defined: true}
			s.MeanTimeToDetection = OptionalDuration{Value: a.sumTime / time.Duration(a.detectedWithValues), Defined: true}
		}
		summaries = append(summaries, s)
	}
	return summaries
}

// ratioOf es el mismo cálculo que el helper privado "ratio" de
// internal/eval — no se puede reusar ese directamente (es privado a
// su paquete), pero es una única división de tres líneas, no vale la
// pena exportarla solo para esto.
func ratioOf(numerator, denominator int) eval.Ratio {
	if denominator == 0 {
		return eval.Ratio{Defined: false}
	}
	return eval.Ratio{Value: float64(numerator) / float64(denominator), Defined: true}
}
