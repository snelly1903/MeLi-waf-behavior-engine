// Resume los retrasos de detección por vector de ataque.
package tuning

import (
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type OptionalFloat struct {
	Value   float64
	Defined bool
}

type OptionalDuration struct {
	Value   time.Duration
	Defined bool
}

type DelaySummary struct {
	Vector                  groundtruth.Label
	Campaigns               int
	DetectedCampaigns       int
	EventualDetectionRate   eval.Ratio
	MeanRequestsToDetection OptionalFloat
	MeanTimeToDetection     OptionalDuration
}

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

func ratioOf(numerator, denominator int) eval.Ratio {
	if denominator == 0 {
		return eval.Ratio{Defined: false}
	}
	return eval.Ratio{Value: float64(numerator) / float64(denominator), Defined: true}
}
