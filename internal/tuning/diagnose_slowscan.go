package tuning

import (
	"fmt"
	"sort"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

// CampaignGateAnalysis es, para UNA campaña de slow_scan, cuántos
// requests hicieron falta hasta que el GATE PROPIO de slowscan.Detector
// disparó (SlowScan.Triggered — no la Decision final combinada, que
// podría reflejar otro detector) y, para las campañas no detectadas o
// detectadas tarde, cuál de las cinco condiciones del gate seguía sin
// cumplirse justo antes.
type CampaignGateAnalysis struct {
	Seed        uint64
	Ratio       int
	CampaignKey string

	TotalRequests int

	// FirstDetectionRequestIndex es 1-indexada, DENTRO de esta
	// campaña — 0 si el gate de slowscan nunca disparó.
	FirstDetectionRequestIndex int
	RequestsBeforeDetection    int
	DetectedEventually         bool

	// GateAtLimit es el estado de las cinco condiciones del gate en
	// el momento más informativo: inmediatamente ANTES de la primera
	// detección si se detectó (para ver qué le faltaba un request
	// antes), o en el ÚLTIMO evento de la campaña si nunca se
	// detectó.
	GateAtLimit slowscan.GateMetrics

	// LimitingGates son los nombres de las condiciones que, en
	// GateAtLimit, todavía estaban por debajo de su mínimo — puede
	// haber más de una a la vez.
	LimitingGates []string
}

func slowScanScope(d EventDiagnostic) slowscan.GateMetrics {
	return d.SlowScanGates[len(d.SlowScanGates)-1] // sesión si existe, si no IP — mismo orden que EvaluateGateMetrics
}

// limitingGates compara g contra cfg y devuelve los nombres de las
// condiciones todavía por debajo de su mínimo.
func limitingGates(g slowscan.GateMetrics, cfg slowscan.Config) []string {
	var limiting []string
	if g.TotalRequests < cfg.MinRequests {
		limiting = append(limiting, fmt.Sprintf("TotalRequests(%d<%d)", g.TotalRequests, cfg.MinRequests))
	}
	if g.DistinctPaths < cfg.MinDistinctPaths {
		limiting = append(limiting, fmt.Sprintf("DistinctPaths(%d<%d)", g.DistinctPaths, cfg.MinDistinctPaths))
	}
	if g.NotFoundRatio < cfg.MinNotFoundRatio {
		limiting = append(limiting, fmt.Sprintf("NotFoundRatio(%.2f<%.2f)", g.NotFoundRatio, cfg.MinNotFoundRatio))
	}
	if g.RouteEntropy < cfg.MinRouteEntropy {
		limiting = append(limiting, fmt.Sprintf("RouteEntropy(%.2f<%.2f)", g.RouteEntropy, cfg.MinRouteEntropy))
	}
	if g.NovelPathRatio < cfg.MinNovelPathRatio {
		limiting = append(limiting, fmt.Sprintf("NovelPathRatio(%.2f<%.2f)", g.NovelPathRatio, cfg.MinNovelPathRatio))
	}
	return limiting
}

// AnalyzeSlowScanCampaigns agrupa diagnostics (de cualquier cantidad
// de seeds/ratios mezclados — se distinguen por Seed/Ratio en el
// resultado) en campañas de slow_scan, usando la misma noción de
// entidad que ya usa internal/slowscan.Detector (sesión si existe, si
// no la IP — ver slowScanScope), y mide dónde estuvo el gate en el
// momento más informativo de cada una.
func AnalyzeSlowScanCampaigns(diagnostics []EventDiagnostic, cfg slowscan.Config) []CampaignGateAnalysis {
	groups := make(map[string][]EventDiagnostic)
	var order []string
	for _, d := range diagnostics {
		if d.Label != groundtruth.LabelSlowScan {
			continue
		}
		key := fmt.Sprintf("seed=%d|ratio=%d|%s", d.Seed, d.Ratio, slowScanScope(d).Scope)
		if _, exists := groups[key]; !exists {
			order = append(order, key)
		}
		groups[key] = append(groups[key], d)
	}
	sort.Strings(order)

	result := make([]CampaignGateAnalysis, 0, len(order))
	for _, key := range order {
		events := groups[key]
		first := events[0]

		firstDetectionIdx := 0
		for i, d := range events {
			if d.SlowScan.Triggered {
				firstDetectionIdx = i + 1 // 1-indexado
				break
			}
		}
		detected := firstDetectionIdx > 0

		var limitEventIdx int // 0-indexado
		switch {
		case detected && firstDetectionIdx > 1:
			limitEventIdx = firstDetectionIdx - 2 // inmediatamente antes de la detección
		case detected:
			limitEventIdx = 0 // detectado en el primer request: no hay "antes"
		default:
			limitEventIdx = len(events) - 1 // nunca detectado: el último evento de la campaña
		}
		gateAtLimit := slowScanScope(events[limitEventIdx])

		requestsBeforeDetection := len(events)
		if detected {
			requestsBeforeDetection = firstDetectionIdx - 1
		}

		result = append(result, CampaignGateAnalysis{
			Seed:                       first.Seed,
			Ratio:                      first.Ratio,
			CampaignKey:                slowScanScope(first).Scope,
			TotalRequests:              len(events),
			FirstDetectionRequestIndex: firstDetectionIdx,
			RequestsBeforeDetection:    requestsBeforeDetection,
			DetectedEventually:         detected,
			GateAtLimit:                gateAtLimit,
			LimitingGates:              limitingGates(gateAtLimit, cfg),
		})
	}
	return result
}

// CampaignSizeDistribution resume TotalRequests entre varias
// campañas: la distribución de tamaño de campaña.
func CampaignSizeDistribution(campaigns []CampaignGateAnalysis) PercentileSummary {
	sizes := make([]float64, len(campaigns))
	for i, c := range campaigns {
		sizes[i] = float64(c.TotalRequests)
	}
	return Summarize(sizes)
}

// RenderSlowScanCampaigns arma un resumen legible en Markdown de
// campaigns, agrupado por ratio, con la distribución de tamaño de
// campaña de cada grupo.
func RenderSlowScanCampaigns(campaigns []CampaignGateAnalysis) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	byRatio := make(map[int][]CampaignGateAnalysis)
	var ratios []int
	for _, c := range campaigns {
		if _, ok := byRatio[c.Ratio]; !ok {
			ratios = append(ratios, c.Ratio)
		}
		byRatio[c.Ratio] = append(byRatio[c.Ratio], c)
	}
	sort.Ints(ratios)

	for _, ratio := range ratios {
		group := byRatio[ratio]
		size := CampaignSizeDistribution(group)
		w("## slow_scan — %d%% malicious (%d campañas)\n\n", ratio, len(group))
		w("Tamaño de campaña (requests): min=%.0f p50=%.0f p95=%.0f max=%.0f\n\n", size.Min, size.P50, size.P95, size.Max)

		w("| Seed | Campaign | Total requests | 1ra detección (índice) | Requests antes | Detectada | Gates limitantes en ese punto |\n")
		w("|---|---|---|---|---|---|---|\n")
		for _, c := range group {
			w("| %d | %s | %d | %d | %d | %v | %v |\n",
				c.Seed, c.CampaignKey, c.TotalRequests, c.FirstDetectionRequestIndex, c.RequestsBeforeDetection, c.DetectedEventually, c.LimitingGates)
		}
		w("\n")
	}
	return string(b)
}
