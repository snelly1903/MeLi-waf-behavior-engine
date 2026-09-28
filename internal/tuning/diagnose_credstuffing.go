package tuning

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// CredentialStuffingCampaignAnalysis es, para UNA campaña real de
// credential_stuffing (un grupo de red, dentro de un seed/ratio), el
// contraste entre lo que pasó de verdad en TODA la campaña (ground
// truth: duración, IPs/cuentas distintas totales) y lo máximo que el
// detector real llegó a ver dentro de CUALQUIER ventana de
// correlación suya — tarea 1.9, diagnóstico previo a tocar cualquier
// threshold de credential_stuffing.
type CredentialStuffingCampaignAnalysis struct {
	Seed        uint64
	Ratio       int
	CampaignKey string // "network:asn:<N>"

	CampaignDuration      time.Duration
	TotalRequests         int
	TotalDistinctIPs      int // ground truth, TODA la campaña
	TotalDistinctAccounts int // ground truth, TODA la campaña

	// MaxWindow* es el máximo, entre TODAS las evaluaciones de esta
	// campaña, de lo que el detector veía en su ventana de
	// correlación en ESE momento — nunca el total de la campaña.
	MaxWindowDistinctIPs      int
	MaxWindowDistinctAccounts int
	MaxWindowTotalAttempts    int
	MaxWindowFailedRatio      float64

	// Thresholds actuales, para comparar directo contra los Max*
	// de arriba.
	MinDistinctIPs      int
	MinDistinctAccounts int
	MinAttempts         int
	MinFailedRatio      float64

	// LimitingGates son los nombres de las condiciones cuyo MÁXIMO DE
	// VENTANA, en TODA la campaña, nunca llegó a cruzar su threshold
	// — la prueba de que esa condición específica es la que impide
	// disparar, no una suposición.
	LimitingGates []string

	// FirstDetectionRequestIndex es 1-indexada, DENTRO de esta
	// campaña — 0 si el gate PROPIO de credential_stuffing nunca
	// disparó.
	FirstDetectionRequestIndex int
	FirstDetectionTime         time.Time
	DetectedEventually         bool

	// TimeToFirstDetection es FirstDetectionTime menos el timestamp
	// del primer evento de la campaña — Defined=false si
	// DetectedEventually es false (promediar "nunca" no tiene
	// sentido numérico, mismo criterio que OptionalDuration en
	// aggregate.go).
	TimeToFirstDetection OptionalDuration

	// Pct* son porcentajes (0-100) del total de eventos de ESTA
	// campaña, según qué detector(es) dispararon para cada uno —
	// mismas cuatro categorías que ComputeMitigationAttribution, pero
	// sin condicionar a que el evento haya sido mitigado: cubre el
	// 100% de los eventos de la campaña, dispare lo que dispare.
	// *Events son los conteos crudos detrás de cada Pct — se exponen
	// aparte para poder agregar varias campañas (por ejemplo, entre
	// seeds) sin perder precisión por redondeo.
	PctCredentialOnly float64
	PctAnomalyOnly    float64
	PctBoth           float64
	PctNeither        float64

	CredOnlyEvents int
	AnomOnlyEvents int
	BothEvents     int
	NeitherEvents  int
}

// AnalyzeCredentialStuffingCampaigns cruza scenarioEvents (los
// eventos ya etiquetados, en el mismo orden que produjo
// datagen.BuildScenario) con diagnostics (de RunDiagnostics, MISMO
// orden y longitud) y arma un CredentialStuffingCampaignAnalysis por
// cada grupo de red distinto que aparezca en eventos etiquetados
// credential_stuffing. cfg es la Config de credential_stuffing usada
// en esa corrida — de ahí salen los thresholds contra los que se
// compara.
func AnalyzeCredentialStuffingCampaigns(scenarioEvents []groundtruth.LabeledEvent, diagnostics []EventDiagnostic, cfg credstuffing.Config) ([]CredentialStuffingCampaignAnalysis, error) {
	if len(scenarioEvents) != len(diagnostics) {
		return nil, fmt.Errorf("tuning: AnalyzeCredentialStuffingCampaigns: %d eventos, %d diagnósticos — deben coincidir", len(scenarioEvents), len(diagnostics))
	}

	type acc struct {
		seed                              uint64
		ratio                             int
		key                               string
		firstEventAt, lastEventAt         time.Time
		totalRequests                     int
		ips                               map[netip.Addr]struct{}
		accounts                          map[string]struct{}
		maxIPs, maxAccounts               int
		maxAttempts                       int
		maxFailedRatio                    float64
		firstDetectionIdx                 int
		firstDetectionAt                  time.Time
		detected                          bool
		credOnly, anomOnly, both, neither int
	}
	groups := make(map[string]*acc)
	var order []string

	for i, le := range scenarioEvents {
		if le.Label != groundtruth.LabelCredentialStuffing {
			continue
		}
		d := diagnostics[i]
		if !d.CredentialStuffingGateFound {
			// No debería pasar para un evento CS real (siempre es una
			// ruta de auth con IP resoluble) — si pasara, se excluye
			// en vez de inventar una campaña sin datos de gate.
			continue
		}

		key := fmt.Sprintf("seed=%d|ratio=%d|%s", d.Seed, d.Ratio, d.CredentialStuffingGate.Group)
		a, exists := groups[key]
		if !exists {
			a = &acc{
				seed: d.Seed, ratio: d.Ratio, key: d.CredentialStuffingGate.Group,
				firstEventAt: le.Event.Timestamp,
				ips:          make(map[netip.Addr]struct{}),
				accounts:     make(map[string]struct{}),
			}
			groups[key] = a
			order = append(order, key)
		}

		a.totalRequests++
		a.ips[le.Event.ClientIP] = struct{}{}
		if le.Event.LoginUserHash != "" {
			a.accounts[le.Event.LoginUserHash] = struct{}{}
		}
		if le.Event.Timestamp.Before(a.firstEventAt) {
			a.firstEventAt = le.Event.Timestamp
		}
		if le.Event.Timestamp.After(a.lastEventAt) {
			a.lastEventAt = le.Event.Timestamp
		}

		g := d.CredentialStuffingGate
		if g.DistinctIPs > a.maxIPs {
			a.maxIPs = g.DistinctIPs
		}
		if g.DistinctAccounts > a.maxAccounts {
			a.maxAccounts = g.DistinctAccounts
		}
		if g.TotalAttempts > a.maxAttempts {
			a.maxAttempts = g.TotalAttempts
		}
		if g.FailedRatio > a.maxFailedRatio {
			a.maxFailedRatio = g.FailedRatio
		}

		if !a.detected && d.CredentialStuffing.Triggered {
			a.detected = true
			a.firstDetectionIdx = a.totalRequests
			a.firstDetectionAt = le.Event.Timestamp
		}

		winner, ok := winningAnomalyEval(d.Anomaly)
		anomTriggered := ok && winner.Triggered
		credTriggered := d.CredentialStuffing.Triggered
		switch {
		case credTriggered && anomTriggered:
			a.both++
		case credTriggered:
			a.credOnly++
		case anomTriggered:
			a.anomOnly++
		default:
			a.neither++
		}
	}

	result := make([]CredentialStuffingCampaignAnalysis, 0, len(order))
	for _, key := range order {
		a := groups[key]

		var limiting []string
		if a.maxIPs < cfg.MinDistinctIPs {
			limiting = append(limiting, fmt.Sprintf("MinDistinctIPs(%d<%d)", a.maxIPs, cfg.MinDistinctIPs))
		}
		if a.maxAccounts < cfg.MinDistinctAccounts {
			limiting = append(limiting, fmt.Sprintf("MinDistinctAccounts(%d<%d)", a.maxAccounts, cfg.MinDistinctAccounts))
		}
		if a.maxAttempts < cfg.MinAttempts {
			limiting = append(limiting, fmt.Sprintf("MinAttempts(%d<%d)", a.maxAttempts, cfg.MinAttempts))
		}
		if a.maxFailedRatio < cfg.MinFailedRatio {
			limiting = append(limiting, fmt.Sprintf("MinFailedRatio(%.2f<%.2f)", a.maxFailedRatio, cfg.MinFailedRatio))
		}

		total := a.totalRequests
		pct := func(n int) float64 {
			if total == 0 {
				return 0
			}
			return float64(n) / float64(total) * 100
		}

		var timeToDetection OptionalDuration
		if a.detected {
			timeToDetection = OptionalDuration{Value: a.firstDetectionAt.Sub(a.firstEventAt), Defined: true}
		}

		result = append(result, CredentialStuffingCampaignAnalysis{
			Seed: a.seed, Ratio: a.ratio, CampaignKey: a.key,
			CampaignDuration:      a.lastEventAt.Sub(a.firstEventAt),
			TotalRequests:         total,
			TotalDistinctIPs:      len(a.ips),
			TotalDistinctAccounts: len(a.accounts),

			MaxWindowDistinctIPs:      a.maxIPs,
			MaxWindowDistinctAccounts: a.maxAccounts,
			MaxWindowTotalAttempts:    a.maxAttempts,
			MaxWindowFailedRatio:      a.maxFailedRatio,

			MinDistinctIPs:      cfg.MinDistinctIPs,
			MinDistinctAccounts: cfg.MinDistinctAccounts,
			MinAttempts:         cfg.MinAttempts,
			MinFailedRatio:      cfg.MinFailedRatio,

			LimitingGates: limiting,

			FirstDetectionRequestIndex: a.firstDetectionIdx,
			FirstDetectionTime:         a.firstDetectionAt,
			DetectedEventually:         a.detected,
			TimeToFirstDetection:       timeToDetection,

			PctCredentialOnly: pct(a.credOnly),
			PctAnomalyOnly:    pct(a.anomOnly),
			PctBoth:           pct(a.both),
			PctNeither:        pct(a.neither),

			CredOnlyEvents: a.credOnly,
			AnomOnlyEvents: a.anomOnly,
			BothEvents:     a.both,
			NeitherEvents:  a.neither,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Seed != result[j].Seed {
			return result[i].Seed < result[j].Seed
		}
		return result[i].Ratio < result[j].Ratio
	})
	return result, nil
}

// MaxWindowDistinctIPsDistribution resume, entre varias campañas, el
// máximo de DistinctIPs-por-ventana observado en cada una — pedido
// explícitamente si MinDistinctIPs resulta ser el gate limitante.
func MaxWindowDistinctIPsDistribution(campaigns []CredentialStuffingCampaignAnalysis) PercentileSummary {
	values := make([]float64, len(campaigns))
	for i, c := range campaigns {
		values[i] = float64(c.MaxWindowDistinctIPs)
	}
	return Summarize(values)
}

// RenderCredentialStuffingCampaigns arma el reporte en Markdown de
// campaigns.
func RenderCredentialStuffingCampaigns(campaigns []CredentialStuffingCampaignAnalysis) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("## Campañas de credential_stuffing: ventana real del detector vs. ground truth\n\n")
	w("| Seed | Ratio | Campaña | Duración | Requests | IPs totales | Cuentas totales | Max ventana IPs (min) | Max ventana Cuentas (min) | Max ventana Attempts (min) | Max ventana FailedRatio (min) | Gates limitantes | 1ra detección propia (índice) | Detectada (gate propio) |\n")
	w("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, c := range campaigns {
		w("| %d | %d%% | %s | %s | %d | %d | %d | %d (min %d) | %d (min %d) | %d (min %d) | %.2f (min %.2f) | %v | %d | %v |\n",
			c.Seed, c.Ratio, c.CampaignKey, c.CampaignDuration.Round(time.Second), c.TotalRequests,
			c.TotalDistinctIPs, c.TotalDistinctAccounts,
			c.MaxWindowDistinctIPs, c.MinDistinctIPs,
			c.MaxWindowDistinctAccounts, c.MinDistinctAccounts,
			c.MaxWindowTotalAttempts, c.MinAttempts,
			c.MaxWindowFailedRatio, c.MinFailedRatio,
			c.LimitingGates, c.FirstDetectionRequestIndex, c.DetectedEventually,
		)
	}
	w("\n")

	w("## Atribución por evento dentro de cada campaña (%% del total de esa campaña)\n\n")
	w("| Seed | Ratio | Campaña | Credential only | Anomaly only | Both | Neither |\n")
	w("|---|---|---|---|---|---|---|\n")
	for _, c := range campaigns {
		w("| %d | %d%% | %s | %.1f%% | %.1f%% | %.1f%% | %.1f%% |\n",
			c.Seed, c.Ratio, c.CampaignKey, c.PctCredentialOnly, c.PctAnomalyOnly, c.PctBoth, c.PctNeither)
	}
	w("\n")

	dist := MaxWindowDistinctIPsDistribution(campaigns)
	w("## Distribución del máximo de DistinctIPs-por-ventana entre campañas\n\n")
	w("Todas las campañas: N=%d, min=%.0f p50=%.0f p95=%.0f max=%.0f (threshold MinDistinctIPs=%d)\n\n", dist.N, dist.Min, dist.P50, dist.P95, dist.Max, campaignsMinDistinctIPs(campaigns))

	byRatio := make(map[int][]CredentialStuffingCampaignAnalysis)
	var ratios []int
	for _, c := range campaigns {
		if _, ok := byRatio[c.Ratio]; !ok {
			ratios = append(ratios, c.Ratio)
		}
		byRatio[c.Ratio] = append(byRatio[c.Ratio], c)
	}
	sort.Ints(ratios)
	for _, ratio := range ratios {
		d := MaxWindowDistinctIPsDistribution(byRatio[ratio])
		w("Solo %d%%: N=%d, min=%.0f p50=%.0f p95=%.0f max=%.0f\n\n", ratio, d.N, d.Min, d.P50, d.P95, d.Max)
	}

	return string(b)
}

func campaignsMinDistinctIPs(campaigns []CredentialStuffingCampaignAnalysis) int {
	if len(campaigns) == 0 {
		return 0
	}
	return campaigns[0].MinDistinctIPs
}
