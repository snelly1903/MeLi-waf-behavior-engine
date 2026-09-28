package tuning

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// WindowSensitivityRow es, para UNA campaña real de credential_stuffing
// y UNA duración de ventana candidata, el máximo rolling de las
// cuatro señales del gate calculado offline — tarea 1.9, verificación
// previa al sweep de credential_stuffing. Se calcula con un Detector
// propio (nunca el de producción) cuyo único campo distinto de la
// Config actual es Window: los cuatro Min* siguen siendo los
// ACTUALES, así que Crosses* solo informa si ESE máximo, con ESA
// ventana, ya cruzaría el threshold de hoy — no implica ningún cambio
// de threshold todavía.
type WindowSensitivityRow struct {
	Seed        uint64
	Ratio       int
	CampaignKey string
	Window      time.Duration

	MaxDistinctIPs      int
	MaxDistinctAccounts int
	MaxTotalAttempts    int
	MaxFailedRatio      float64

	CrossesMinDistinctIPs      bool
	CrossesMinDistinctAccounts bool
	CrossesMinAttempts         bool
	CrossesMinFailedRatio      bool
}

// AnalyzeWindowSensitivity corre, para cada duración en windows, un
// Detector de credential_stuffing propio y limpio (misma Config que
// baseCfg, salvo Window) sobre TODOS los eventos de scenario — igual
// que RunDiagnostics, porque el detector real también observa
// tráfico legítimo del mismo grupo de red además del malicioso, no
// solo los eventos etiquetados — y registra el máximo histórico de
// cada señal del gate únicamente en los eventos etiquetados
// credential_stuffing de cada campaña (agrupada por seed+ratio+grupo
// de red). No modifica baseCfg ni ningún detector usado en el resto
// de la tarea 1.9.
func AnalyzeWindowSensitivity(scenario datagen.Scenario, resolver credstuffing.NetworkResolver, baseCfg credstuffing.Config, windows []time.Duration) ([]WindowSensitivityRow, error) {
	seed := scenario.Stats.Seed
	ratio := int(math.Round(scenario.Stats.TargetMaliciousRatio * 100))

	type acc struct {
		key                 string
		maxIPs, maxAccounts int
		maxAttempts         int
		maxFailedRatio      float64
	}

	var rows []WindowSensitivityRow
	for _, w := range windows {
		cfg := baseCfg
		cfg.Window = w
		cfg.Resolver = resolver
		det, err := credstuffing.NewDetector(cfg)
		if err != nil {
			return nil, fmt.Errorf("tuning: AnalyzeWindowSensitivity: %w", err)
		}

		maxima := make(map[string]*acc)
		var order []string

		for _, le := range scenario.Events {
			e := le.Payload()
			det.Observe(e)
			gate, found := det.EvaluateGateMetrics(e)
			if !found || le.Label != groundtruth.LabelCredentialStuffing {
				continue
			}

			a, ok := maxima[gate.Group]
			if !ok {
				a = &acc{key: gate.Group}
				maxima[gate.Group] = a
				order = append(order, gate.Group)
			}
			if gate.DistinctIPs > a.maxIPs {
				a.maxIPs = gate.DistinctIPs
			}
			if gate.DistinctAccounts > a.maxAccounts {
				a.maxAccounts = gate.DistinctAccounts
			}
			if gate.TotalAttempts > a.maxAttempts {
				a.maxAttempts = gate.TotalAttempts
			}
			if gate.FailedRatio > a.maxFailedRatio {
				a.maxFailedRatio = gate.FailedRatio
			}
		}

		for _, key := range order {
			a := maxima[key]
			rows = append(rows, WindowSensitivityRow{
				Seed: seed, Ratio: ratio, CampaignKey: a.key, Window: w,

				MaxDistinctIPs:      a.maxIPs,
				MaxDistinctAccounts: a.maxAccounts,
				MaxTotalAttempts:    a.maxAttempts,
				MaxFailedRatio:      a.maxFailedRatio,

				CrossesMinDistinctIPs:      a.maxIPs >= baseCfg.MinDistinctIPs,
				CrossesMinDistinctAccounts: a.maxAccounts >= baseCfg.MinDistinctAccounts,
				CrossesMinAttempts:         a.maxAttempts >= baseCfg.MinAttempts,
				CrossesMinFailedRatio:      a.maxFailedRatio >= baseCfg.MinFailedRatio,
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Seed != rows[j].Seed {
			return rows[i].Seed < rows[j].Seed
		}
		if rows[i].CampaignKey != rows[j].CampaignKey {
			return rows[i].CampaignKey < rows[j].CampaignKey
		}
		return rows[i].Window < rows[j].Window
	})
	return rows, nil
}

// RenderWindowSensitivity arma el reporte en Markdown de rows —
// pensado para mostrar, por campaña, cómo cambia cada máximo al
// variar solo Window.
func RenderWindowSensitivity(rows []WindowSensitivityRow, cfg credstuffing.Config) string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("## Sensibilidad a Window: máximo rolling por campaña (10%%), sin tocar ningún threshold\n\n")
	w("Thresholds actuales: MinDistinctIPs=%d, MinDistinctAccounts=%d, MinAttempts=%d, MinFailedRatio=%.2f\n\n",
		cfg.MinDistinctIPs, cfg.MinDistinctAccounts, cfg.MinAttempts, cfg.MinFailedRatio)
	w("| Seed | Campaña | Window | Max IPs | Max Cuentas | Max Attempts | Max FailedRatio | Cruza IPs | Cruza Cuentas | Cruza Attempts | Cruza FailedRatio |\n")
	w("|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		w("| %d | %s | %s | %d | %d | %d | %.2f | %v | %v | %v | %v |\n",
			r.Seed, r.CampaignKey, r.Window,
			r.MaxDistinctIPs, r.MaxDistinctAccounts, r.MaxTotalAttempts, r.MaxFailedRatio,
			r.CrossesMinDistinctIPs, r.CrossesMinDistinctAccounts, r.CrossesMinAttempts, r.CrossesMinFailedRatio,
		)
	}
	w("\n")
	return string(b)
}
