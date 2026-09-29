package main

import (
	"fmt"
	"os"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/loadtest"
)

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// summaryParams son los parámetros de la corrida que se documentan en
// summary.md: hardware, Go version, configuración, duración,
// concurrency, OTel on/off, modo de ASN.
type summaryParams struct {
	Profiles      []string
	Concurrencies []int
	Reps          int
	Warmup        time.Duration
	Measurement   time.Duration
	ASNMode       string

	ChallengeThreshold float64
	BlockThreshold     float64

	OTelEndpoint       string
	ExperimentDuration time.Duration
}

// writeSummary arma reports/performance/summary.md — el resumen
// legible por humanos, con las advertencias explícitas pedidas: los
// resultados HTTP son "local end-to-end / loopback throughput" (nunca
// capacidad absoluta de un servidor separado, cliente y servidor
// comparten proceso/máquina), el delta de memoria es del proceso
// COMBINADO cliente+servidor (nunca RAM exclusiva del servidor), y
// ningún resultado local se extrapola linealmente a 1.000 millones de
// requests/hora.
func writeSummary(path string, combos []loadtest.CombinationResult, p summaryParams) error {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }

	w("# Performance del prototipo — resumen\n\n")

	env := detectEnv()
	w("## Entorno\n\n")
	w("| | |\n|---|---|\n")
	w("| Go version | %s |\n", env.GoVersion)
	w("| SO/versión | %s |\n", nonEmpty(env.OSVersion, "desconocido"))
	w("| Arquitectura | %s/%s |\n", env.GOOS, env.GOARCH)
	w("| CPUs lógicas (runtime.NumCPU) | %d |\n", env.NumCPU)
	w("| GOMAXPROCS | %d |\n", env.GOMAXPROCS)
	if env.RAMBytes > 0 {
		w("| RAM | %.1f GB |\n", float64(env.RAMBytes)/(1<<30))
	} else {
		w("| RAM | desconocida |\n")
	}
	w("| Duración total del experimento | %s |\n", p.ExperimentDuration.Round(time.Millisecond))
	w("\n")

	w("## Configuración\n\n")
	w("| | |\n|---|---|\n")
	w("| Perfiles | %v |\n", p.Profiles)
	w("| Concurrencias | %v |\n", p.Concurrencies)
	w("| Repeticiones por combinación | %d |\n", p.Reps)
	w("| Warmup | %s |\n", p.Warmup)
	w("| Measurement | %s |\n", p.Measurement)
	w("| Modo ASN | %s |\n", p.ASNMode)
	w("| Policy (final congelada) | Challenge=%.2f Block=%.2f |\n", p.ChallengeThreshold, p.BlockThreshold)
	w("| ScoreFloor | sin cambios (default de cada detector, congelado tras el holdout) |\n")
	if p.OTelEndpoint != "" {
		w("| OTel Collector (comparativo) | %s |\n", p.OTelEndpoint)
	} else {
		w("| OTel Collector (comparativo) | no corrido (sin --otel-endpoint) |\n")
	}
	w("\n")

	w("## Resultados — matriz principal (OTel deshabilitado)\n\n")
	w("**Nota metodológica**: estos números son *local end-to-end / loopback throughput* — cliente y servidor corren en el MISMO proceso y máquina (httptest.Server sobre loopback). No representan la capacidad absoluta de un servidor desplegado por separado, donde el cliente no compite por los mismos CPUs/memoria/scheduler que el servidor.\n\n")
	w("Throughput: mediana de %d repeticiones independientes, con min/max entre paréntesis. Latencias (p50/p95/p99): percentil calculado POR repetición, y acá se muestra la MEDIANA de esos percentiles entre las %d repeticiones — nunca las muestras crudas de todas las repeticiones mezcladas en un pool único. Resultados crudos por repetición en loadtest.json (`repetitions_detail`).\n\n", p.Reps, p.Reps)
	w("| Perfil | Concurrencia | Throughput mediana (min–max) req/s | p50 ms | p95 ms | p99 ms | Error rate | Δ memoria proceso combinado |\n")
	w("|---|---|---|---|---|---|---|---|\n")
	for _, c := range combos {
		if c.OTelEnabled || c.PairedOTelComparison {
			continue
		}
		a := c.Aggregated
		w("| %s | %d | %.1f (%.1f–%.1f) | %.2f | %.2f | %.2f | %.4f | %+d B |\n",
			c.Profile, c.Concurrency, a.ThroughputMedian, a.ThroughputMin, a.ThroughputMax,
			a.P50.Seconds()*1000, a.P95.Seconds()*1000, a.P99.Seconds()*1000,
			a.ErrorRate, c.CombinedProcessAllocDeltaBytes,
		)
	}
	w("\n")

	pairedRows := pairedOTelCombos(combos)
	if len(pairedRows) > 0 {
		w("## Comparativo OTel: disabled/noop vs. enabled + Collector local (pareado)\n\n")
		w("Solo perfil \"mixed\", concurrencia 25 y 100. Cada par OFF->ON corrió uno INMEDIATAMENTE después del otro, cerca en el tiempo (nunca separados por el resto de la matriz principal) — filas independientes de la matriz principal de arriba, para no mezclar mediciones tomadas en momentos distintos.\n\n")
		w("| Concurrencia | OTel | Throughput mediana req/s | p95 ms | p99 ms | Error rate |\n")
		w("|---|---|---|---|---|---|\n")
		for _, c := range pairedRows {
			a := c.Aggregated
			otelLabel := "off"
			if c.OTelEnabled {
				otelLabel = "on"
			}
			w("| %d | %s | %.1f | %.2f | %.2f | %.4f |\n", c.Concurrency, otelLabel, a.ThroughputMedian, a.P95.Seconds()*1000, a.P99.Seconds()*1000, a.ErrorRate)
		}
		w("\n")
	}

	w("## Microbenchmark (BehavioralDecider.Decide())\n\n")
	w("Correr `go test -bench=. -benchmem ./internal/engine/...` (o `make perf-bench`) — reporta ns/op, B/op y allocs/op para los perfiles normal/mixed/attack-heavy. Salida cruda en `microbench.txt` en esta misma carpeta, si se generó con `make perf-bench`.\n\n")

	w("## Limitaciones y alcance\n\n")
	w("- **Nunca se extrapola linealmente a 1.000 millones de requests/hora.** Esa escala se trata conceptualmente en docs/scaling-1b-rph.md — un resultado local de loopback en una sola máquina no dice nada por sí solo sobre un despliegue distribuido real.\n")
	w("- **Δ memoria es del proceso COMBINADO cliente+servidor**, nunca memoria exclusiva del servidor — este harness corre ambos en el mismo proceso Go.\n")
	w("- **Los timestamps de los eventos se reescriben a `time.Now()` en cada envío** (el validador de producción exige timestamps recientes) — esto mide rendimiento de *serving*, no reproduce la precisión de detección de tuning/holdout: comprimir el tiempo real de una campaña a milisegundos de wall-clock cambia por completo el comportamiento de las ventanas deslizantes de los detectores. Los resultados de detección de este load test NO son comparables con los de tuning/holdout.\n")
	w("- **No se corrió profiling (pprof)** — pedido explícito: medir primero, optimizar (si hace falta) después.\n")

	return os.WriteFile(path, b, 0o644)
}

func pairedOTelCombos(combos []loadtest.CombinationResult) []loadtest.CombinationResult {
	var out []loadtest.CombinationResult
	for _, c := range combos {
		if c.PairedOTelComparison {
			out = append(out, c)
		}
	}
	return out
}
