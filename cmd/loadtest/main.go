// Command loadtest es el load test HTTP end-to-end (POST /v1/events):
// corre la matriz perfil x concurrencia contra un *httpapi.Server
// real montado en httptest.NewServer
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/loadtest"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/telemetry"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/wiring"
)

const (
	asnModeNone      = "none"
	asnModeSimulated = "simulated"
)

var otelPairedConcurrencies = []int{25, 100}

func main() {
	profilesFlag := flag.String("profiles", "normal,mixed,attack-heavy", "perfiles a correr, separados por coma (normal=0% malicioso, mixed=10%, attack-heavy=30%)")
	concurrenciesFlag := flag.String("concurrencies", "1,10,25,50,100", "niveles de concurrencia, separados por coma")
	reps := flag.Int("reps", 3, "repeticiones independientes por combinación (decider/servidor frescos en cada una)")
	warmup := flag.Duration("warmup", 3*time.Second, "duración del calentamiento (tráfico real enviado, pero descartado de las métricas)")
	measurement := flag.Duration("measurement", 10*time.Second, "duración de la medición, después del calentamiento")
	asnMode := flag.String("asn-mode", asnModeSimulated, `resolver de ASN: "simulated" (default, determinista, ejercita la correlación real de credential_stuffing) o "none" (siempre inerte) -- nunca "ripestat"`)
	finalPolicy := wiring.FinalPolicy()
	challengeThreshold := flag.Float64("challenge-threshold", finalPolicy.ChallengeThreshold, "ChallengeThreshold -- default: la Policy final congelada")
	blockThreshold := flag.Float64("block-threshold", finalPolicy.BlockThreshold, "BlockThreshold -- default: la Policy final congelada")
	otelEndpoint := flag.String("otel-endpoint", "", `si se especifica (por ejemplo "localhost:4317"), además de la matriz principal (siempre con OTel deshabilitado) corre el comparativo pareado OTel OFF->ON: perfil "mixed", concurrencia 25 y 100, contra ese Collector`)
	otelInsecure := flag.Bool("otel-insecure", true, "desactiva TLS hacia --otel-endpoint -- solo para un Collector local de desarrollo")
	otelConnectTimeout := flag.Duration("otel-connect-timeout", 3*time.Second, "cuánto espera a que --otel-endpoint quede alcanzable antes de caer a no-op")
	out := flag.String("out", "reports/performance", "carpeta donde escribir loadtest.csv/loadtest.json/summary.md")
	flag.Parse()

	profiles := splitCSV(*profilesFlag)
	concurrencies, err := parseIntCSV(*concurrenciesFlag)
	if err != nil {
		log.Fatalf("loadtest: --concurrencies inválido: %v", err)
	}
	if *asnMode != asnModeNone && *asnMode != asnModeSimulated {
		log.Fatalf("loadtest: --asn-mode inválido: %q (quiere %q o %q)", *asnMode, asnModeNone, asnModeSimulated)
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatalf("loadtest: creando carpeta de salida: %v", err)
	}

	experimentStart := time.Now()

	resolver := buildResolver(*asnMode)
	eventsByProfile := buildProfileEvents(profiles)

	var combos []loadtest.CombinationResult

	for _, profile := range profiles {
		events := eventsByProfile[profile]
		for _, concurrency := range concurrencies {
			combo := runCombination(profile, concurrency, false, false, events, resolver, nil, *reps, *warmup, *measurement, *challengeThreshold, *blockThreshold)
			combos = append(combos, combo)
			log.Printf("loadtest: %s@%d (OTel=off) listo — throughput mediana=%.1f req/s p95=%.2fms error_rate=%.4f",
				profile, concurrency, combo.Aggregated.ThroughputMedian, combo.Aggregated.P95.Seconds()*1000, combo.Aggregated.ErrorRate)
		}
	}

	if *otelEndpoint != "" {
		if _, ok := eventsByProfile["mixed"]; !ok {
			extra := buildProfileEvents([]string{"mixed"})
			eventsByProfile["mixed"] = extra["mixed"]
		}
		recorders, shutdown, usedNoop := telemetry.Init(context.Background(), telemetry.Config{
			Endpoint:       *otelEndpoint,
			Insecure:       *otelInsecure,
			ConnectTimeout: *otelConnectTimeout,
		})
		if usedNoop {
			log.Printf("loadtest: WARNING no se pudo conectar a --otel-endpoint=%q -- el comparativo OTel ON va a medir efectivamente lo mismo que OFF (fail-open, no bloquea el resto del load test)", *otelEndpoint)
		}
		for _, concurrency := range otelPairedConcurrencies {
			off := runCombination("mixed", concurrency, false, true, eventsByProfile["mixed"], resolver, nil, *reps, *warmup, *measurement, *challengeThreshold, *blockThreshold)
			combos = append(combos, off)
			log.Printf("loadtest: mixed@%d OTel=off (pareado) listo — throughput mediana=%.1f req/s p95=%.2fms",
				concurrency, off.Aggregated.ThroughputMedian, off.Aggregated.P95.Seconds()*1000)

			on := runCombination("mixed", concurrency, true, true, eventsByProfile["mixed"], resolver, recorders, *reps, *warmup, *measurement, *challengeThreshold, *blockThreshold)
			combos = append(combos, on)
			log.Printf("loadtest: mixed@%d OTel=on (pareado) listo — throughput mediana=%.1f req/s p95=%.2fms",
				concurrency, on.Aggregated.ThroughputMedian, on.Aggregated.P95.Seconds()*1000)
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := shutdown(shutdownCtx); err != nil {
			log.Printf("loadtest: telemetry shutdown: %v", err)
		}
		cancel()
	}

	experimentDuration := time.Since(experimentStart)

	if err := loadtest.WriteCSV(*out+"/loadtest.csv", combos); err != nil {
		log.Fatalf("loadtest: WriteCSV: %v", err)
	}
	if err := loadtest.WriteJSON(*out+"/loadtest.json", combos); err != nil {
		log.Fatalf("loadtest: WriteJSON: %v", err)
	}
	if err := writeSummary(*out+"/summary.md", combos, summaryParams{
		Profiles: profiles, Concurrencies: concurrencies, Reps: *reps,
		Warmup: *warmup, Measurement: *measurement, ASNMode: *asnMode,
		ChallengeThreshold: *challengeThreshold, BlockThreshold: *blockThreshold,
		OTelEndpoint: *otelEndpoint, ExperimentDuration: experimentDuration,
	}); err != nil {
		log.Fatalf("loadtest: writeSummary: %v", err)
	}

	log.Printf("loadtest: listo en %s — reportes en %s (loadtest.csv, loadtest.json, summary.md)", experimentDuration.Round(time.Millisecond), *out)
}

func runCombination(profile string, concurrency int, otelEnabled, paired bool, events []event.Event, resolver credstuffing.NetworkResolver, recorders *telemetry.Recorders, reps int, warmup, measurement time.Duration, challengeThreshold, blockThreshold float64) loadtest.CombinationResult {
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	var results []loadtest.RunResult
	for r := 0; r < reps; r++ {
		server, err := wiring.BuildServerWithResolver(challengeThreshold, blockThreshold, resolver, recorders)
		if err != nil {
			log.Fatalf("loadtest: BuildServerWithResolver: %v", err)
		}
		httpServer := httptest.NewServer(server.Routes())

		result := loadtest.Run(context.Background(), loadtest.RunConfig{
			BaseURL:     httpServer.URL,
			Events:      events,
			Concurrency: concurrency,
			Warmup:      warmup,
			Measurement: measurement,
			Client:      loadtest.NewClient(concurrency),
		})
		httpServer.Close()
		results = append(results, result)
	}

	runtime.ReadMemStats(&memAfter)

	return loadtest.CombinationResult{
		Profile:                        profile,
		Concurrency:                    concurrency,
		OTelEnabled:                    otelEnabled,
		PairedOTelComparison:           paired,
		Aggregated:                     loadtest.Aggregate(results),
		CombinedProcessAllocDeltaBytes: int64(memAfter.Alloc) - int64(memBefore.Alloc),
	}
}

func buildResolver(asnMode string) credstuffing.NetworkResolver {
	if asnMode == asnModeNone {
		return credstuffing.UnavailableNetworkResolver{}
	}
	r := datagen.NewSimulatedASNResolver()
	return r
}

func buildProfileEvents(profiles []string) map[string][]event.Event {
	ratios := map[string]float64{
		"normal":       0,
		"mixed":        0.10,
		"attack-heavy": 0.30,
	}

	result := make(map[string][]event.Event, len(profiles))
	for _, p := range profiles {
		ratio, ok := ratios[p]
		if !ok {
			log.Fatalf("loadtest: perfil desconocido %q (quiere normal, mixed o attack-heavy)", p)
		}
		scenario := datagen.BuildScenario(datagen.DefaultScenarioConfig(loadtest.PerfSeed, ratio))
		events := make([]event.Event, len(scenario.Events))
		for i, le := range scenario.Events {
			events[i] = le.Payload()
		}
		result[p] = events
	}
	return result
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseIntCSV(s string) ([]int, error) {
	var out []int
	for _, part := range splitCSV(s) {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%q no es un entero válido: %w", part, err)
		}
		out = append(out, n)
	}
	return out, nil
}
