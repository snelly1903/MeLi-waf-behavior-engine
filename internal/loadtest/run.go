// Package loadtest es el harness del load test HTTP end-to-end
// (POST /v1/events): un cliente de carga chico, sin dependencias
// externas (net/http + sync/atomic de la librería estándar), pensado
// para correr contra un *httpapi.Server real montado en un
// httptest.Server local — nunca contra Internet.
//
// Los resultados de este paquete son "local end-to-end / loopback
// throughput" — cliente y servidor comparten el mismo proceso y
// máquina, así que NO representan la capacidad absoluta de un
// servidor desplegado por separado (ver docs/decisiones.md).
package loadtest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

// PerfSeed es la semilla determinista compartida por los perfiles de
// tráfico de performance — nunca 101/102/103 (tuning) ni 201/202/203
// (holdout), para no mezclar conceptos. Se redefine tal cual en
// internal/engine/decide_bench_test.go (no se puede importar un
// paquete de test externo desde acá) — mismo criterio ya usado en el
// proyecto para constantes compartidas entre binarios/paquetes de
// test independientes (ver cmd/diagnosecs).
const PerfSeed uint64 = 901

// DefaultMaxIdleConnsPerHost es el mínimo recomendado para
// NewClient cuando no se conoce la concurrencia máxima de antemano
// — alto a propósito (ver NewClient) para que el pool de conexiones
// nunca sea el cuello de botella del propio harness de medición.
const DefaultMaxIdleConnsPerHost = 256

// NewClient arma un *http.Client con un *http.Transport propio
// (nunca http.DefaultTransport, cuyo MaxIdleConnsPerHost=2 de
// fábrica fuerza a reabrir conexión TCP en casi cada request bajo
// concurrencia alta, midiendo el costo de abrir conexiones en vez
// del costo real de servir) — keep-alive habilitado (default de
// http.Transport), con MaxIdleConns/MaxIdleConnsPerHost generosos
// respecto a concurrency para que nunca sea el cuello de botella.
// Pensado para construirse UNA vez por repetición (compartido entre
// todos los workers de esa repetición, nunca uno por worker) — ver
// Run.
func NewClient(concurrency int) *http.Client {
	maxConns := DefaultMaxIdleConnsPerHost
	if concurrency > maxConns {
		maxConns = concurrency * 2
	}
	transport := &http.Transport{
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: maxConns,
		IdleConnTimeout:     90 * time.Second,
	}
	return &http.Client{Transport: transport}
}

// sample es un intento de request ya completado — se guarda en un
// slice LOCAL de cada worker (nunca un slice compartido con lock por
// request) para no introducir contención artificial entre workers
// que distorsione la medición de concurrencia.
type sample struct {
	latency time.Duration
	ok      bool
}

// RunConfig configura UNA repetición del load test contra UN
// servidor ya levantado.
type RunConfig struct {
	// BaseURL es la URL base del servidor (por ejemplo, la de un
	// httptest.Server) — SIN el path, se le agrega "/v1/events".
	BaseURL string

	// Events es la secuencia de eventos a enviar, en el MISMO orden
	// que produjo datagen.BuildScenario. Un cursor atómico
	// compartido entre todos los workers reparte esta secuencia
	// única entre ellos (request n -> Events[n % len(Events)]) — así
	// aumentar Concurrency nunca duplica artificialmente el mismo
	// evento N veces en simultáneo, y se mantiene aproximadamente la
	// composición real del escenario. El MISMO cursor sigue avanzando
	// entre la fase de warmup y la de medición (nunca se resetea ahí)
	// — solo se resetea entre repeticiones (cada llamada a Run
	// arranca su propio cursor). Timestamp se reescribe a time.Now()
	// en cada envío (nunca se reutiliza el timestamp original del
	// escenario): el validador de producción exige timestamps
	// recientes, y esto mide rendimiento de serving, no reproduce
	// detección — ver docs/decisiones.md.
	Events []event.Event

	Concurrency int
	Warmup      time.Duration
	Measurement time.Duration

	// Client es COMPARTIDO entre todos los workers de esta repetición
	// — nunca uno por worker. Ver NewClient para un *http.Transport
	// con keep-alive y pool de conexiones dimensionado para
	// Concurrency.
	Client *http.Client
}

// RunResult es el resultado crudo de UNA repetición — SOLO de la
// fase de medición: la fase de warmup (ver Run) corre en un bloque
// de código estructuralmente separado, que nunca escribe acá, así
// que ninguna muestra de warmup puede filtrarse por construcción
// (no por una condición que pudiera fallar).
type RunResult struct {
	Requests  int
	Errors    int
	Latencies []time.Duration // todas las muestras de la fase de medición (éxito y error), sin ordenar

	// ActualDuration es el tiempo real transcurrido durante la fase
	// de medición — nunca el Measurement nominal pedido, que es solo
	// un objetivo aproximado (el último request en vuelo de cada
	// worker puede terminar un poco después del deadline).
	ActualDuration time.Duration
}

// Throughput es Requests/ActualDuration, en requests por segundo.
func (r RunResult) Throughput() float64 {
	if r.ActualDuration <= 0 {
		return 0
	}
	return float64(r.Requests) / r.ActualDuration.Seconds()
}

// ErrorRate es Errors/Requests — 0 si Requests es 0 (nunca división
// por cero).
func (r RunResult) ErrorRate() float64 {
	if r.Requests == 0 {
		return 0
	}
	return float64(r.Errors) / float64(r.Requests)
}

// P50/P95/P99 son los percentiles de Latencies de ESTA repetición
// sola (nearest-rank) — la base de "mediana de percentiles entre
// repeticiones" que calcula Aggregate (nunca mezclar las muestras
// crudas de las 3 repeticiones en un solo pool antes de calcular el
// percentil).
func (r RunResult) P50() time.Duration { return percentile(r.Latencies, 50) }
func (r RunResult) P95() time.Duration { return percentile(r.Latencies, 95) }
func (r RunResult) P99() time.Duration { return percentile(r.Latencies, 99) }

// Run ejecuta UNA repetición en DOS fases estructuralmente separadas:
// primero fireWorkers corre durante Warmup con record=false (tráfico
// real enviado, cada muestra descartada en el momento — nunca llega a
// existir en ningún resultado), y recién
// DESPUÉS de que esa fase termina por completo (wg.Wait() adentro de
// fireWorkers) arranca la fase de medición, con su propio reloj de
// referencia (measureStart) y record=true. No hay ninguna condición
// "si el timestamp es posterior a X, grabar" compartida entre fases
// — son dos bloques de código distintos, así que un bug futuro en
// uno no puede filtrar muestras de warmup a la medición. cfg.Client
// se COMPARTE entre las dos fases y entre todos los workers (ver
// NewClient) — nunca se crea un cliente nuevo por fase ni por
// worker. El cursor atómico SÍ es compartido entre las dos fases
// (nunca se resetea ahí), para que la secuencia de eventos sea
// continua de punta a punta de la repetición.
func Run(ctx context.Context, cfg RunConfig) RunResult {
	var cursor int64

	// Warm-up: prepara conexiones y estado sin registrar métricas.
	fireWorkers(ctx, cfg, &cursor, time.Now().Add(cfg.Warmup), false)

	// Medición: registra las métricas del intervalo evaluado. Separada
	// por completo del warmup — arranca su propio reloj de referencia,
	// recién acá empieza a existir cualquier RunResult.
	measureStart := time.Now()
	results := fireWorkers(ctx, cfg, &cursor, measureStart.Add(cfg.Measurement), true)
	actualEnd := time.Now()

	var res RunResult
	for _, ls := range results {
		for _, s := range ls {
			res.Requests++
			if !s.ok {
				res.Errors++
			}
			res.Latencies = append(res.Latencies, s.latency)
		}
	}
	res.ActualDuration = actualEnd.Sub(measureStart)
	if res.ActualDuration < 0 {
		res.ActualDuration = 0
	}
	return res
}

// fireWorkers levanta cfg.Concurrency workers que leen el cursor
// atómico COMPARTIDO (pasado por puntero, para que dos llamadas
// sucesivas — warmup y medición — sigan la MISMA secuencia continua)
// y envían POST /v1/events hasta deadline. record=false hace que
// cada muestra se descarte de inmediato (fase de warmup); record=true
// las guarda en el slice LOCAL de cada worker (fase de medición).
func fireWorkers(ctx context.Context, cfg RunConfig, cursor *int64, deadline time.Time, record bool) [][]sample {
	results := make([][]sample, cfg.Concurrency)

	var wg sync.WaitGroup
	wg.Add(cfg.Concurrency)
	for w := 0; w < cfg.Concurrency; w++ {
		go func(w int) {
			defer wg.Done()
			var local []sample
			for {
				select {
				case <-ctx.Done():
					results[w] = local
					return
				default:
				}
				if !time.Now().Before(deadline) {
					break
				}

				n := atomic.AddInt64(cursor, 1) - 1
				e := cfg.Events[int(n)%len(cfg.Events)]
				e.Timestamp = time.Now()
				body, _ := json.Marshal(e)

				reqStart := time.Now()
				resp, err := cfg.Client.Post(cfg.BaseURL+"/v1/events", "application/json", bytes.NewReader(body))
				lat := time.Since(reqStart)

				ok := err == nil
				if resp != nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						ok = false
					}
				}

				if record {
					local = append(local, sample{latency: lat, ok: ok})
				}
			}
			results[w] = local
		}(w)
	}
	wg.Wait()
	return results
}
