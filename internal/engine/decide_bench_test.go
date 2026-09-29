package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/wiring"
)

// monotonicEventStream reproduce, indefinidamente, el patrón de
// deltas temporales de un escenario real de datagen — necesario
// porque un microbenchmark corre b.N iteraciones, que casi siempre
// superan len(events): un wrap ingenuo (events[i % len(events)] con
// su Timestamp original) haría que la segunda vuelta empiece ANTES
// del watermark que los detectores ya alcanzaron en la primera
// (Observe nunca retrocede el watermark — ver internal/profile,
// internal/credstuffing, internal/anomaly), así que esos eventos
// quedarían fuera de cualquier ventana de correlación como si
// fueran tardíos, sesgando el benchmark hacia el caso más barato
// (gates que nunca cruzan).
//
// El patrón real de deltas entre eventos consecutivos se preserva
// DENTRO de cada vuelta; en el borde entre una vuelta y la siguiente
// (donde el delta real sería negativo: último evento → primer
// evento) se usa el delta PROMEDIO del escenario en su lugar — así
// el cursor de tiempo queda siempre estrictamente creciente a lo
// largo de todo b.N, sin alterar el resto de la cadencia real.
type monotonicEventStream struct {
	events   []event.Event
	avgDelta time.Duration
}

func newMonotonicEventStream(scenario datagen.Scenario) monotonicEventStream {
	events := make([]event.Event, len(scenario.Events))
	for i, le := range scenario.Events {
		events[i] = le.Payload()
	}
	if len(events) < 2 {
		return monotonicEventStream{events: events, avgDelta: time.Millisecond}
	}
	total := events[len(events)-1].Timestamp.Sub(events[0].Timestamp)
	avg := total / time.Duration(len(events)-1)
	if avg <= 0 {
		avg = time.Millisecond
	}
	return monotonicEventStream{events: events, avgDelta: avg}
}

// at devuelve el evento en la posición i (0-indexada, puede exceder
// len(events) las veces que haga falta), con su Timestamp rebasado
// respecto a cursor para mantenerse estrictamente creciente. cursor
// es mutado en cada llamada — el llamador debe invocar at con i
// creciente de a uno, empezando en 0, sobre el MISMO *time.Time.
func (m monotonicEventStream) at(i int, cursor *time.Time) event.Event {
	n := len(m.events)
	idx := i % n
	e := m.events[idx]

	if i == 0 {
		*cursor = e.Timestamp
		e.Timestamp = *cursor
		return e
	}

	prevIdx := (i - 1) % n
	var delta time.Duration
	if idx == 0 {
		// Borde de vuelta: el delta real (primer evento - último
		// evento) sería negativo. Se sustituye por el promedio del
		// escenario para no romper la monotonía ni distorsionar la
		// cadencia general.
		delta = m.avgDelta
	} else {
		delta = m.events[idx].Timestamp.Sub(m.events[prevIdx].Timestamp)
		if delta <= 0 {
			delta = time.Nanosecond // nunca cero ni negativo: estrictamente creciente
		}
	}
	*cursor = cursor.Add(delta)
	e.Timestamp = *cursor
	return e
}

// benchScenario genera, para seed y ratio dados, el escenario base
// del microbenchmark — la MISMA semilla de performance (901, nunca
// 101-103/201-203 de tuning/holdout, para no mezclar conceptos)
// usada también por cmd/loadtest.
const perfSeed = 901

func benchScenario(ratio float64) datagen.Scenario {
	return datagen.BuildScenario(datagen.DefaultScenarioConfig(perfSeed, ratio))
}

// newBenchDecider arma un *engine.BehavioralDecider real con la
// configuración final congelada (credential_stuffing CSw2, slow_scan
// S3, statistical_anomaly A3, Policy Challenge=0.50/Block=0.75 — ver
// internal/wiring, que es la MISMA construcción que sirve cmd/engine
// en producción) y el resolver determinista de ASN (nunca RIPEstat
// real: un microbenchmark no debe medir latencia de red).
func newBenchDecider(b *testing.B) *engine.BehavioralDecider {
	b.Helper()
	d, err := wiring.BuildDecider(0.50, 0.75, wiring.ASNProviderNone, 0, 0, nil)
	if err != nil {
		b.Fatalf("wiring.BuildDecider: %v", err)
	}
	return d
}

func runDecideBenchmark(b *testing.B, ratio float64) {
	scenario := benchScenario(ratio)
	stream := newMonotonicEventStream(scenario)
	d := newBenchDecider(b)
	ctx := context.Background()

	var cursor time.Time
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := stream.at(i, &cursor)
		d.Decide(ctx, e)
	}
}

// BenchmarkDecide_LegitOnly mide el costo de Decide() sobre tráfico
// puramente legítimo (perfil "normal", ratio 0%) — ningún gate de
// credential_stuffing/slow_scan cruza nunca; statistical_anomaly sí
// corre su cálculo completo en cada evento (Observe+Evaluate),
// aunque rara vez dispare.
func BenchmarkDecide_LegitOnly(b *testing.B) {
	runDecideBenchmark(b, 0)
}

// BenchmarkDecide_Mixed mide el costo de Decide() sobre el perfil
// "mixed" (ratio 10%) — mezcla de tráfico legítimo con campañas de
// credential_stuffing/slow_scan, algunas ya disparando a mitad del
// escenario.
func BenchmarkDecide_Mixed(b *testing.B) {
	runDecideBenchmark(b, 0.10)
}

// BenchmarkDecide_AttackHeavy mide el costo de Decide() sobre el
// perfil "attack-heavy" (ratio 30%) — la mayor proporción de eventos
// con gates ya disparando (RiskScore por encima de ScoreFloor,
// ContributingSignals pobladas, Explanation armada) de los tres
// perfiles.
func BenchmarkDecide_AttackHeavy(b *testing.B) {
	runDecideBenchmark(b, 0.30)
}
