// Mide el rendimiento de Decide con escenarios legítimos, mixtos y de ataque.
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
		delta = m.avgDelta
	} else {
		delta = m.events[idx].Timestamp.Sub(m.events[prevIdx].Timestamp)
		if delta <= 0 {
			delta = time.Nanosecond
		}
	}
	*cursor = cursor.Add(delta)
	e.Timestamp = *cursor
	return e
}

const perfSeed = 901

func benchScenario(ratio float64) datagen.Scenario {
	return datagen.BuildScenario(datagen.DefaultScenarioConfig(perfSeed, ratio))
}

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

func BenchmarkDecide_LegitOnly(b *testing.B) {
	runDecideBenchmark(b, 0)
}

func BenchmarkDecide_Mixed(b *testing.B) {
	runDecideBenchmark(b, 0.10)
}

func BenchmarkDecide_AttackHeavy(b *testing.B) {
	runDecideBenchmark(b, 0.30)
}
