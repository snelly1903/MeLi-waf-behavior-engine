// Verifica que el stream de eventos del benchmark mantenga timestamps estrictamente crecientes.
package engine_test

import (
	"testing"
	"time"
)

func TestMonotonicEventStream_StrictlyIncreasing_AcrossManyLaps(t *testing.T) {
	scenario := benchScenario(0.10)
	stream := newMonotonicEventStream(scenario)
	n := len(stream.events)
	if n < 2 {
		t.Fatalf("escenario de prueba demasiado chico (%d eventos), no puede probar el wrap", n)
	}

	var cursor time.Time
	var prev time.Time
	for i := 0; i < n*3+7; i++ {
		e := stream.at(i, &cursor)
		if i > 0 && !e.Timestamp.After(prev) {
			t.Fatalf("i=%d: Timestamp = %v, no es estrictamente posterior a %v (rompe monotonía)", i, e.Timestamp, prev)
		}
		prev = e.Timestamp
	}
}

func TestMonotonicEventStream_PreservesDeltaPattern_WithinOneLap(t *testing.T) {
	scenario := benchScenario(0.10)
	stream := newMonotonicEventStream(scenario)
	n := len(stream.events)
	if n < 3 {
		t.Fatalf("escenario de prueba demasiado chico (%d eventos)", n)
	}

	var cursor time.Time
	var got []time.Time
	for i := 0; i < n; i++ {
		got = append(got, stream.at(i, &cursor).Timestamp)
	}

	for i := 1; i < n; i++ {
		wantDelta := stream.events[i].Timestamp.Sub(stream.events[i-1].Timestamp)
		if wantDelta <= 0 {
			continue
		}
		gotDelta := got[i].Sub(got[i-1])
		if gotDelta != wantDelta {
			t.Errorf("i=%d: delta = %v, want %v (el patrón real de la primera vuelta debe preservarse exacto)", i, gotDelta, wantDelta)
		}
	}
}

func TestMonotonicEventStream_ReusesEventBodies_AcrossLaps(t *testing.T) {
	scenario := benchScenario(0.10)
	stream := newMonotonicEventStream(scenario)
	n := len(stream.events)

	var cursor time.Time
	var first, secondLap map[string]bool
	first = make(map[string]bool)
	secondLap = make(map[string]bool)
	for i := 0; i < n; i++ {
		first[stream.at(i, &cursor).RequestID] = true
	}
	for i := n; i < 2*n; i++ {
		secondLap[stream.at(i, &cursor).RequestID] = true
	}
	for id := range first {
		if !secondLap[id] {
			t.Errorf("RequestID %q de la primera vuelta no reaparece en la segunda — el contenido debería repetirse, solo el Timestamp cambia", id)
		}
	}
}
