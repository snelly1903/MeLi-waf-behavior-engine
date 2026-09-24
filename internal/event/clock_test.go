package event

import (
	"testing"
	"time"
)

func TestManualClock(t *testing.T) {
	start := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	clock := NewManualClock(start)

	if got := clock.Now(); !got.Equal(start) {
		t.Fatalf("Now() = %v, want %v", got, start)
	}

	clock.Advance(90 * time.Second)
	want := start.Add(90 * time.Second)
	if got := clock.Now(); !got.Equal(want) {
		t.Fatalf("after Advance: Now() = %v, want %v", got, want)
	}

	clock.Set(start)
	if got := clock.Now(); !got.Equal(start) {
		t.Fatalf("after Set: Now() = %v, want %v", got, start)
	}
}
