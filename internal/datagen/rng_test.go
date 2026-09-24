package datagen

import (
	"testing"
	"time"
)

func TestRNG_Reproducible(t *testing.T) {
	a := NewRNG(42)
	b := NewRNG(42)

	for i := 0; i < 50; i++ {
		if got, want := a.IntRange(0, 1000), b.IntRange(0, 1000); got != want {
			t.Fatalf("IntRange diverged at draw %d: %d != %d", i, got, want)
		}
		if got, want := a.DurationRange(time.Second, time.Minute), b.DurationRange(time.Second, time.Minute); got != want {
			t.Fatalf("DurationRange diverged at draw %d: %v != %v", i, got, want)
		}
		if got, want := a.Bool(0.5), b.Bool(0.5); got != want {
			t.Fatalf("Bool diverged at draw %d: %v != %v", i, got, want)
		}
		if got, want := a.ID("r-"), b.ID("r-"); got != want {
			t.Fatalf("ID diverged at draw %d: %q != %q", i, got, want)
		}
		if got, want := a.HexHash(64), b.HexHash(64); got != want {
			t.Fatalf("HexHash diverged at draw %d: %q != %q", i, got, want)
		}
	}
}

func TestRNG_DifferentSeedsDiverge(t *testing.T) {
	a := NewRNG(1)
	b := NewRNG(2)

	same := true
	for i := 0; i < 20; i++ {
		if a.IntRange(0, 1_000_000) != b.IntRange(0, 1_000_000) {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two different seeds produced the same sequence of 20 draws — seeding is not actually taking effect")
	}
}

func TestRNG_IntRange_Bounds(t *testing.T) {
	g := NewRNG(7)
	for i := 0; i < 500; i++ {
		v := g.IntRange(5, 9)
		if v < 5 || v > 9 {
			t.Fatalf("IntRange(5, 9) = %d, out of bounds", v)
		}
	}
	if got := g.IntRange(5, 5); got != 5 {
		t.Errorf("IntRange(5, 5) = %d, want 5", got)
	}
	if got := g.IntRange(9, 5); got != 9 {
		t.Errorf("IntRange(9, 5) = %d, want 9 (min returned when max <= min)", got)
	}
}

func TestRNG_DurationRange_Bounds(t *testing.T) {
	g := NewRNG(7)
	min, max := 2*time.Second, 5*time.Second
	for i := 0; i < 500; i++ {
		v := g.DurationRange(min, max)
		if v < min || v > max {
			t.Fatalf("DurationRange(%v, %v) = %v, out of bounds", min, max, v)
		}
	}
}

func TestRNG_Bool_Extremes(t *testing.T) {
	g := NewRNG(7)
	for i := 0; i < 50; i++ {
		if g.Bool(0) {
			t.Fatal("Bool(0) returned true")
		}
		if !g.Bool(1) {
			t.Fatal("Bool(1) returned false")
		}
	}
}

func TestPick_PanicsOnEmpty(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Pick with an empty slice did not panic")
		}
	}()
	g := NewRNG(1)
	Pick(g, []string{})
}

func TestRNG_HexHash_OnlyHexDigits(t *testing.T) {
	g := NewRNG(3)
	h := g.HexHash(64)
	if len(h) != 64 {
		t.Fatalf("HexHash(64) has length %d, want 64", len(h))
	}
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("HexHash(64) contains non-hex character %q: %s", c, h)
		}
	}
}
