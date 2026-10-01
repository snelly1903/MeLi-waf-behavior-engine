// Package datagen implementa el generador de tráfico de prueba: fabrica
// eventos HTTP (legítimos y de ataque) de forma determinista,
// reproducible a partir de una semilla, y siempre junto con su
// etiqueta de ground truth.
package datagen

import (
	"fmt"
	"math/rand/v2"
	"time"
)

type RNG struct {
	r *rand.Rand
}


func NewRNG(seed uint64) *RNG {
	return &RNG{r: rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15))}
}

func (g *RNG) IntRange(min, max int) int {
	if max <= min {
		return min
	}
	return min + g.r.IntN(max-min+1)
}

func (g *RNG) DurationRange(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(g.r.Int64N(int64(max-min)+1))
}

func (g *RNG) Bool(p float64) bool {
	if p <= 0 {
		return false
	}
	if p >= 1 {
		return true
	}
	return g.r.Float64() < p
}


func Pick[T any](g *RNG, items []T) T {
	if len(items) == 0 {
		panic("datagen: Pick called with an empty slice")
	}
	return items[g.r.IntN(len(items))]
}

func (g *RNG) ID(prefix string) string {
	return fmt.Sprintf("%s%016x", prefix, g.r.Uint64())
}


func (g *RNG) HexHash(nChars int) string {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, nChars)
	for i := range b {
		b[i] = hexDigits[g.r.IntN(16)]
	}
	return string(b)
}
