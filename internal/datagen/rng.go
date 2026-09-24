// Package datagen implementa el generador de tráfico de prueba: fabrica
// eventos HTTP (legítimos en esta tarea, de ataque en la tarea 0.5) de
// forma determinista, reproducible a partir de una semilla, y siempre
// junto con su etiqueta de ground truth.
package datagen

import (
	"fmt"
	"math/rand/v2"
	"time"
)

// RNG envuelve una fuente de aleatoriedad con semilla y agrega métodos
// de conveniencia reutilizados por todos los generadores de tráfico
// (los perfiles legítimos de esta tarea, y los atacantes de la tarea
// 0.5). La misma semilla produce siempre la misma secuencia de
// valores — es la base de la reproducibilidad de todo el dataset
// generado.
type RNG struct {
	r *rand.Rand
}

// NewRNG crea un RNG determinista a partir de seed. rand/v2.NewPCG pide
// dos números de 64 bits; derivamos el segundo a partir del primero con
// una constante fija, así quien use el generador solo necesita
// recordar un único número de semilla.
func NewRNG(seed uint64) *RNG {
	return &RNG{r: rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15))}
}

// IntRange devuelve un entero uniforme en [min, max], ambos extremos
// incluidos. Si max <= min, devuelve min.
func (g *RNG) IntRange(min, max int) int {
	if max <= min {
		return min
	}
	return min + g.r.IntN(max-min+1)
}

// DurationRange devuelve una duración uniforme entre min y max
// (incluidos). Si max <= min, devuelve min.
func (g *RNG) DurationRange(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(g.r.Int64N(int64(max-min)+1))
}

// Bool devuelve true con probabilidad p (0 a 1). p <= 0 siempre da
// false; p >= 1 siempre da true.
func (g *RNG) Bool(p float64) bool {
	if p <= 0 {
		return false
	}
	if p >= 1 {
		return true
	}
	return g.r.Float64() < p
}

// Pick devuelve un elemento aleatorio de items. Entra en pánico si
// items está vacío: un perfil configurado con una lista vacía de rutas
// es un error de programación, no un caso a manejar en tiempo de
// ejecución.
func Pick[T any](g *RNG, items []T) T {
	if len(items) == 0 {
		panic("datagen: Pick called with an empty slice")
	}
	return items[g.r.IntN(len(items))]
}

// ID devuelve un identificador con el prefijo dado y 16 caracteres
// hexadecimales derivados del RNG (64 bits) — suficiente para que la
// probabilidad de colisión sea despreciable incluso generando cientos
// de miles de eventos.
func (g *RNG) ID(prefix string) string {
	return fmt.Sprintf("%s%016x", prefix, g.r.Uint64())
}

// HexHash devuelve una cadena de nChars caracteres hexadecimales en
// minúsculas, derivados del RNG. Se usa para simular un
// login_user_hash con forma realista (ver event.Validator) sin
// necesitar una cuenta de verdad detrás.
func (g *RNG) HexHash(nChars int) string {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, nChars)
	for i := range b {
		b[i] = hexDigits[g.r.IntN(16)]
	}
	return string(b)
}
