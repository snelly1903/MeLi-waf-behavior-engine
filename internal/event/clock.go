package event

import (
	"sync"
	"time"
)

// Clock abstrae el "ahora" para que la validación (y, más adelante, la
// agregación por ventanas) nunca llame directamente a time.Now(). El
// código de producción usa SystemClock; los tests y el reproductor
// acelerado del generador de tráfico usan ManualClock, así una regla
// como "rechazar timestamps de más de 5 minutos de antigüedad" se puede
// probar sin esperar 5 minutos de verdad.
type Clock interface {
	Now() time.Time
}

// SystemClock informa la hora real del reloj del sistema, en UTC.
type SystemClock struct{}

// Now devuelve la hora actual en UTC.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// ManualClock es un Clock cuyo valor se fija a mano. Es seguro para uso
// concurrente, así que la misma instancia se puede compartir entre las
// goroutines de un test o entre el escritor y el lector del generador de
// tráfico.
type ManualClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewManualClock devuelve un ManualClock inicializado en t.
func NewManualClock(t time.Time) *ManualClock {
	return &ManualClock{now: t}
}

// Now devuelve el valor actual del reloj.
func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Set mueve el reloj a t.
func (c *ManualClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// Advance mueve el reloj hacia adelante en d (d puede ser negativo).
func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
