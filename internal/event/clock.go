// Define la abstracción de reloj con implementaciones de sistema y manual.
package event

import (
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

type ManualClock struct {
	mu  sync.Mutex
	now time.Time
}

func NewManualClock(t time.Time) *ManualClock {
	return &ManualClock{now: t}
}

func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *ManualClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
