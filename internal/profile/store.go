// Mantiene en memoria perfiles de comportamiento por IP y sesión dentro de una ventana temporal.
package profile

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

var ErrInvalidWindow = errors.New("profile: window must be greater than 0")

type observation struct {
	timestamp     time.Time
	path          string
	statusCode    int
	hasReferer    bool
	loginUserHash string
	sessionID     string
}

type Metrics struct {
	Total int

	Status401Or403 int

	Status404 int

	PathCounts map[string]int

	DistinctAccounts int

	WithReferer    int
	WithoutReferer int

	DistinctSessions int

	WindowStart time.Time
	WindowEnd   time.Time
}

type keyState struct {
	watermark time.Time
	queue     []observation
}

type keyedWindow[K comparable] struct {
	mu     sync.Mutex
	window time.Duration
	data   map[K]keyState
}

func newKeyedWindow[K comparable](window time.Duration) *keyedWindow[K] {
	return &keyedWindow[K]{window: window, data: make(map[K]keyState)}
}

func (w *keyedWindow[K]) observe(key K, obs observation) {
	w.mu.Lock()
	defer w.mu.Unlock()

	state := w.data[key]
	if obs.timestamp.After(state.watermark) {
		state.watermark = obs.timestamp
	}
	cutoff := state.watermark.Add(-w.window)

	kept := make([]observation, 0, len(state.queue)+1)
	for _, o := range state.queue {
		if !o.timestamp.Before(cutoff) {
			kept = append(kept, o)
		}
	}
	if !obs.timestamp.Before(cutoff) {
		kept = append(kept, obs)
	}
	state.queue = kept

	w.data[key] = state
}

func (w *keyedWindow[K]) snapshot(key K) ([]observation, time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	state := w.data[key]
	out := make([]observation, len(state.queue))
	copy(out, state.queue)
	return out, state.watermark
}

func (w *keyedWindow[K]) sweep(now time.Time, idleTTL time.Duration) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	removed := 0
	for key, state := range w.data {
		if now.Sub(state.watermark) > idleTTL {
			delete(w.data, key)
			removed++
		}
	}
	return removed
}

type Store struct {
	ip      *keyedWindow[netip.Addr]
	session *keyedWindow[string]
}

func NewStore(window time.Duration) (*Store, error) {
	if window <= 0 {
		return nil, ErrInvalidWindow
	}
	return &Store{
		ip:      newKeyedWindow[netip.Addr](window),
		session: newKeyedWindow[string](window),
	}, nil
}

func (s *Store) Observe(e event.Event) {
	obs := observation{
		timestamp:     e.Timestamp,
		path:          e.Path,
		statusCode:    e.StatusCode,
		hasReferer:    e.Referer != "",
		loginUserHash: e.LoginUserHash,
		sessionID:     e.SessionID,
	}
	s.ip.observe(e.ClientIP, obs)
	if e.SessionID != "" {
		s.session.observe(e.SessionID, obs)
	}
}

func (s *Store) SnapshotIP(ip netip.Addr) Metrics {
	obs, watermark := s.ip.snapshot(ip)
	return aggregate(obs, watermark)
}

func (s *Store) SnapshotSession(sessionID string) Metrics {
	obs, watermark := s.session.snapshot(sessionID)
	return aggregate(obs, watermark)
}

func (s *Store) Sweep(now time.Time, idleTTL time.Duration) int {
	return s.ip.sweep(now, idleTTL) + s.session.sweep(now, idleTTL)
}

func aggregate(obs []observation, watermark time.Time) Metrics {
	m := Metrics{PathCounts: make(map[string]int)}
	if len(obs) == 0 {
		return m
	}

	accounts := make(map[string]struct{})
	sessions := make(map[string]struct{})
	windowStart := obs[0].timestamp

	for _, o := range obs {
		m.Total++
		if o.statusCode == 401 || o.statusCode == 403 {
			m.Status401Or403++
		}
		if o.statusCode == 404 {
			m.Status404++
		}
		m.PathCounts[o.path]++
		if o.hasReferer {
			m.WithReferer++
		} else {
			m.WithoutReferer++
		}
		if o.loginUserHash != "" {
			accounts[o.loginUserHash] = struct{}{}
		}
		if o.sessionID != "" {
			sessions[o.sessionID] = struct{}{}
		}
		if o.timestamp.Before(windowStart) {
			windowStart = o.timestamp
		}
	}

	m.DistinctAccounts = len(accounts)
	m.DistinctSessions = len(sessions)
	m.WindowStart = windowStart
	m.WindowEnd = watermark
	return m
}
