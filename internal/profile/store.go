// Package profile es el componente con estado (tarea 1.2) que le
// permite al futuro motor "recordar" el comportamiento reciente de una
// IP y, cuando exista, de una sesión, dentro de una ventana temporal
// configurable. Todavía no es un detector: solo acumula observaciones
// y expone métricas agregadas — ninguna acción (ALLOW/CHALLENGE/BLOCK)
// se decide acá.
//
// Todo el estado vive en memoria (map + slice, protegidos con
// sync.Mutex). No hay Redis, DynamoDB ni ninguna base externa — ver
// docs/decisiones.md, tarea 1.2, para las limitaciones que eso implica
// y cómo se acotan.
package profile

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

// ErrInvalidWindow se devuelve cuando NewStore recibe una ventana no
// positiva.
var ErrInvalidWindow = errors.New("profile: window must be greater than 0")

// observation es lo mínimo que se retiene de cada event.Event — nunca
// el Event completo, nunca su UserAgent, el contenido de su Referer ni
// los valores de sus QueryParams. login_user_hash ya llega hasheado
// desde la tarea 0.2 (nunca un username ni un email en claro), así que
// retenerlo acá no agrega ningún riesgo nuevo de privacidad.
type observation struct {
	timestamp     time.Time
	path          string
	statusCode    int
	hasReferer    bool
	loginUserHash string
	sessionID     string
}

// Metrics son las métricas agregadas de una clave (una IP o una
// sesión) dentro de su ventana. Es una copia propia de quien la pide —
// modificarla nunca afecta el estado interno del Store (ver aggregate).
type Metrics struct {
	// Total es la cantidad de observaciones retenidas.
	Total int

	// Status401Or403 es cuántas de esas observaciones respondieron con
	// 401 o 403 — la señal cruda de intentos de login fallidos.
	Status401Or403 int

	// Status404 es cuántas respondieron con 404 — la señal cruda de
	// escaneo/enumeración.
	Status404 int

	// PathCounts es ruta -> cantidad de veces vista. "Rutas distintas"
	// es len(PathCounts); no se guarda como campo aparte para no tener
	// dos fuentes de la misma información que se puedan desincronizar.
	PathCounts map[string]int

	// DistinctAccounts es la cantidad de login_user_hash distintos y no
	// vacíos vistos.
	DistinctAccounts int

	// WithReferer y WithoutReferer suman siempre Total.
	WithReferer    int
	WithoutReferer int

	// DistinctSessions es la cantidad de session_id distintos y no
	// vacíos vistos. En un snapshot por IP es la señal de "cuántas
	// sesiones distintas hay detrás de esta IP" (por ejemplo, un NAT de
	// oficina). En un snapshot por sesión siempre da 1 (o 0 si nunca se
	// observó nada): es la propia clave, no aporta información nueva
	// ahí, pero se calcula igual para no duplicar la función de
	// agregación con una rama especial.
	DistinctSessions int

	// WindowStart es el timestamp más viejo retenido; WindowEnd es el
	// watermark actual de la clave (el timestamp más reciente
	// observado, sin importar el orden de llegada — ver Store.Observe).
	// Ambos quedan en su valor cero si Total es 0.
	WindowStart time.Time
	WindowEnd   time.Time
}

// keyState es el estado retenido de una clave: su watermark (el
// timestamp más reciente observado para esa clave, que nunca retrocede
// — ver Store.Observe) y las observaciones todavía dentro de la
// ventana relativa a ese watermark.
type keyState struct {
	watermark time.Time
	queue     []observation
}

// keyedWindow es la ventana deslizante genérica, parametrizada por el
// tipo de clave (netip.Addr para IPs, string para sesiones) para no
// escribir dos veces el mismo algoritmo de recorte.
type keyedWindow[K comparable] struct {
	mu     sync.Mutex
	window time.Duration
	data   map[K]keyState
}

func newKeyedWindow[K comparable](window time.Duration) *keyedWindow[K] {
	return &keyedWindow[K]{window: window, data: make(map[K]keyState)}
}

// observe agrega obs al estado de key.
//
// No asume que los eventos llegan ordenados por timestamp — detrás de
// net/http, dos requests concurrentes pueden procesarse en un orden
// distinto al de sus Event.Timestamp. Por eso cada clave mantiene un
// watermark (el máximo timestamp visto hasta ahora para esa clave, que
// nunca retrocede) y la ventana se interpreta siempre respecto a ese
// watermark, no respecto al timestamp del evento que acaba de llegar:
//
//   - un evento atrasado pero todavía dentro de
//     [watermark-Window, watermark] SÍ cuenta;
//   - un evento anterior a ese corte NUNCA se agrega — ni siquiera
//     puede "revivir" observaciones que ya habían expirado, porque el
//     watermark tampoco retrocede para él;
//   - el watermark solo avanza, nunca retrocede.
//
// Como el orden de llegada ya no está garantizado, no se puede seguir
// asumiendo que la cola está ordenada y recortar solo por adelante en
// O(1) amortizado (el truco que sí usa internal/baseline, donde el
// llamador SÍ garantiza el orden). Acá cada Observe reconstruye la
// cola filtrando todo lo que quedó por debajo del corte — O(k), con k
// = observaciones retenidas para esa clave. Es una elección deliberada
// de simplicidad y corrección por sobre preservar O(1): para el
// volumen de este challenge, k es chico (acotado por cuánto tráfico
// generó esa entidad dentro de una sola ventana), y una estructura más
// compleja (por ejemplo, un árbol balanceado por timestamp) sería
// optimizar prematuramente algo que todavía no es un problema medido.
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

// snapshot devuelve una copia de las observaciones retenidas de key,
// junto con su watermark actual. Nunca devuelve el slice interno.
func (w *keyedWindow[K]) snapshot(key K) ([]observation, time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	state := w.data[key]
	out := make([]observation, len(state.queue))
	copy(out, state.queue)
	return out, state.watermark
}

// sweep elimina cualquier clave cuyo watermark tenga más de idleTTL de
// antigüedad respecto a now, y devuelve cuántas claves eliminó. now se
// recibe como parámetro (nunca time.Now() internamente) para que siga
// siendo determinista y testeable; quien lo invoque periódicamente con
// un reloj real queda fuera del alcance de esta tarea.
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

// Store mantiene los perfiles de comportamiento por IP y por sesión.
// Es seguro para uso concurrente.
type Store struct {
	ip      *keyedWindow[netip.Addr]
	session *keyedWindow[string]
}

// NewStore construye un Store con una única ventana de retención
// (compartida por los perfiles de IP y de sesión). Si más adelante
// hace falta más de un tamaño de ventana, se construyen varios Store
// independientes, cada uno observando los mismos eventos — mantener un
// solo Window por Store evita el riesgo de pedir, por error, una
// ventana de consulta más ancha que la retenida y obtener un resultado
// truncado en silencio.
func NewStore(window time.Duration) (*Store, error) {
	if window <= 0 {
		return nil, ErrInvalidWindow
	}
	return &Store{
		ip:      newKeyedWindow[netip.Addr](window),
		session: newKeyedWindow[string](window),
	}, nil
}

// Observe registra e en el perfil de su IP y, si e.SessionID no está
// vacío, también en el perfil de esa sesión.
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

// SnapshotIP devuelve las métricas agregadas del perfil de ip. Si
// nunca se observó nada para esa IP, devuelve un Metrics vacío
// (Total=0), no un error.
func (s *Store) SnapshotIP(ip netip.Addr) Metrics {
	obs, watermark := s.ip.snapshot(ip)
	return aggregate(obs, watermark)
}

// SnapshotSession devuelve las métricas agregadas del perfil de
// sessionID. Igual que SnapshotIP, una clave nunca observada devuelve
// un Metrics vacío.
func (s *Store) SnapshotSession(sessionID string) Metrics {
	obs, watermark := s.session.snapshot(sessionID)
	return aggregate(obs, watermark)
}

// Sweep elimina, tanto del índice por IP como del índice por sesión,
// cualquier clave cuyo watermark tenga más de idleTTL de antigüedad
// respecto a now, y devuelve cuántas claves eliminó en total. Sin
// llamar a Sweep periódicamente, el Store retiene una entrada por cada
// IP/sesión distinta vista alguna vez en la vida del proceso, aunque
// nunca vuelva a aparecer — ver docs/decisiones.md, tarea 1.2, para la
// limitación completa. Conectar esto a un scheduler real queda fuera
// del alcance de esta tarea.
func (s *Store) Sweep(now time.Time, idleTTL time.Duration) int {
	return s.ip.sweep(now, idleTTL) + s.session.sweep(now, idleTTL)
}

// aggregate calcula Metrics a partir de una copia ya aislada de
// observaciones (ver keyedWindow.snapshot) y el watermark de esa
// clave. Como obs ya es una copia, cada map que arma (PathCounts) es
// enteramente propio del Metrics devuelto.
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
