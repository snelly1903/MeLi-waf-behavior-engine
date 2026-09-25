package profile

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

var testBase = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

func mustAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}

// ev arma un event.Event mínimo pero completo para los tests de este
// paquete. offset se suma a testBase; los demás campos tienen valores
// neutros que cada test sobrescribe cuando le importan.
func ev(ip netip.Addr, offset time.Duration) event.Event {
	return event.Event{
		RequestID:  "r",
		Timestamp:  testBase.Add(offset),
		ClientIP:   ip,
		Method:     "GET",
		Path:       "/",
		StatusCode: 200,
	}
}

func newTestStore(t *testing.T, window time.Duration) *Store {
	t.Helper()
	s, err := NewStore(window)
	if err != nil {
		t.Fatalf("NewStore(%s): %v", window, err)
	}
	return s
}

func TestNewStore_InvalidWindow_ReturnsError(t *testing.T) {
	if _, err := NewStore(0); err != ErrInvalidWindow {
		t.Errorf("NewStore(0) error = %v, want ErrInvalidWindow", err)
	}
	if _, err := NewStore(-time.Second); err != ErrInvalidWindow {
		t.Errorf("NewStore(-1s) error = %v, want ErrInvalidWindow", err)
	}
}

// TestObserve_ExpirationAndExactBorder cubre expiración normal (en
// orden) y el borde exacto de la ventana: con arribos en orden
// 10:00:00, 10:01:00, 10:03:00 y luego 10:06:00 (Window=5min), el
// primero (10:00:00) queda estrictamente antes del corte
// (10:06:00-5min=10:01:00) y se descarta; 10:01:00 está EXACTAMENTE en
// el corte y se conserva (intervalo cerrado).
func TestObserve_ExpirationAndExactBorder(t *testing.T) {
	s := newTestStore(t, 5*time.Minute)
	ip := mustAddr("203.0.113.1")

	s.Observe(ev(ip, 0))             // 10:00:00 — va a expirar
	s.Observe(ev(ip, 1*time.Minute)) // 10:01:00 — queda justo en el borde
	s.Observe(ev(ip, 3*time.Minute)) // 10:03:00
	s.Observe(ev(ip, 6*time.Minute)) // 10:06:00 — dispara el corte

	m := s.SnapshotIP(ip)
	if m.Total != 3 {
		t.Fatalf("Total = %d, want 3 (10:00:00 should have expired)", m.Total)
	}
	wantStart := testBase.Add(1 * time.Minute)
	if !m.WindowStart.Equal(wantStart) {
		t.Errorf("WindowStart = %v, want %v", m.WindowStart, wantStart)
	}
	wantEnd := testBase.Add(6 * time.Minute)
	if !m.WindowEnd.Equal(wantEnd) {
		t.Errorf("WindowEnd = %v, want %v", m.WindowEnd, wantEnd)
	}
}

// TestObserve_OutOfOrder_UsesWatermarkNotArrivalOrder es el caso
// explícito pedido: con Window=5min, llegan 10:06, luego 10:03, luego
// 09:59 (fuera de orden). El watermark queda en 10:06 (el máximo
// visto, nunca retrocede); el corte es 10:06-5min=10:01. 10:03 está
// dentro y cuenta; 09:59 está antes del corte y nunca se agrega, ni
// "revive" nada. Total esperado = 2.
func TestObserve_OutOfOrder_UsesWatermarkNotArrivalOrder(t *testing.T) {
	s := newTestStore(t, 5*time.Minute)
	ip := mustAddr("203.0.113.2")

	s.Observe(ev(ip, 6*time.Minute))  // 10:06 — llega primero, fija el watermark
	s.Observe(ev(ip, 3*time.Minute))  // 10:03 — llega atrasado, pero está en ventana
	s.Observe(ev(ip, -1*time.Minute)) // 09:59 — llega atrasado, ya fuera de ventana

	m := s.SnapshotIP(ip)
	if m.Total != 2 {
		t.Fatalf("Total = %d, want 2", m.Total)
	}
	wantWatermark := testBase.Add(6 * time.Minute)
	if !m.WindowEnd.Equal(wantWatermark) {
		t.Errorf("WindowEnd (watermark) = %v, want %v (a late event must never move it backward)", m.WindowEnd, wantWatermark)
	}
	wantStart := testBase.Add(3 * time.Minute)
	if !m.WindowStart.Equal(wantStart) {
		t.Errorf("WindowStart = %v, want %v (09:59 must not count)", m.WindowStart, wantStart)
	}
}

// TestObserve_OrderInvariance_SameEventsDifferentArrivalOrder procesa
// exactamente el mismo conjunto de cuatro timestamps
// (10:00, 10:01, 10:03, 10:06 — Window=5min) dos veces sobre dos IPs
// distintas: una vez en orden cronológico y otra vez en el orden
// 10:06, 10:00, 10:03, 10:01. El resultado final tiene que ser
// idéntico en los dos casos — Total=3 (10:00 expira, porque una vez
// que el watermark llega a 10:06 el corte es 10:01 y 10:00 queda
// estrictamente antes) y ventana efectiva WindowStart=10:01,
// WindowEnd=10:06 — sin importar en qué orden llegaron los eventos.
// Confirma, además, que el recorte inspecciona TODA la cola (no solo
// el frente, como si estuviera ordenada) y que WindowStart/WindowEnd
// se calculan por mínimo/máximo timestamp real, no por la posición del
// elemento en el slice.
func TestObserve_OrderInvariance_SameEventsDifferentArrivalOrder(t *testing.T) {
	offsets := map[string]time.Duration{
		"10:00": 0,
		"10:01": 1 * time.Minute,
		"10:03": 3 * time.Minute,
		"10:06": 6 * time.Minute,
	}
	chronological := []string{"10:00", "10:01", "10:03", "10:06"}
	shuffled := []string{"10:06", "10:00", "10:03", "10:01"}

	run := func(t *testing.T, ip netip.Addr, order []string) Metrics {
		t.Helper()
		s := newTestStore(t, 5*time.Minute)
		for _, label := range order {
			s.Observe(ev(ip, offsets[label]))
		}
		return s.SnapshotIP(ip)
	}

	inOrder := run(t, mustAddr("203.0.113.4"), chronological)
	outOfOrder := run(t, mustAddr("203.0.113.5"), shuffled)

	wantStart := testBase.Add(1 * time.Minute)
	wantEnd := testBase.Add(6 * time.Minute)

	for name, m := range map[string]Metrics{"chronological": inOrder, "shuffled": outOfOrder} {
		if m.Total != 3 {
			t.Errorf("%s: Total = %d, want 3 (10:00 must have expired once the watermark reached 10:06)", name, m.Total)
		}
		if !m.WindowStart.Equal(wantStart) {
			t.Errorf("%s: WindowStart = %v, want %v", name, m.WindowStart, wantStart)
		}
		if !m.WindowEnd.Equal(wantEnd) {
			t.Errorf("%s: WindowEnd = %v, want %v", name, m.WindowEnd, wantEnd)
		}
	}

	if inOrder.Total != outOfOrder.Total || !inOrder.WindowStart.Equal(outOfOrder.WindowStart) || !inOrder.WindowEnd.Equal(outOfOrder.WindowEnd) {
		t.Errorf("processing order changed the result: chronological=%+v shuffled=%+v", inOrder, outOfOrder)
	}
}

// TestObserve_LateArrival_NeverRevivesAlreadyExpiredData refuerza el
// mismo punto con una secuencia distinta: una vez que el watermark ya
// avanzó lo suficiente para expirar una observación vieja, un evento
// que llega tarde con un timestamp anterior al corte no puede
// "resucitarla" ni a sí mismo.
func TestObserve_LateArrival_NeverRevivesAlreadyExpiredData(t *testing.T) {
	s := newTestStore(t, 5*time.Minute)
	ip := mustAddr("203.0.113.3")

	s.Observe(ev(ip, 0))              // 10:00:00
	s.Observe(ev(ip, 10*time.Minute)) // 10:10:00 — corte pasa a 10:05:00, 10:00:00 expira
	s.Observe(ev(ip, 1*time.Minute))  // 10:01:00 — llega tarde, ya está antes del corte

	m := s.SnapshotIP(ip)
	if m.Total != 1 {
		t.Fatalf("Total = %d, want 1 (only 10:10:00 should remain)", m.Total)
	}
	wantEnd := testBase.Add(10 * time.Minute)
	if !m.WindowEnd.Equal(wantEnd) {
		t.Errorf("WindowEnd = %v, want %v", m.WindowEnd, wantEnd)
	}
}

func TestObserve_IndependentIPs(t *testing.T) {
	s := newTestStore(t, time.Minute)
	ipA := mustAddr("203.0.113.10")
	ipB := mustAddr("203.0.113.20")

	s.Observe(ev(ipA, 0))
	s.Observe(ev(ipA, 1*time.Second))
	s.Observe(ev(ipB, 2*time.Second))

	if got := s.SnapshotIP(ipA).Total; got != 2 {
		t.Errorf("ipA Total = %d, want 2", got)
	}
	if got := s.SnapshotIP(ipB).Total; got != 1 {
		t.Errorf("ipB Total = %d, want 1", got)
	}
}

func TestObserve_IndependentSessions(t *testing.T) {
	s := newTestStore(t, time.Minute)
	ip := mustAddr("203.0.113.30")

	e1 := ev(ip, 0)
	e1.SessionID = "s-1"
	e2 := ev(ip, 1*time.Second)
	e2.SessionID = "s-2"
	e3 := ev(ip, 2*time.Second)
	e3.SessionID = "s-1"

	s.Observe(e1)
	s.Observe(e2)
	s.Observe(e3)

	if got := s.SnapshotSession("s-1").Total; got != 2 {
		t.Errorf("s-1 Total = %d, want 2", got)
	}
	if got := s.SnapshotSession("s-2").Total; got != 1 {
		t.Errorf("s-2 Total = %d, want 1", got)
	}
	// El perfil de IP ve las tres, y cuenta 2 sesiones distintas detrás
	// de ella (el caso NAT).
	ipMetrics := s.SnapshotIP(ip)
	if ipMetrics.Total != 3 {
		t.Errorf("ip Total = %d, want 3", ipMetrics.Total)
	}
	if ipMetrics.DistinctSessions != 2 {
		t.Errorf("ip DistinctSessions = %d, want 2", ipMetrics.DistinctSessions)
	}
}

func TestObserve_EventWithoutSessionID_DoesNotCreateSessionEntry(t *testing.T) {
	s := newTestStore(t, time.Minute)
	ip := mustAddr("203.0.113.40")
	s.Observe(ev(ip, 0)) // SessionID vacío

	if got := s.SnapshotSession("").Total; got != 0 {
		t.Errorf(`SnapshotSession("").Total = %d, want 0`, got)
	}
}

// TestMetrics_HandComputed cubre 401/403, 404, cuentas distintas y
// referer presente/ausente, todos calculados a mano.
func TestMetrics_HandComputed(t *testing.T) {
	s := newTestStore(t, time.Minute)
	ip := mustAddr("203.0.113.50")

	e1 := ev(ip, 0)
	e1.StatusCode = 401
	e1.LoginUserHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	e1.Referer = "https://example.com"

	e2 := ev(ip, 1*time.Second)
	e2.StatusCode = 403
	e2.LoginUserHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	e3 := ev(ip, 2*time.Second)
	e3.StatusCode = 404
	e3.Path = "/admin"

	e4 := ev(ip, 3*time.Second)
	e4.StatusCode = 200
	e4.LoginUserHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // cuenta repetida

	for _, e := range []event.Event{e1, e2, e3, e4} {
		s.Observe(e)
	}

	m := s.SnapshotIP(ip)
	if m.Total != 4 {
		t.Fatalf("Total = %d, want 4", m.Total)
	}
	if m.Status401Or403 != 2 {
		t.Errorf("Status401Or403 = %d, want 2", m.Status401Or403)
	}
	if m.Status404 != 1 {
		t.Errorf("Status404 = %d, want 1", m.Status404)
	}
	if m.DistinctAccounts != 2 {
		t.Errorf("DistinctAccounts = %d, want 2", m.DistinctAccounts)
	}
	if m.WithReferer != 1 || m.WithoutReferer != 3 {
		t.Errorf("WithReferer=%d WithoutReferer=%d, want 1 and 3", m.WithReferer, m.WithoutReferer)
	}
	if len(m.PathCounts) != 2 { // "/" (x3) y "/admin" (x1)
		t.Errorf("len(PathCounts) = %d, want 2: %v", len(m.PathCounts), m.PathCounts)
	}
	if m.PathCounts["/"] != 3 || m.PathCounts["/admin"] != 1 {
		t.Errorf("PathCounts = %v, want {\"/\":3, \"/admin\":1}", m.PathCounts)
	}
}

// TestSnapshotMetrics_PathCountsIsOwnedCopy confirma que modificar el
// map devuelto en Metrics nunca afecta al estado interno del Store ni
// a un snapshot posterior.
func TestSnapshotMetrics_PathCountsIsOwnedCopy(t *testing.T) {
	s := newTestStore(t, time.Minute)
	ip := mustAddr("203.0.113.60")
	s.Observe(ev(ip, 0))

	first := s.SnapshotIP(ip)
	first.PathCounts["/tampered"] = 999
	first.Total = 999

	second := s.SnapshotIP(ip)
	if _, exists := second.PathCounts["/tampered"]; exists {
		t.Error("mutating a returned Metrics.PathCounts leaked into a later snapshot")
	}
	if second.Total != 1 {
		t.Errorf("second.Total = %d, want 1 (mutating the first snapshot must not affect the store)", second.Total)
	}
}

func TestSnapshot_NeverObservedKey_ReturnsEmptyMetrics(t *testing.T) {
	s := newTestStore(t, time.Minute)
	m := s.SnapshotIP(mustAddr("203.0.113.70"))
	if m.Total != 0 {
		t.Errorf("Total = %d, want 0", m.Total)
	}
	if len(m.PathCounts) != 0 {
		t.Errorf("PathCounts = %v, want empty", m.PathCounts)
	}
	if !m.WindowStart.IsZero() || !m.WindowEnd.IsZero() {
		t.Errorf("WindowStart/WindowEnd = %v/%v, want zero values", m.WindowStart, m.WindowEnd)
	}
}

// TestSweep_RemovesOnlyIdleKeys confirma que Sweep elimina una clave
// inactiva por más de idleTTL, y conserva una activa.
func TestSweep_RemovesOnlyIdleKeys(t *testing.T) {
	s := newTestStore(t, time.Minute)
	idleIP := mustAddr("203.0.113.80")
	activeIP := mustAddr("203.0.113.81")

	s.Observe(ev(idleIP, 0))                // watermark = 10:00:00
	s.Observe(ev(activeIP, 30*time.Minute)) // watermark = 10:30:00

	now := testBase.Add(40 * time.Minute)
	removed := s.Sweep(now, 20*time.Minute)

	if removed != 1 {
		t.Fatalf("Sweep removed %d keys, want 1", removed)
	}
	if got := s.SnapshotIP(idleIP).Total; got != 0 {
		t.Errorf("idleIP Total after sweep = %d, want 0 (should have been removed)", got)
	}
	if got := s.SnapshotIP(activeIP).Total; got != 1 {
		t.Errorf("activeIP Total after sweep = %d, want 1 (should have survived)", got)
	}
}

// TestObserve_ConcurrentWrites_SameIP corre muchas goroutines
// observando la misma IP en paralelo, con timestamps fijos y
// deterministas (nunca time.Now()), y confirma con go test -race que
// no hay condiciones de carrera y que el conteo final es exacto — la
// prueba no depende de en qué orden intercalan las goroutines, solo
// del resultado final.
func TestObserve_ConcurrentWrites_SameIP(t *testing.T) {
	const n = 200
	s := newTestStore(t, time.Hour) // ventana ancha: todo cabe, ningún evento expira
	ip := mustAddr("203.0.113.90")

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			s.Observe(ev(ip, time.Duration(i)*time.Millisecond))
		}(i)
	}
	wg.Wait()

	if got := s.SnapshotIP(ip).Total; got != n {
		t.Errorf("Total = %d, want %d", got, n)
	}
}

// TestObserve_ConcurrentWrites_MultipleIPsAndSessions ejercita el
// mismo escenario con varias claves distintas en paralelo (IP y
// sesión), para que -race también cubra el mutex del índice de
// sesiones y no solo el de IPs.
func TestObserve_ConcurrentWrites_MultipleIPsAndSessions(t *testing.T) {
	const ips = 10
	const perIP = 50
	s := newTestStore(t, time.Hour)

	addrs := make([]netip.Addr, ips)
	for i := range addrs {
		addrs[i] = netip.AddrFrom4([4]byte{203, 0, 113, byte(100 + i)})
	}

	var wg sync.WaitGroup
	wg.Add(ips * perIP)
	for i, addr := range addrs {
		for j := 0; j < perIP; j++ {
			go func(addr netip.Addr, idx int) {
				defer wg.Done()
				e := ev(addr, time.Duration(idx)*time.Millisecond)
				e.SessionID = "s"
				s.Observe(e)
			}(addr, i*perIP+j)
		}
	}
	wg.Wait()

	for _, addr := range addrs {
		if got := s.SnapshotIP(addr).Total; got != perIP {
			t.Errorf("IP %s Total = %d, want %d", addr, got, perIP)
		}
	}
	if got := s.SnapshotSession("s").Total; got != ips*perIP {
		t.Errorf(`session "s" Total = %d, want %d`, got, ips*perIP)
	}
}
