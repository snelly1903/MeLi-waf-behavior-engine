package asn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

func testConfig(baseURL string, clock event.Clock) Config {
	return Config{
		BaseURL:               baseURL,
		SourceApp:             "waf-behavior-engine-test",
		Timeout:               200 * time.Millisecond,
		MaxConcurrentRequests: 2,
		SuccessTTL:            time.Hour,
		FailureTTL:            time.Minute,
		Clock:                 clock,
	}
}

func newTestResolver(t *testing.T, baseURL string, clock event.Clock) *Resolver {
	t.Helper()
	r, err := NewResolver(testConfig(baseURL, clock))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

// --- Config.Validate --------------------------------------------------

func TestConfig_Validate_InvalidConfigurations(t *testing.T) {
	valid := testConfig("http://example.invalid", event.SystemClock{})
	tests := []struct {
		name   string
		modify func(c Config) Config
	}{
		{"empty base url", func(c Config) Config { c.BaseURL = ""; return c }},
		{"empty source app", func(c Config) Config { c.SourceApp = ""; return c }},
		{"zero timeout", func(c Config) Config { c.Timeout = 0; return c }},
		{"zero max concurrent", func(c Config) Config { c.MaxConcurrentRequests = 0; return c }},
		{"zero success ttl", func(c Config) Config { c.SuccessTTL = 0; return c }},
		{"zero failure ttl", func(c Config) Config { c.FailureTTL = 0; return c }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.modify(valid).Validate(); err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
		})
	}
}

func TestNewResolver_InvalidConfig_ReturnsError(t *testing.T) {
	cfg := testConfig("", event.SystemClock{})
	if _, err := NewResolver(cfg); err == nil {
		t.Fatal("NewResolver() error = nil, want an error")
	}
}

// --- Parseo exitoso -----------------------------------------------------

func networkInfoHandler(asns []string, status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := networkInfoResponse{Status: status}
		resp.Data.ASNs = asns
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func TestResolve_SingleASN_Succeeds(t *testing.T) {
	srv := httptest.NewServer(networkInfoHandler([]string{"15169"}, "ok"))
	defer srv.Close()

	r := newTestResolver(t, srv.URL, event.SystemClock{})
	group, ok := r.Resolve(netip.MustParseAddr("8.8.8.8"))

	if !ok {
		t.Fatal("Resolve() ok = false, want true")
	}
	if group != "asn:15169" {
		t.Errorf("group = %q, want %q", group, "asn:15169")
	}
}

func TestResolve_ASPrefix_IsStripped(t *testing.T) {
	srv := httptest.NewServer(networkInfoHandler([]string{"AS15169"}, "ok"))
	defer srv.Close()

	r := newTestResolver(t, srv.URL, event.SystemClock{})
	group, ok := r.Resolve(netip.MustParseAddr("8.8.8.8"))

	if !ok || group != "asn:15169" {
		t.Errorf("Resolve() = (%q, %v), want (%q, true)", group, ok, "asn:15169")
	}
}

// --- Política conservadora: 0 y >1 ASN ------------------------------------

func TestResolve_ZeroASNs_ReturnsUnresolved(t *testing.T) {
	srv := httptest.NewServer(networkInfoHandler([]string{}, "ok"))
	defer srv.Close()

	r := newTestResolver(t, srv.URL, event.SystemClock{})
	_, ok := r.Resolve(netip.MustParseAddr("203.0.113.1"))

	if ok {
		t.Error("Resolve() ok = true, want false (no ASN in the response)")
	}
}

// TestResolve_MultipleASNs_ReturnsUnresolved es el test pedido
// explícitamente: RIPEstat puede devolver más de un ASN (multi-homing)
// — este prototipo no elige uno arbitrariamente, trata la ambigüedad
// como no resoluble.
func TestResolve_MultipleASNs_ReturnsUnresolved(t *testing.T) {
	srv := httptest.NewServer(networkInfoHandler([]string{"15169", "6432"}, "ok"))
	defer srv.Close()

	r := newTestResolver(t, srv.URL, event.SystemClock{})
	group, ok := r.Resolve(netip.MustParseAddr("8.8.8.8"))

	if ok {
		t.Errorf("Resolve() = (%q, true), want ok=false for a multi-ASN response", group)
	}
}

// --- Errores del proveedor -------------------------------------------------

func TestResolve_MalformedJSON_ReturnsUnresolved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	r := newTestResolver(t, srv.URL, event.SystemClock{})
	_, ok := r.Resolve(netip.MustParseAddr("203.0.113.2"))
	if ok {
		t.Error("Resolve() ok = true, want false for malformed JSON")
	}
}

func TestResolve_NonOKStatus_ReturnsUnresolved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := newTestResolver(t, srv.URL, event.SystemClock{})
	_, ok := r.Resolve(netip.MustParseAddr("203.0.113.3"))
	if ok {
		t.Error("Resolve() ok = true, want false for a non-200 response")
	}
}

func TestResolve_RIPEStatusNotOK_ReturnsUnresolved(t *testing.T) {
	srv := httptest.NewServer(networkInfoHandler([]string{"15169"}, "error"))
	defer srv.Close()

	r := newTestResolver(t, srv.URL, event.SystemClock{})
	_, ok := r.Resolve(netip.MustParseAddr("203.0.113.4"))
	if ok {
		t.Error(`Resolve() ok = true, want false when status != "ok"`)
	}
}

// --- Timeout: acota TODO Resolve, incluida la espera de capacidad --------

func TestResolve_ProviderTooSlow_TimesOutAndReturnsUnresolved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // muy por encima del Timeout configurado
	}))
	defer srv.Close()

	r := newTestResolver(t, srv.URL, event.SystemClock{})

	start := time.Now()
	_, ok := r.Resolve(netip.MustParseAddr("203.0.113.5"))
	elapsed := time.Since(start)

	if ok {
		t.Error("Resolve() ok = true, want false when the provider is too slow")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Resolve() took %v, want it bounded close to the configured Timeout (200ms)", elapsed)
	}
}

// TestResolve_TimeoutConsumedWaitingForCapacity_NeverCallsProvider es el
// segundo ajuste pedido: si el plazo se agota esperando un cupo de
// concurrencia, Resolve devuelve ("", false) SIN llegar a llamar al
// proveedor — nunca una espera ilimitada antes del timeout.
//
// Ocupa el único cupo directamente sobre el campo interno r.sem (el
// test vive en el mismo paquete) en vez de con una segunda llamada de
// fondo a Resolve: así no hay ninguna carrera de tiempos entre el
// timeout de esa llamada de fondo y el de la que se está probando —
// el cupo queda ocupado de forma determinista durante todo el test.
func TestResolve_TimeoutConsumedWaitingForCapacity_NeverCallsProvider(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		fmt.Fprint(w, `{"status":"ok","data":{"asns":["15169"]}}`)
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL, event.SystemClock{})
	cfg.MaxConcurrentRequests = 1
	cfg.Timeout = 100 * time.Millisecond
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	r.sem <- struct{}{} // ocupa el único cupo, sin pasar por el proveedor
	defer func() { <-r.sem }()

	start := time.Now()
	_, ok := r.Resolve(netip.MustParseAddr("203.0.113.11"))
	elapsed := time.Since(start)

	if ok {
		t.Error("Resolve() ok = true, want false when capacity never freed up in time")
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("Resolve() took %v while waiting for capacity, want it bounded close to Timeout (100ms)", elapsed)
	}
	if callCount.Load() != 0 {
		t.Errorf("provider was called %d times, want exactly 0 (Resolve must never reach the HTTP call while capacity is exhausted)", callCount.Load())
	}
}

// --- Caché positivo y negativo, con TTL -----------------------------------

func TestResolve_CachesSuccessfulResult_AvoidsSecondCall(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		fmt.Fprint(w, `{"status":"ok","data":{"asns":["15169"]}}`)
	}))
	defer srv.Close()

	r := newTestResolver(t, srv.URL, event.SystemClock{})
	ip := netip.MustParseAddr("8.8.8.8")

	r.Resolve(ip)
	r.Resolve(ip)
	r.Resolve(ip)

	if got := callCount.Load(); got != 1 {
		t.Errorf("provider was called %d times, want exactly 1 (the rest must come from cache)", got)
	}
}

func TestResolve_SuccessTTL_ExpiresAndRequeries(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		fmt.Fprint(w, `{"status":"ok","data":{"asns":["15169"]}}`)
	}))
	defer srv.Close()

	clock := event.NewManualClock(time.Now())
	cfg := testConfig(srv.URL, clock)
	cfg.SuccessTTL = time.Minute
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	ip := netip.MustParseAddr("8.8.8.8")

	r.Resolve(ip)
	clock.Advance(30 * time.Second) // todavía dentro del TTL
	r.Resolve(ip)
	if got := callCount.Load(); got != 1 {
		t.Fatalf("provider was called %d times before the TTL elapsed, want 1", got)
	}

	clock.Advance(31 * time.Second) // ya pasó el TTL de 1 minuto
	r.Resolve(ip)
	if got := callCount.Load(); got != 2 {
		t.Errorf("provider was called %d times after the TTL elapsed, want 2", got)
	}
}

func TestResolve_FailureTTL_ShorterThanSuccessTTL_Requeries(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	clock := event.NewManualClock(time.Now())
	cfg := testConfig(srv.URL, clock)
	cfg.FailureTTL = 10 * time.Second
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	ip := netip.MustParseAddr("203.0.113.6")

	r.Resolve(ip)
	clock.Advance(5 * time.Second)
	r.Resolve(ip)
	if got := callCount.Load(); got != 1 {
		t.Fatalf("provider was called %d times before the negative TTL elapsed, want 1", got)
	}

	clock.Advance(6 * time.Second) // ya pasaron los 10s del caché negativo
	r.Resolve(ip)
	if got := callCount.Load(); got != 2 {
		t.Errorf("provider was called %d times after the negative TTL elapsed, want 2", got)
	}
}

// --- Sweep ------------------------------------------------------------------

func TestSweep_RemovesOnlyExpiredEntries(t *testing.T) {
	srv := httptest.NewServer(networkInfoHandler([]string{"15169"}, "ok"))
	defer srv.Close()

	clock := event.NewManualClock(time.Now())
	cfg := testConfig(srv.URL, clock)
	cfg.SuccessTTL = time.Minute
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	r.Resolve(netip.MustParseAddr("8.8.8.8"))
	clock.Advance(2 * time.Minute)
	r.Resolve(netip.MustParseAddr("8.8.4.4")) // entra ya con el reloj más nuevo

	removed := r.Sweep(clock.Now())
	if removed != 1 {
		t.Errorf("Sweep removed %d entries, want 1 (only the expired one)", removed)
	}
}

// --- Límite de concurrencia -------------------------------------------------

func TestResolve_ConcurrencyLimit_NeverExceedsMax(t *testing.T) {
	const maxConcurrent = 3
	var current, maxObserved atomic.Int32
	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := current.Add(1)
		for {
			old := maxObserved.Load()
			if n <= old || maxObserved.CompareAndSwap(old, n) {
				break
			}
		}
		<-release
		current.Add(-1)
		fmt.Fprint(w, `{"status":"ok","data":{"asns":["15169"]}}`)
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL, event.SystemClock{})
	cfg.MaxConcurrentRequests = maxConcurrent
	cfg.Timeout = 2 * time.Second
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{203, 0, 113, byte(20 + i)})
			r.Resolve(ip)
		}(i)
	}

	time.Sleep(200 * time.Millisecond) // deja que se acumulen las que puedan
	close(release)
	wg.Wait()

	if got := maxObserved.Load(); got > int32(maxConcurrent) {
		t.Errorf("observed %d concurrent requests to the provider, want at most %d", got, maxConcurrent)
	}
}

// --- Concurrencia general con -race ----------------------------------------

func TestResolve_ConcurrentCalls_NoRaces(t *testing.T) {
	srv := httptest.NewServer(networkInfoHandler([]string{"15169"}, "ok"))
	defer srv.Close()

	r := newTestResolver(t, srv.URL, event.SystemClock{})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + i%254)})
			r.Resolve(ip)
		}(i)
	}
	wg.Wait()
}
