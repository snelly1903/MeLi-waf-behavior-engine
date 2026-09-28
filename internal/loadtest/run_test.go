package loadtest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

func testEvents(n int) []event.Event {
	events := make([]event.Event, n)
	for i := 0; i < n; i++ {
		events[i] = event.Event{
			RequestID:  "seed-" + string(rune('a'+i%26)),
			ClientIP:   netip.MustParseAddr("203.0.113.1"),
			Method:     "GET",
			Path:       "/",
			StatusCode: 200,
			Timestamp:  time.Date(2020, 1, 1, 0, 0, i, 0, time.UTC), // se reescribe igual, valor irrelevante
		}
	}
	return events
}

// recordingServer arma un httptest.Server que decodifica cada
// request_id recibido y responde 200 — usado para confirmar, sin
// pasar por internal/wiring, que Run() efectivamente reparte los
// eventos por cursor y no por worker independiente.
func recordingServer(t *testing.T, seen *sync.Map, counter *int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		var e event.Event
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		atomic.AddInt64(counter, 1)
		n, _ := seen.LoadOrStore(e.RequestID, new(int64))
		atomic.AddInt64(n.(*int64), 1)
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
}

// TestRun_SharedCursor_DistributesEventsAcrossAllWorkers confirma el
// ajuste 2 pedido explícitamente: request n -> events[n%len(events)]
// por un cursor ATÓMICO COMPARTIDO entre todos los workers — nunca
// cada worker recorriendo el escenario desde el evento 0 por su
// cuenta (lo que duplicaría el mismo evento N veces en simultáneo al
// subir la concurrencia). Con 5 eventos distintos y concurrencia 4,
// cada uno de los 5 debería recibirse una cantidad de veces
// aproximadamente pareja (nunca "4 workers, 4 copias simultáneas del
// evento 0").
func TestRun_SharedCursor_DistributesEventsAcrossAllWorkers(t *testing.T) {
	var seen sync.Map
	var totalReceived int64
	server := recordingServer(t, &seen, &totalReceived)
	defer server.Close()

	events := testEvents(5)
	result := Run(context.Background(), RunConfig{
		BaseURL:     server.URL,
		Events:      events,
		Concurrency: 4,
		Warmup:      0,
		Measurement: 300 * time.Millisecond,
		Client:      server.Client(),
	})

	if result.Requests == 0 {
		t.Fatal("Requests = 0, want > 0")
	}

	distinctSeen := 0
	seen.Range(func(_, _ any) bool { distinctSeen++; return true })
	if distinctSeen != 5 {
		t.Errorf("distinctSeen = %d, want 5 (los 5 eventos del escenario tienen que aparecer, repartidos por el cursor compartido)", distinctSeen)
	}

	// Ningún evento individual debería concentrar una fracción
	// desproporcionada del total -- con reparto por cursor
	// compartido, la diferencia entre el más y el menos frecuente
	// tiene que ser chica (a lo sumo unas pocas unidades, nunca del
	// orden de "toda una tanda de un worker").
	var min, max int64 = -1, -1
	seen.Range(func(_, v any) bool {
		n := atomic.LoadInt64(v.(*int64))
		if min == -1 || n < min {
			min = n
		}
		if max == -1 || n > max {
			max = n
		}
		return true
	})
	if max-min > max/2+2 { // margen laxo: solo detecta un desbalance grosero
		t.Errorf("distribución desbalanceada entre eventos: min=%d max=%d, want repartido aproximadamente parejo", min, max)
	}
}

// TestRun_WarmupSamplesAreDiscarded confirma que, con Measurement=0,
// Run no registra NINGUNA muestra (todo lo enviado cae dentro de
// Warmup) — las requests SÍ se envían (el servidor las recibe), pero
// no se miden.
func TestRun_WarmupSamplesAreDiscarded(t *testing.T) {
	var seen sync.Map
	var totalReceived int64
	server := recordingServer(t, &seen, &totalReceived)
	defer server.Close()

	result := Run(context.Background(), RunConfig{
		BaseURL:     server.URL,
		Events:      testEvents(3),
		Concurrency: 2,
		Warmup:      150 * time.Millisecond,
		Measurement: 0,
		Client:      server.Client(),
	})

	if result.Requests != 0 {
		t.Errorf("Requests = %d, want 0 (todo el tráfico cayó en warmup, medición=0)", result.Requests)
	}
	if atomic.LoadInt64(&totalReceived) == 0 {
		t.Error("el servidor no recibió NINGÚN request durante el warmup -- se esperaba que el warmup sí generara tráfico real, solo que no se mida")
	}
}

// TestRun_RecordsLatencyAndErrors_OnNon200 confirma que un status
// distinto de 200 cuenta como error (Errors++) pero SIGUE
// contribuyendo a Latencies -- el tiempo de respuesta de un error
// también es información real del sistema, nunca se descarta.
func TestRun_RecordsLatencyAndErrors_OnNon200(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	result := Run(context.Background(), RunConfig{
		BaseURL:     server.URL,
		Events:      testEvents(2),
		Concurrency: 1,
		Warmup:      0,
		Measurement: 100 * time.Millisecond,
		Client:      server.Client(),
	})

	if result.Requests == 0 {
		t.Fatal("Requests = 0, want > 0")
	}
	if result.Errors != result.Requests {
		t.Errorf("Errors = %d, want %d (todos los requests recibieron 400)", result.Errors, result.Requests)
	}
	if len(result.Latencies) != result.Requests {
		t.Errorf("len(Latencies) = %d, want %d (la latencia de un error también se registra)", len(result.Latencies), result.Requests)
	}
	if rate := result.ErrorRate(); rate != 1.0 {
		t.Errorf("ErrorRate() = %v, want 1.0", rate)
	}
}

// TestNewClient_TransportTunedForHighConcurrency confirma la
// verificación pedida explícitamente (tarea 1.10): el *http.Client
// que arma el harness NUNCA usa http.DefaultTransport tal cual (cuyo
// MaxIdleConnsPerHost=2 de fábrica fuerza a reabrir conexión en casi
// cada request bajo concurrencia alta) — MaxIdleConns/
// MaxIdleConnsPerHost tienen que ser generosos respecto a la
// concurrencia pedida, y keep-alive tiene que seguir habilitado
// (DisableKeepAlives=false, el default de http.Transport).
func TestNewClient_TransportTunedForHighConcurrency(t *testing.T) {
	client := NewClient(100)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.DisableKeepAlives {
		t.Error("DisableKeepAlives = true, want false (keep-alive tiene que seguir habilitado)")
	}
	if transport.MaxIdleConnsPerHost < 100 {
		t.Errorf("MaxIdleConnsPerHost = %d, want >= 100 (concurrency pedida)", transport.MaxIdleConnsPerHost)
	}
	if transport.MaxIdleConns < transport.MaxIdleConnsPerHost {
		t.Errorf("MaxIdleConns = %d, want >= MaxIdleConnsPerHost = %d", transport.MaxIdleConns, transport.MaxIdleConnsPerHost)
	}
}

func TestNewClient_LowConcurrency_StillUsesGenerousDefault(t *testing.T) {
	client := NewClient(1)
	transport := client.Transport.(*http.Transport)
	if transport.MaxIdleConnsPerHost < DefaultMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want >= %d incluso con concurrencia baja (nunca depender de http.DefaultTransport)", transport.MaxIdleConnsPerHost, DefaultMaxIdleConnsPerHost)
	}
}

// TestRun_WarmupResponseArrivingDuringMeasurement_NeverRecorded es la
// verificación estructural pedida explícitamente (tarea 1.10): un
// request que ARRANCÓ durante warmup pero cuya respuesta llega bien
// entrada la fase de medición NUNCA se cuenta — no por una condición
// de tiempo que pudiera fallar en un caso límite, sino porque
// fireWorkers(record=false) de la fase de warmup nunca escribe en
// ningún resultado, estructuralmente. Se fuerza el escenario con un
// servidor que tarda más que todo el warmup en responder.
func TestRun_WarmupResponseArrivingDuringMeasurement_NeverRecorded(t *testing.T) {
	const slowResponseDelay = 200 * time.Millisecond
	var requestCount int64

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		time.Sleep(slowResponseDelay) // más lento que todo el warmup de abajo
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	result := Run(context.Background(), RunConfig{
		BaseURL:     server.URL,
		Events:      testEvents(1),
		Concurrency: 1,
		Warmup:      50 * time.Millisecond, // el request de warmup arranca acá...
		Measurement: 400 * time.Millisecond,
		Client:      NewClient(1),
	})

	total := atomic.LoadInt64(&requestCount)
	if total < 2 {
		t.Fatalf("el servidor recibió %d request(s), want >= 2 (setup de test inválido: hace falta al menos el de warmup y uno de medición)", total)
	}
	// El servidor vio "total" requests en total (warmup + medición),
	// pero Run() solo debería CONTAR los de la fase de medición -- el
	// de warmup, aunque su respuesta llegó bien entrada la ventana de
	// medición nominal, nunca se cuenta porque fireWorkers(record=
	// false) de la fase de warmup nunca escribe en ningún resultado.
	if int64(result.Requests) >= total {
		t.Errorf("Requests = %d, want estrictamente menor que %d (el servidor vio 1 request de warmup que el cliente nunca debería contar)", result.Requests, total)
	}
	if result.Requests == 0 {
		t.Error("Requests = 0, want > 0 (algún request de medición debería haberse contado)")
	}
}

// TestRun_FreshStateBetweenRepetitions_NoSharedCursor confirma que
// dos llamadas independientes a Run (simulando dos repeticiones)
// arrancan cada una su PROPIO cursor desde 0 -- nunca comparten
// estado entre repeticiones (tarea 1.10, ajuste 4: decider/servidor
// frescos por repetición implica también que el cursor de reparto de
// eventos empieza de nuevo).
func TestRun_FreshStateBetweenRepetitions_NoSharedCursor(t *testing.T) {
	var seen1, seen2 sync.Map
	var total1, total2 int64
	server1 := recordingServer(t, &seen1, &total1)
	defer server1.Close()
	server2 := recordingServer(t, &seen2, &total2)
	defer server2.Close()

	cfg := func(url string) RunConfig {
		return RunConfig{BaseURL: url, Events: testEvents(3), Concurrency: 2, Warmup: 0, Measurement: 100 * time.Millisecond, Client: http.DefaultClient}
	}
	Run(context.Background(), cfg(server1.URL))
	Run(context.Background(), cfg(server2.URL))

	// Ambas repeticiones deberían haber visto el primer evento del
	// escenario (RequestID del índice 0) -- si el cursor se
	// compartiera entre repeticiones, la segunda arrancaría "a mitad
	// de camino" y podría no verlo nunca.
	firstRequestID := testEvents(3)[0].RequestID
	if _, ok := seen1.Load(firstRequestID); !ok {
		t.Error("la 1ra repetición nunca vio el primer evento del escenario")
	}
	if _, ok := seen2.Load(firstRequestID); !ok {
		t.Error("la 2da repetición nunca vio el primer evento del escenario -- el cursor no debería compartirse entre repeticiones")
	}
}
