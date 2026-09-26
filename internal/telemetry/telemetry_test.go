package telemetry

import (
	"context"
	"net"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// --- Init: fail-open --------------------------------------------------

// TestInit_EmptyEndpoint_IsNoopWithoutDialing confirma la
// configuración por defecto: sin Endpoint, Init nunca intenta
// conectar con nadie, y usedNoop queda en false (no es un fallback,
// es lo esperado).
func TestInit_EmptyEndpoint_IsNoopWithoutDialing(t *testing.T) {
	recorders, shutdown, usedNoop := Init(context.Background(), Config{})
	defer func() {
		if err := shutdown(context.Background()); err != nil {
			t.Errorf("shutdown() = %v, want nil", err)
		}
	}()

	if usedNoop {
		t.Error("usedNoop = true, want false when Endpoint is empty (this is the default, not a fallback)")
	}
	if recorders == nil || recorders.Provider == nil {
		t.Fatal("recorders/Provider = nil, want a usable no-op provider")
	}
	// Debe ser inocuo llamarlo, incluso sin ningún Collector real.
	recorders.Engine.RecordFinding("credential_stuffing")
	recorders.ASN.RecordCacheResult(true)
	recorders.HTTP.RecordDecision("ALLOW", "unknown")
}

// TestInit_CollectorUnreachable_FallsBackToNoop es el test central del
// ajuste 3 de la tarea 1.8: si --otel-endpoint apunta a un Collector
// que no está escuchando, Init debe caer a instrumentación no-op y
// devolver usedNoop=true, SIN devolver un error que le impida a
// cmd/engine arrancar -- y sin colgarse más allá de ConnectTimeout.
func TestInit_CollectorUnreachable_FallsBackToNoop(t *testing.T) {
	// Un puerto TCP libre, cerrado antes de intentar conectar: nadie
	// escucha ahí, así que la conexión gRPC falla rápido
	// (ECONNREFUSED), no por agotar todo el ConnectTimeout esperando
	// -- pero igual verificamos que el tiempo total quede acotado.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	endpoint := lis.Addr().String()
	if err := lis.Close(); err != nil {
		t.Fatalf("closing listener: %v", err)
	}

	connectTimeout := 500 * time.Millisecond
	start := time.Now()
	recorders, shutdown, usedNoop := Init(context.Background(), Config{
		Endpoint:       endpoint,
		Insecure:       true,
		ConnectTimeout: connectTimeout,
	})
	elapsed := time.Since(start)
	defer func() {
		if err := shutdown(context.Background()); err != nil {
			t.Errorf("shutdown() = %v, want nil", err)
		}
	}()

	if !usedNoop {
		t.Error("usedNoop = false, want true when the collector is unreachable at startup")
	}
	if elapsed > 2*connectTimeout {
		t.Errorf("Init took %v with an unreachable collector, want it bounded close to ConnectTimeout (%v)", elapsed, connectTimeout)
	}
	if recorders == nil || recorders.Provider == nil {
		t.Fatal("recorders/Provider = nil, want a usable no-op provider even on fallback")
	}
	// El motor tiene que poder seguir sirviendo tráfico y registrando
	// (sin efecto real) aunque el Collector esté caído.
	recorders.Engine.RecordFinding("slow_scan")
	recorders.ASN.RecordResolveResult("success")
	recorders.HTTP.RecordDecision("BLOCK", "credential_stuffing")
}

// --- Nombres y valores reales de los instrumentos ----------------------
//
// Estos tests NO pasan por Init/dial -- construyen su propio
// *sdkmetric.MeterProvider con un ManualReader (sin exportar nada por
// red), exactamente la forma soportada por el SDK de OpenTelemetry
// para testear instrumentación sin Collector/Prometheus/Internet (ver
// docs/decisiones.md, tarea 1.8, punto 13 del plan).

func collect(t *testing.T, reader *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	return rm
}

// findMetric busca, entre todas las métricas recolectadas, la que
// tiene exactamente name -- fallando el test si no la encuentra, para
// que un cambio accidental de nombre (por ejemplo, al renombrar
// waf.asn.resolve.duration a waf.asn.provider.duration) se note acá,
// no recién mirando Prometheus a mano.
func findMetric(t *testing.T, rm metricdata.ResourceMetrics, name string) metricdata.Metrics {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m
			}
		}
	}
	t.Fatalf("no se encontró la métrica %q entre las recolectadas", name)
	return metricdata.Metrics{}
}

func sumDataPoints(t *testing.T, m metricdata.Metrics) []metricdata.DataPoint[int64] {
	t.Helper()
	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("la métrica %q no es un Sum[int64] (es %T)", m.Name, m.Data)
	}
	return sum.DataPoints
}

func TestEngineRecorder_RecordFinding_ExportsExpectedNameAndAttribute(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	r := newEngineRecorder(provider.Meter("test"))

	r.RecordFinding("credential_stuffing")
	r.RecordFinding("credential_stuffing")
	r.RecordFinding("slow_scan")

	rm := collect(t, reader)
	points := sumDataPoints(t, findMetric(t, rm, "waf.detector.findings"))

	got := map[string]int64{}
	for _, p := range points {
		detector, _ := p.Attributes.Value("detector")
		got[detector.AsString()] = p.Value
	}
	if got["credential_stuffing"] != 2 {
		t.Errorf("credential_stuffing = %d, want 2", got["credential_stuffing"])
	}
	if got["slow_scan"] != 1 {
		t.Errorf("slow_scan = %d, want 1", got["slow_scan"])
	}
}

func TestHTTPRecorder_RecordDecision_ExportsExpectedNameAndAttributes(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	r := newHTTPRecorder(provider.Meter("test"))

	r.RecordDecision("ALLOW", "unknown")
	r.RecordDecision("BLOCK", "credential_stuffing")

	rm := collect(t, reader)
	points := sumDataPoints(t, findMetric(t, rm, "waf.decisions"))
	if len(points) != 2 {
		t.Fatalf("data points = %d, want 2 (una serie por combinación action/attack_vector)", len(points))
	}
	for _, p := range points {
		action, _ := p.Attributes.Value("action")
		vector, _ := p.Attributes.Value("attack_vector")
		if p.Value != 1 {
			t.Errorf("action=%s attack_vector=%s: value = %d, want 1", action.AsString(), vector.AsString(), p.Value)
		}
	}
}

func TestASNRecorder_RecordsAllThreeInstruments(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	r := newASNRecorder(provider.Meter("test"))

	r.RecordCacheResult(false)
	r.RecordCacheResult(true)
	r.RecordResolveResult("success")
	r.RecordResolveResult("capacity_timeout")
	r.RecordProviderDuration("success", 42*time.Millisecond)

	rm := collect(t, reader)

	cachePoints := sumDataPoints(t, findMetric(t, rm, "waf.asn.cache"))
	if len(cachePoints) != 2 {
		t.Errorf("waf.asn.cache data points = %d, want 2 (hit y miss)", len(cachePoints))
	}

	resolvePoints := sumDataPoints(t, findMetric(t, rm, "waf.asn.resolve"))
	if len(resolvePoints) != 2 {
		t.Errorf("waf.asn.resolve data points = %d, want 2 (success y capacity_timeout)", len(resolvePoints))
	}

	durationMetric := findMetric(t, rm, "waf.asn.provider.duration")
	hist, ok := durationMetric.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("waf.asn.provider.duration no es un Histogram[float64] (es %T)", durationMetric.Data)
	}
	if len(hist.DataPoints) != 1 {
		t.Fatalf("waf.asn.provider.duration data points = %d, want 1", len(hist.DataPoints))
	}
	if hist.DataPoints[0].Count != 1 {
		t.Errorf("count = %d, want 1", hist.DataPoints[0].Count)
	}
	result, _ := hist.DataPoints[0].Attributes.Value("result")
	if result.AsString() != "success" {
		t.Errorf(`result attribute = %q, want "success"`, result.AsString())
	}
}
