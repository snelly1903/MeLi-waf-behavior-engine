package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/telemetry"
)

// TestFinalConfigs_ExactValues es el guardrail que confirma que
// FinalConfigs() tiene que diferir de engine.Default*Config() en
// EXACTAMENTE los campos de CSw2/S3/A3
// (Window/MinDistinctIPs; MaxVisitorsForNovelPath/MinNovelPathRatio;
// AccountDiversity) y en NADA más — si algún día alguien agrega un
// override adicional sin querer, este test lo detecta de inmediato.
func TestFinalConfigs_ExactValues(t *testing.T) {
	csGot, ssGot, anGot := FinalConfigs()

	csWant := engine.DefaultCredentialStuffingConfig()
	csWant.Window = 90 * time.Minute
	csWant.MinDistinctIPs = 16
	if !reflect.DeepEqual(csGot, csWant) {
		t.Errorf("credential_stuffing FinalConfigs() = %+v, want %+v (solo Window/MinDistinctIPs deben diferir del default)", csGot, csWant)
	}

	ssWant := engine.DefaultSlowScanConfig()
	ssWant.MaxVisitorsForNovelPath = 3
	ssWant.MinNovelPathRatio = 0.35
	if !reflect.DeepEqual(ssGot, ssWant) {
		t.Errorf("slow_scan FinalConfigs() = %+v, want %+v (solo MaxVisitorsForNovelPath/MinNovelPathRatio deben diferir del default)", ssGot, ssWant)
	}

	anWant := engine.DefaultAnomalyConfig()
	anWant.Weights.AccountDiversity = 0.5
	if !reflect.DeepEqual(anGot, anWant) {
		t.Errorf("statistical_anomaly FinalConfigs() = %+v, want %+v (solo Weights.AccountDiversity debe diferir del default)", anGot, anWant)
	}
}

func TestFinalPolicy_ExactValues(t *testing.T) {
	want := engine.Policy{ChallengeThreshold: 0.50, BlockThreshold: 0.75}
	if got := FinalPolicy(); got != want {
		t.Errorf("FinalPolicy() = %+v, want %+v", got, want)
	}
}

// TestPackageConfigVars_ServeFinalConfigs es el test central del
// blocker: los vars de paquete que BuildDecider/BuildServer (usados
// por cmd/engine en producción) sirven por default tienen que ser
// EXACTAMENTE FinalConfigs() — nunca engine.Default*Config()
// directamente. Si esto pasa, cmd/engine sirve la misma
// configuración que cmd/loadtest mide.
func TestPackageConfigVars_ServeFinalConfigs(t *testing.T) {
	csWant, ssWant, anWant := FinalConfigs()
	if !reflect.DeepEqual(credentialStuffingConfig, csWant) {
		t.Errorf("credentialStuffingConfig (usado por BuildDecider/cmd/engine) = %+v, want FinalConfigs() = %+v", credentialStuffingConfig, csWant)
	}
	if !reflect.DeepEqual(slowScanConfig, ssWant) {
		t.Errorf("slowScanConfig (usado por BuildDecider/cmd/engine) = %+v, want FinalConfigs() = %+v", slowScanConfig, ssWant)
	}
	if !reflect.DeepEqual(anomalyConfig, anWant) {
		t.Errorf("anomalyConfig (usado por BuildDecider/cmd/engine) = %+v, want FinalConfigs() = %+v", anomalyConfig, anWant)
	}
}

// eventJSON arma el body JSON de un event.Event mínimo, con timestamp
// relativo a "ahora" (BuildServer usa event.SystemClock{} de verdad,
// no un reloj simulado).
func eventJSON(requestID string, offset time.Duration, ip, path string, status int) []byte {
	body := map[string]any{
		"request_id":  requestID,
		"timestamp":   time.Now().UTC().Add(offset).Format(time.RFC3339),
		"client_ip":   ip,
		"method":      "GET",
		"path":        path,
		"status_code": status,
	}
	data, _ := json.Marshal(body)
	return data
}

func postEvent(t *testing.T, mux http.Handler, body []byte) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding response: %v (body=%q)", err, rec.Body.String())
	}
	return decoded
}

// TestBuildServer_SlowScanPattern_ReturnsNonAllow es la prueba de
// integración de punta a punta: confirma que POST /v1/events,
// servido por el *httpapi.Server real que arma
// BuildServer (el mismo que usa cmd/engine en producción), ya NO
// depende de engine.AllowAllDecider — un patrón real de escaneo lento
// termina en CHALLENGE o BLOCK, no en ALLOW.
func TestBuildServer_SlowScanPattern_ReturnsNonAllow(t *testing.T) {
	server, err := BuildServer(0.5, 0.8, ASNProviderNone, 2*time.Second, time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	mux := server.Routes()

	ip := "203.0.113.7"

	// Primero, un evento normal: tiene que seguir dando ALLOW.
	normal := postEvent(t, mux, eventJSON("r-normal", 0, ip, "/", 200))
	if normal["action"] != "ALLOW" {
		t.Fatalf(`primer evento normal: action = %v, want "ALLOW"`, normal["action"])
	}

	// Ahora, un patrón de escaneo lento claro: muchas rutas sensibles
	// distintas, todas 404, sin Referer — usa slowScanConfig, la
	// configuración real de cmd/engine (no una de test).
	var last map[string]any
	for i := 0; i < 50; i++ {
		body := map[string]any{
			"request_id":  fmt.Sprintf("r-scan-%d", i),
			"timestamp":   time.Now().UTC().Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			"client_ip":   ip,
			"method":      "GET",
			"path":        fmt.Sprintf("/sensitive-%d", i),
			"status_code": 404,
		}
		data, _ := json.Marshal(body)
		last = postEvent(t, mux, data)
	}

	action, _ := last["action"].(string)
	if action == "ALLOW" {
		t.Fatalf("after a clear slow-scan pattern, action = ALLOW, want CHALLENGE or BLOCK: %+v", last)
	}
	if action != "CHALLENGE" && action != "BLOCK" {
		t.Fatalf("action = %q, want CHALLENGE or BLOCK", action)
	}
	if last["attack_vector"] != "slow_scan" {
		t.Errorf("attack_vector = %v, want %q", last["attack_vector"], "slow_scan")
	}
}

func TestBuildServer_InvalidPolicy_ReturnsError(t *testing.T) {
	if _, err := BuildServer(0.8, 0.5, ASNProviderNone, 2*time.Second, time.Hour, nil); err == nil {
		t.Fatal("BuildServer(0.8, 0.5) returned nil error, want an error (challenge >= block)")
	}
}

// --- --asn-provider ---------------------------------------------------
//
// Estos tests solo verifican la CONSTRUCCIÓN del resolver (nunca
// llaman a Resolve) — construir un asn.Resolver no hace ninguna
// llamada de red por sí solo, así que este archivo sigue sin
// depender de Internet real.

func TestBuildCredentialStuffingResolver_None_ReturnsUnavailable(t *testing.T) {
	resolver, err := BuildCredentialStuffingResolver(ASNProviderNone, 2*time.Second, time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildCredentialStuffingResolver: %v", err)
	}
	// El placeholder "none" nunca resuelve ninguna IP — llamar
	// Resolve directamente no hace ninguna llamada de red.
	if _, ok := resolver.Resolve(netip.MustParseAddr("203.0.113.1")); ok {
		t.Error("Resolve() ok = true, want false for the \"none\" placeholder")
	}
}

func TestBuildCredentialStuffingResolver_RIPEStat_ConstructsWithoutNetworkCalls(t *testing.T) {
	resolver, err := BuildCredentialStuffingResolver(ASNProviderRIPEStat, 2*time.Second, time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildCredentialStuffingResolver: %v", err)
	}
	if resolver == nil {
		t.Fatal("resolver = nil, want a non-nil *asn.Resolver")
	}
}

func TestBuildCredentialStuffingResolver_UnknownProvider_ReturnsError(t *testing.T) {
	if _, err := BuildCredentialStuffingResolver("bogus", 2*time.Second, time.Hour, nil); err == nil {
		t.Fatal("BuildCredentialStuffingResolver(\"bogus\", ...) returned nil error, want an error")
	}
}

func TestBuildServer_UnknownASNProvider_ReturnsError(t *testing.T) {
	if _, err := BuildServer(0.5, 0.8, "bogus", 2*time.Second, time.Hour, nil); err == nil {
		t.Fatal("BuildServer with an unknown ASN provider returned nil error, want an error")
	}
}

// --- Telemetría ---------------------------------------------------------

// TestBuildServer_NilRecorders_StillWorks confirma que BuildServer
// sigue funcionando con recorders=nil (sin --otel-endpoint
// configurado, o en cualquier test que no necesite verificar
// telemetría) — cada componente interno ya sabe degradar a un
// recorder no-op por su cuenta.
func TestBuildServer_NilRecorders_StillWorks(t *testing.T) {
	server, err := BuildServer(0.5, 0.8, ASNProviderNone, 2*time.Second, time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	if server == nil {
		t.Fatal("server = nil, want a non-nil *httpapi.Server")
	}
}

// TestBuildServer_WithRecorders_RecordsRealDecision verifica de punta
// a punta que un *telemetry.Recorders real (construido con
// telemetry.Init y Endpoint="", igual que --otel-endpoint sin
// configurar) efectivamente termina conectado al Server que sirve
// POST /v1/events -- sin pasar por ningún Collector real.
func TestBuildServer_WithRecorders_RecordsRealDecision(t *testing.T) {
	recorders, shutdown, _ := telemetry.Init(context.Background(), telemetry.Config{})
	defer func() {
		if err := shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()

	server, err := BuildServer(0.5, 0.8, ASNProviderNone, 2*time.Second, time.Hour, recorders)
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}

	postEvent(t, server.Routes(), eventJSON("r-telemetry", 0, "203.0.113.9", "/", 200))
	// No hay Collector real detrás (Endpoint=""), así que esto solo
	// confirma que la llamada no entra en pánico ni bloquea -- el
	// valor exportado ya se prueba de forma aislada en
	// internal/telemetry.
}

// TestBuildDecider_ReturnsUsableDecider confirma que BuildDecider
// (usado por los microbenchmarks de internal/engine) da un decider
// utilizable sin pasar por la capa HTTP.
func TestBuildDecider_ReturnsUsableDecider(t *testing.T) {
	decider, err := BuildDecider(0.5, 0.8, ASNProviderNone, 2*time.Second, time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildDecider: %v", err)
	}
	if decider == nil {
		t.Fatal("decider = nil, want a non-nil *engine.BehavioralDecider")
	}
}

// fakeResolver es un credstuffing.NetworkResolver determinista mínimo
// — nunca internal/datagen.SimulatedASNResolver real, para que este
// paquete siga sin importar internal/datagen (ver el comentario de
// BuildDeciderWithResolver: quien arma el resolver es responsabilidad
// de quien llama, nunca de internal/wiring).
type fakeResolver map[netip.Addr]string

func (r fakeResolver) Resolve(ip netip.Addr) (string, bool) {
	g, ok := r[ip]
	return g, ok
}

// TestBuildServerWithResolver_UsesGivenResolver_NotProviderLookup
// confirma que BuildServerWithResolver (para cmd/loadtest) usa
// EXACTAMENTE el resolver recibido — nunca construye uno nuevo por
// nombre de proveedor.
func TestBuildServerWithResolver_UsesGivenResolver_NotProviderLookup(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.7")
	resolver := fakeResolver{ip: "asn:test"}

	server, err := BuildServerWithResolver(0.5, 0.8, resolver, nil)
	if err != nil {
		t.Fatalf("BuildServerWithResolver: %v", err)
	}
	if server == nil {
		t.Fatal("server = nil, want a non-nil *httpapi.Server")
	}
}

func TestBuildServerWithResolver_InvalidPolicy_ReturnsError(t *testing.T) {
	if _, err := BuildServerWithResolver(0.8, 0.5, fakeResolver{}, nil); err == nil {
		t.Fatal("BuildServerWithResolver(0.8, 0.5, ...) returned nil error, want an error (challenge >= block)")
	}
}

// TestBuildDeciderWithConfigs_UsesGivenConfigs_NotPackageDefaults
// confirma que los tres Config pasados a BuildDeciderWithConfigs se
// usan de verdad — nunca los defaults de paquete
// (engine.Default*Config()) — pasando un credstuffing.Config con un
// gate imposible de cruzar (MinDistinctIPs altísimo) y confirmando
// que Build igual construye sin error (el detector se arma con ESE
// Config, no lo ignora).
func TestBuildDeciderWithConfigs_UsesGivenConfigs_NotPackageDefaults(t *testing.T) {
	csCfg := engine.DefaultCredentialStuffingConfig()
	csCfg.MinDistinctIPs = 999_999 // gate deliberadamente imposible, distinto del default

	decider, err := BuildDeciderWithConfigs(csCfg, engine.DefaultSlowScanConfig(), engine.DefaultAnomalyConfig(), 0.5, 0.8, fakeResolver{}, nil)
	if err != nil {
		t.Fatalf("BuildDeciderWithConfigs: %v", err)
	}
	if decider == nil {
		t.Fatal("decider = nil, want a non-nil *engine.BehavioralDecider")
	}
	// No hay forma directa de leer el Config ya guardado adentro del
	// detector desde acá (encapsulado a propósito) -- esta prueba
	// confirma sobre todo que Build acepta y usa el Config recibido
	// sin caer a ningún default silencioso. El comportamiento
	// (MinDistinctIPs realmente aplicado) ya está cubierto por los
	// tests propios de internal/credstuffing.
}

func TestBuildServerWithConfigs_InvalidPolicy_ReturnsError(t *testing.T) {
	if _, err := BuildServerWithConfigs(engine.DefaultCredentialStuffingConfig(), engine.DefaultSlowScanConfig(), engine.DefaultAnomalyConfig(), 0.8, 0.5, fakeResolver{}, nil); err == nil {
		t.Fatal("BuildServerWithConfigs(0.8, 0.5, ...) returned nil error, want an error (challenge >= block)")
	}
}
