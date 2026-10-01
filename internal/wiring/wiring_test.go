// Prueba la configuración final y la construcción del servidor y del resolver de ASN.
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

func TestBuildServer_SlowScanPattern_ReturnsNonAllow(t *testing.T) {
	server, err := BuildServer(0.5, 0.8, ASNProviderNone, 2*time.Second, time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	mux := server.Routes()

	ip := "203.0.113.7"

	normal := postEvent(t, mux, eventJSON("r-normal", 0, ip, "/", 200))
	if normal["action"] != "ALLOW" {
		t.Fatalf(`primer evento normal: action = %v, want "ALLOW"`, normal["action"])
	}

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

func TestBuildCredentialStuffingResolver_None_ReturnsUnavailable(t *testing.T) {
	resolver, err := BuildCredentialStuffingResolver(ASNProviderNone, 2*time.Second, time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildCredentialStuffingResolver: %v", err)
	}
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

func TestBuildServer_NilRecorders_StillWorks(t *testing.T) {
	server, err := BuildServer(0.5, 0.8, ASNProviderNone, 2*time.Second, time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	if server == nil {
		t.Fatal("server = nil, want a non-nil *httpapi.Server")
	}
}

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
}

func TestBuildDecider_ReturnsUsableDecider(t *testing.T) {
	decider, err := BuildDecider(0.5, 0.8, ASNProviderNone, 2*time.Second, time.Hour, nil)
	if err != nil {
		t.Fatalf("BuildDecider: %v", err)
	}
	if decider == nil {
		t.Fatal("decider = nil, want a non-nil *engine.BehavioralDecider")
	}
}

type fakeResolver map[netip.Addr]string

func (r fakeResolver) Resolve(ip netip.Addr) (string, bool) {
	g, ok := r[ip]
	return g, ok
}

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

func TestBuildDeciderWithConfigs_UsesGivenConfigs_NotPackageDefaults(t *testing.T) {
	csCfg := engine.DefaultCredentialStuffingConfig()
	csCfg.MinDistinctIPs = 999_999

	decider, err := BuildDeciderWithConfigs(csCfg, engine.DefaultSlowScanConfig(), engine.DefaultAnomalyConfig(), 0.5, 0.8, fakeResolver{}, nil)
	if err != nil {
		t.Fatalf("BuildDeciderWithConfigs: %v", err)
	}
	if decider == nil {
		t.Fatal("decider = nil, want a non-nil *engine.BehavioralDecider")
	}
}

func TestBuildServerWithConfigs_InvalidPolicy_ReturnsError(t *testing.T) {
	if _, err := BuildServerWithConfigs(engine.DefaultCredentialStuffingConfig(), engine.DefaultSlowScanConfig(), engine.DefaultAnomalyConfig(), 0.8, 0.5, fakeResolver{}, nil); err == nil {
		t.Fatal("BuildServerWithConfigs(0.8, 0.5, ...) returned nil error, want an error (challenge >= block)")
	}
}
