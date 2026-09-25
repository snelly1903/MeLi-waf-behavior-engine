package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// eventJSON arma el body JSON de un event.Event mínimo, con timestamp
// relativo a "ahora" (buildServer usa event.SystemClock{} de verdad,
// no un reloj simulado — mismo detalle ya visto en el test manual con
// curl de la tarea 1.1).
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
// integración de punta a punta pedida en la tarea 1.5: confirma que
// POST /v1/events, servido por el *httpapi.Server real que arma
// buildServer (el mismo que usa cmd/engine en producción), ya NO
// depende de engine.AllowAllDecider — un patrón real de escaneo lento
// termina en CHALLENGE o BLOCK, no en ALLOW.
func TestBuildServer_SlowScanPattern_ReturnsNonAllow(t *testing.T) {
	server, err := buildServer(0.5, 0.8)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
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
	if _, err := buildServer(0.8, 0.5); err == nil {
		t.Fatal("buildServer(0.8, 0.5) returned nil error, want an error (challenge >= block)")
	}
}
