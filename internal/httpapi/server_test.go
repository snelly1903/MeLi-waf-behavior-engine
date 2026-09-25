package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	clock := event.NewManualClock(time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC))
	validator := event.NewValidator(clock)
	return NewServer(validator, engine.AllowAllDecider{})
}

func postEvents(t *testing.T, srv *Server, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func decodeErrorResponse(t *testing.T, rec *httptest.ResponseRecorder) errorResponse {
	t.Helper()
	var resp errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding error response: %v (body=%q)", err, rec.Body.String())
	}
	return resp
}

// TestHandleEvents_ValidEvent_ReturnsAllowDecision cubre el caso
// "evento válido": la respuesta es 200, parsea como decision.Decision,
// pasa decision.Validate(), y RequestID/EntityID quedan derivados
// correctamente del evento enviado.
func TestHandleEvents_ValidEvent_ReturnsAllowDecision(t *testing.T) {
	srv := testServer(t)
	body := []byte(`{
		"request_id": "r-1",
		"timestamp": "2026-09-25T10:00:00Z",
		"client_ip": "203.0.113.7",
		"method": "GET",
		"path": "/",
		"status_code": 200
	}`)

	rec := postEvents(t, srv, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var d decision.Decision
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("decoding decision: %v (body=%q)", err, rec.Body.String())
	}
	if err := decision.Validate(d); err != nil {
		t.Errorf("decision.Validate(%+v) = %v, want nil", d, err)
	}
	if d.Action != decision.ActionAllow {
		t.Errorf("Action = %v, want ALLOW", d.Action)
	}
	if d.RequestID != "r-1" {
		t.Errorf("RequestID = %q, want %q", d.RequestID, "r-1")
	}
	if d.EntityID != "ip:203.0.113.7" {
		t.Errorf("EntityID = %q, want %q", d.EntityID, "ip:203.0.113.7")
	}
	if d.Explanation == "" {
		t.Error("Explanation is empty, want a deterministic message")
	}
}

// TestHandleEvents_MalformedJSON_Returns400 cubre el caso "JSON
// corrupto".
func TestHandleEvents_MalformedJSON_Returns400(t *testing.T) {
	srv := testServer(t)
	rec := postEvents(t, srv, []byte(`{"request_id": "r-1", "timestamp":`)) // JSON truncado

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	resp := decodeErrorResponse(t, rec)
	if resp.Error != "invalid_json" {
		t.Errorf("Error = %q, want %q", resp.Error, "invalid_json")
	}
}

// TestHandleEvents_InvalidEvent_Returns422 cubre el caso "evento
// inválido": JSON bien formado, pero el Validator lo rechaza (acá,
// por tener una IP privada — event.ErrPrivateClientIP).
func TestHandleEvents_InvalidEvent_Returns422(t *testing.T) {
	srv := testServer(t)
	body := []byte(`{
		"request_id": "r-1",
		"timestamp": "2026-09-25T10:00:00Z",
		"client_ip": "10.0.0.5",
		"method": "GET",
		"path": "/",
		"status_code": 200
	}`)

	rec := postEvents(t, srv, body)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	resp := decodeErrorResponse(t, rec)
	if resp.Error != "validation_failed" {
		t.Errorf("Error = %q, want %q", resp.Error, "validation_failed")
	}
	if !strings.Contains(resp.Message, "client_ip") {
		t.Errorf("Message = %q, want it to mention client_ip", resp.Message)
	}
}

// TestHandleEvents_WrongMethod_Returns405 cubre el caso "método HTTP
// incorrecto".
func TestHandleEvents_WrongMethod_Returns405(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusMethodNotAllowed, rec.Body.String())
	}
	if allow := rec.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("Allow header = %q, want %q", allow, http.MethodPost)
	}
	resp := decodeErrorResponse(t, rec)
	if resp.Error != "method_not_allowed" {
		t.Errorf("Error = %q, want %q", resp.Error, "method_not_allowed")
	}
}

// TestHandleHealthz_ReturnsOK cubre el caso "health check".
func TestHandleHealthz_ReturnsOK(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding healthz body: %v (body=%q)", err, rec.Body.String())
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %q, want %q", body["status"], "ok")
	}
}
