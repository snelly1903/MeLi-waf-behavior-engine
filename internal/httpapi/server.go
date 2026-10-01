// Expone la API HTTP que recibe eventos y devuelve decisiones del Decider.
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

const maxEventBodyBytes = 64 * 1024

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type DecisionRecorder interface {
	RecordDecision(action, attackVector string)
}

type noopDecisionRecorder struct{}

func (noopDecisionRecorder) RecordDecision(string, string) {}

type Server struct {
	validator *event.Validator
	decider   engine.Decider
	recorder  DecisionRecorder
}

func NewServer(validator *event.Validator, decider engine.Decider, recorder DecisionRecorder) *Server {
	if recorder == nil {
		recorder = noopDecisionRecorder{}
	}
	return &Server{validator: validator, decider: decider, recorder: recorder}
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", s.handleEvents)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported on this endpoint")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxEventBodyBytes)
	defer r.Body.Close()

	var e event.Event
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	e = e.Normalize()
	if err := s.validator.Validate(e); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}

	d := s.decider.Decide(r.Context(), e)
	s.recorder.RecordDecision(string(d.Action), string(d.AttackVector))
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is supported on this endpoint")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: code, Message: message})
}
