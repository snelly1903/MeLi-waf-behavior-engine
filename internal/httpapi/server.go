// Package httpapi es la capa HTTP del servicio (tarea 1.1): recibe
// eventos, los valida reutilizando internal/event, y le pide una
// decisión a internal/engine. Deliberadamente no sabe nada de cómo se
// toma esa decisión — solo conoce la interfaz engine.Decider. Ningún
// detector conductual vive acá.
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

// maxEventBodyBytes limita el tamaño del body de POST /v1/events. Un
// evento es un objeto JSON chico; este límite evita que un body
// arbitrariamente grande consuma memoria sin control antes siquiera de
// llegar a la validación.
const maxEventBodyBytes = 64 * 1024

// errorResponse es el cuerpo JSON de cualquier respuesta de error de
// esta API — la misma forma para JSON malformado, eventos inválidos y
// método incorrecto, para que quien integre contra esta API tenga un
// único formato de error que parsear.
type errorResponse struct {
	// Error es un código corto y estable, pensado para lógica de
	// cliente (ej. "invalid_json").
	Error string `json:"error"`
	// Message es el detalle legible por humanos. Para
	// "validation_failed" es el texto ya combinado que devuelve
	// event.Validator.Validate (errors.Join) — no se desglosa campo por
	// campo, para mantener esto simple.
	Message string `json:"message"`
}

// Server arma los handlers HTTP a partir de las piezas ya existentes
// del proyecto: un event.Validator (tarea 0.2) y un engine.Decider
// (tarea 1.1).
type Server struct {
	validator *event.Validator
	decider   engine.Decider
}

// NewServer construye un Server. validator y decider son obligatorios.
func NewServer(validator *event.Validator, decider engine.Decider) *Server {
	return &Server{validator: validator, decider: decider}
}

// Routes arma el *http.ServeMux con los endpoints de esta tarea:
// POST /v1/events y GET /healthz.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", s.handleEvents)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

// handleEvents implementa POST /v1/events: decodifica el body como
// event.Event, lo normaliza y valida reutilizando el Validator de la
// tarea 0.2, y si es válido le pide una decisión al Decider
// configurado. Nunca construye ninguna lógica de detección acá.
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
	writeJSON(w, http.StatusOK, d)
}

// handleHealthz implementa GET /healthz.
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
