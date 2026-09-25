// Command engine levanta el servicio HTTP de ingestión y decisión
// (tarea 1.1): POST /v1/events recibe un event.Event, lo valida
// reutilizando internal/event, y devuelve un decision.Decision. Todavía
// no existe ningún detector conductual — el Decider configurado es
// engine.AllowAllDecider, que permite todo. Ese es exactamente el
// alcance de esta tarea: la tubería HTTP completa, sin ningún motor
// real todavía.
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/httpapi"
)

func main() {
	addr := flag.String("addr", ":8080", "dirección donde escuchar (host:puerto)")
	flag.Parse()

	validator := event.NewValidator(event.SystemClock{})
	decider := engine.AllowAllDecider{}
	server := httpapi.NewServer(validator, decider)

	log.Printf("engine: escuchando en %s (POST /v1/events, GET /healthz) — sin detectores todavía, decider=AllowAllDecider", *addr)
	if err := http.ListenAndServe(*addr, server.Routes()); err != nil {
		log.Fatalf("engine: %v", err)
	}
}
