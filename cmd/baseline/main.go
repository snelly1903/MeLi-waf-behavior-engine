// Command baseline genera decisions.jsonl para un escenario de datos
// (ver cmd/datagen), aplicando un rate limit tradicional por IP con
// ventana deslizante (internal/baseline, tarea 0.9). Es la línea base
// contra la que se compara el futuro motor conductual de la Fase 1 —
// no es, en sí mismo, ese motor.
package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/baseline"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
)

func main() {
	scenario := flag.String("scenario", "", "carpeta del escenario con events.jsonl (ver cmd/datagen)")
	mode := flag.String("mode", "all", `modo de conteo: "all" (todas las peticiones) o "auth" (solo endpoints de autenticación)`)
	maxRequests := flag.Int("max-requests", 100, "peticiones contadas permitidas por IP dentro de la ventana")
	windowStr := flag.String("window", "60s", "tamaño de la ventana deslizante (formato time.ParseDuration, ej. 60s, 5m)")
	out := flag.String("out", "", "ruta del decisions.jsonl a generar; por defecto incluye modo/umbral/ventana en el nombre para no pisar otras corridas (ver docs/decisiones.md, tarea 0.9)")
	flag.Parse()

	if *scenario == "" {
		log.Fatal("baseline: --scenario es obligatorio")
	}
	window, err := time.ParseDuration(*windowStr)
	if err != nil {
		log.Fatalf("baseline: --window inválida: %v", err)
	}

	cfg := baseline.Config{
		MaxRequests: *maxRequests,
		Window:      window,
		Mode:        baseline.CountMode(*mode),
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("baseline: configuración inválida: %v", err)
	}

	events, err := baseline.LoadEvents(filepath.Join(*scenario, "events.jsonl"))
	if err != nil {
		log.Fatalf("baseline: %v", err)
	}

	decisions, err := baseline.Detect(events, cfg)
	if err != nil {
		log.Fatalf("baseline: %v", err)
	}

	outPath := *out
	if outPath == "" {
		outPath = filepath.Join(*scenario, fmt.Sprintf("decisions-baseline-%s-max%d-win%s.jsonl", *mode, *maxRequests, window))
	}
	if err := baseline.WriteDecisions(outPath, decisions); err != nil {
		log.Fatalf("baseline: no se pudo escribir %s: %v", outPath, err)
	}

	blocked := 0
	for _, d := range decisions {
		if d.Action == decision.ActionBlock {
			blocked++
		}
	}
	log.Printf(
		"baseline: %d decisiones escritas en %s (%d BLOCK, modo=%s, max-requests=%d, window=%s)",
		len(decisions), outPath, blocked, *mode, *maxRequests, window,
	)
	log.Print("baseline: para evaluar esta corrida con cmd/eval, --out tiene que apuntar exactamente a <scenario>/decisions.jsonl (cmd/eval siempre busca ese nombre)")
}
