// Command datagen genera los datasets de prueba del challenge: tráfico
// legítimo mezclado con credential stuffing distribuido y escaneo
// lento, en las proporciones 0%, 10% o 30% de tráfico malicioso que
// exige el PDF, con su ground truth guardado aparte (ver
// docs/decisiones.md, tarea 0.6).
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
)

func main() {
	seed := flag.Uint64("seed", 42, "semilla determinista del generador")
	ratio := flag.Float64("ratio", 0, "porcentaje de tráfico malicioso objetivo: 0, 10 o 30")
	out := flag.String("out", "data", "carpeta base donde escribir el escenario")
	flag.Parse()

	if *ratio != 0 && *ratio != 10 && *ratio != 30 {
		log.Fatalf("ratio inválido: %v (debe ser 0, 10 o 30)", *ratio)
	}

	cfg := datagen.DefaultScenarioConfig(*seed, *ratio/100)
	scenario := datagen.BuildScenario(cfg)

	dir := fmt.Sprintf("%s/scenario-%d", *out, int(*ratio))
	if err := datagen.WriteScenario(dir, scenario); err != nil {
		log.Fatalf("no se pudo escribir el escenario: %v", err)
	}

	log.Printf(
		"escenario %d%% generado en %s: %d eventos (%d legítimos, %d credential_stuffing, %d slow_scan) — ratio real: %.2f%%",
		int(*ratio), dir, scenario.Stats.TotalEvents, scenario.Stats.LegitEvents,
		scenario.Stats.CredentialStuffingEvents, scenario.Stats.SlowScanEvents,
		scenario.Stats.AchievedMaliciousRatio*100,
	)
}
