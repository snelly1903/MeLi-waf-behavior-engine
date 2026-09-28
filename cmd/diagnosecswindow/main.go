// Command diagnosecswindow es la verificación offline pedida antes
// de aprobar el sweep de Credential Stuffing (tarea 1.9): para las
// tres campañas reales de credential_stuffing al 10%, recalcula el
// máximo rolling de las cuatro señales del gate con Window=30m
// (producción), 60m y 90m — usando exactamente los mismos eventos,
// sin tocar ningún threshold ni el detector de producción. Ver
// docs/decisiones.md, tarea 1.9.
package main

import (
	"log"
	"os"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/datagen"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/tuning"
)

// c2Candidate replica exactamente C2 del sweep combinado (S3+A3) —
// ver cmd/sweepcombined/main.go. Los thresholds de credential_stuffing
// de C2 son los mismos que el baseline (C2 no los toca), pero se
// redefine acá para mantener el mismo candidato de referencia que
// cmd/diagnosecs.
func c2Candidate() tuning.Candidate {
	c := tuning.BaselineCandidate()
	c.Name = "C2-slowscan-account-weight"
	c.SlowScan.MaxVisitorsForNovelPath = 3
	c.SlowScan.MinNovelPathRatio = 0.35
	c.Anomaly.Weights.AccountDiversity = 0.5
	return c
}

func main() {
	seeds := []uint64{101, 102, 103}
	windows := []time.Duration{30 * time.Minute, 60 * time.Minute, 90 * time.Minute}

	candidate := c2Candidate()
	resolver := datagen.NewSimulatedASNResolver()

	var allRows []tuning.WindowSensitivityRow
	for _, seed := range seeds {
		scenario := datagen.BuildScenario(datagen.DefaultScenarioConfig(seed, 0.10))

		rows, err := tuning.AnalyzeWindowSensitivity(scenario, resolver, candidate.CredentialStuffing, windows)
		if err != nil {
			log.Fatalf("diagnosecswindow: AnalyzeWindowSensitivity seed=%d: %v", seed, err)
		}
		allRows = append(allRows, rows...)
		log.Printf("diagnosecswindow: seed=%d — %d fila(s)", seed, len(rows))
	}

	if err := os.MkdirAll("reports/tuning", 0o755); err != nil {
		log.Fatalf("diagnosecswindow: creando carpeta de salida: %v", err)
	}

	report := "# Sensibilidad de credential_stuffing a Window (tarea 1.9)\n\n" +
		"Campañas al 10%, seeds 101/102/103. Candidato de referencia: C2 (S3+A3) — los thresholds " +
		"de credential_stuffing son los del baseline, sin cambios, en las tres columnas de Window.\n\n" +
		tuning.RenderWindowSensitivity(allRows, candidate.CredentialStuffing)

	if err := os.WriteFile("reports/tuning/diagnose-cs-window.md", []byte(report), 0o644); err != nil {
		log.Fatalf("diagnosecswindow: %v", err)
	}
	log.Printf("diagnosecswindow: reporte escrito en reports/tuning/diagnose-cs-window.md (%d filas totales)", len(allRows))
}
