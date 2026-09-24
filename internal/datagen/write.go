package datagen

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// labelRecord es la forma de cada línea de labels.jsonl: el ground
// truth de un evento, identificado por su request_id — nunca el evento
// en sí. Ver docs/decisiones.md, tarea 0.6.
type labelRecord struct {
	RequestID string `json:"request_id"`
	Label     string `json:"label"`
}

// WriteScenario escribe un Scenario ya generado en dir, en tres
// archivos separados (ver docs/decisiones.md, tarea 0.6):
//
//   - events.jsonl:  una línea por evento, exactamente lo que recibiría
//     el motor (LabeledEvent.Payload(), sin ninguna etiqueta).
//   - labels.jsonl:  una línea por evento, con request_id y label — el
//     ground truth, en un archivo que el motor nunca lee.
//   - manifest.json: la configuración, la semilla y las estadísticas de
//     esta generación (Scenario.Stats), en JSON indentado.
//
// dir se crea si no existe. La separación en dos archivos (en vez de un
// único archivo con la etiqueta adentro) es la garantía estructural de
// que el motor WAF nunca puede recibir ni leer el ground truth: el
// código que arma el request hacia el motor solo tiene acceso a
// events.jsonl.
func WriteScenario(dir string, s Scenario) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	if err := writeJSONLPayloads(filepath.Join(dir, "events.jsonl"), s.Events); err != nil {
		return err
	}
	if err := writeJSONLLabels(filepath.Join(dir, "labels.jsonl"), s.Events); err != nil {
		return err
	}
	return writeManifest(filepath.Join(dir, "manifest.json"), s.Stats)
}

func writeJSONLPayloads(path string, events []groundtruth.LabeledEvent) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, le := range events {
		if err := enc.Encode(le.Payload()); err != nil {
			return err
		}
	}
	return w.Flush()
}

func writeJSONLLabels(path string, events []groundtruth.LabeledEvent) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, le := range events {
		rec := labelRecord{RequestID: le.Event.RequestID, Label: string(le.Label)}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return w.Flush()
}

func writeManifest(path string, stats ScenarioStats) error {
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
