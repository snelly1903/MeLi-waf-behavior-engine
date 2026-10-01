// Escribe un escenario a disco como eventos, etiquetas y manifiesto.
package datagen

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type labelRecord struct {
	RequestID string `json:"request_id"`
	Label     string `json:"label"`
}

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
