package baseline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

// LoadEvents lee un archivo events.jsonl — el formato que escribe
// datagen.WriteScenario (tarea 0.6): un event.Event por línea, sin
// ninguna etiqueta — y devuelve los eventos en el mismo orden en que
// aparecen en el archivo. LoadEvents no reordena nada: es
// responsabilidad de quien generó el archivo (datagen.WriteScenario ya
// lo garantiza) que las líneas vengan en orden cronológico, que es lo
// que Detect exige.
func LoadEvents(path string) ([]event.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: opening events file: %w", err)
	}
	defer f.Close()

	var events []event.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		var e event.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("baseline: events.jsonl line %d: %w", line, err)
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("baseline: reading events file: %w", err)
	}
	return events, nil
}

// WriteDecisions escribe decisions en path, un decision.Decision por
// línea — el mismo formato decisions.jsonl que ya consume cmd/eval
// (tarea 0.8). No agrega nada que Detect no haya puesto ya en cada
// Decision.
func WriteDecisions(path string, decisions []decision.Decision) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("baseline: creating decisions file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, d := range decisions {
		if err := enc.Encode(d); err != nil {
			return fmt.Errorf("baseline: writing decision %q: %w", d.RequestID, err)
		}
	}
	return w.Flush()
}
