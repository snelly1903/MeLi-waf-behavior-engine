// Package eval compara las decisiones de un motor (real o ficticio)
// contra el ground truth generado en internal/datagen, y calcula las
// métricas de efectividad del challenge. A diferencia de internal/event
// y de internal/decision, este paquete SÍ importa internal/groundtruth
// — es, junto con internal/datagen, el único lugar del proyecto donde
// eso es correcto: su trabajo es precisamente comparar el ground truth
// con lo que decidió el motor. La regla de separación de la tarea 0.2
// nunca fue "nadie puede ver el ground truth", fue "el motor nunca lo
// ve" — eval no es el motor.
package eval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// LoadLabelsResult es lo que devuelve LoadLabels: el mapa de etiquetas
// listo para usar, más cualquier problema encontrado en el archivo.
// Ningún problema se descarta en silencio — Evaluate los arrastra hasta
// el resultado final (ver evaluate.go).
type LoadLabelsResult struct {
	Labels map[string]groundtruth.Label

	// DuplicateIDs son request_id que aparecen más de una vez en el
	// archivo — se conserva la primera aparición en Labels, y el resto
	// queda anotado acá.
	DuplicateIDs []string

	// UnknownLabelIDs son request_id cuya etiqueta no es
	// legit/credential_stuffing/slow_scan — nunca entran en Labels.
	UnknownLabelIDs []string
}

// LoadLabels lee un archivo labels.jsonl — el formato que escribe
// WriteScenario en la tarea 0.6: una línea por evento, con request_id y
// label — y arma el mapa request_id -> Label.
//
// No confía ciegamente en el archivo: un request_id duplicado o una
// etiqueta que no sea una de las tres conocidas no interrumpen la
// carga, quedan anotados en el resultado (ver docs/decisiones.md,
// tarea 0.7).
func LoadLabels(path string) (LoadLabelsResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return LoadLabelsResult{}, err
	}
	defer f.Close()

	result := LoadLabelsResult{Labels: make(map[string]groundtruth.Label)}

	scanner := bufio.NewScanner(f)
	line := 0
	for scanner.Scan() {
		line++
		var rec struct {
			RequestID string            `json:"request_id"`
			Label     groundtruth.Label `json:"label"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			return LoadLabelsResult{}, fmt.Errorf("labels.jsonl line %d: %w", line, err)
		}

		if !rec.Label.Valid() {
			result.UnknownLabelIDs = append(result.UnknownLabelIDs, rec.RequestID)
			continue
		}
		if _, exists := result.Labels[rec.RequestID]; exists {
			result.DuplicateIDs = append(result.DuplicateIDs, rec.RequestID)
			continue
		}
		result.Labels[rec.RequestID] = rec.Label
	}
	if err := scanner.Err(); err != nil {
		return LoadLabelsResult{}, err
	}

	return result, nil
}
