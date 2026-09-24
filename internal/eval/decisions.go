package eval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
)

// LoadDecisionsResult es lo que devuelve LoadDecisions: las decisiones
// utilizables, más cualquier problema encontrado en el archivo. Ningún
// problema se descarta en silencio ni convierte una decisión inválida
// en un ALLOW — quedan anotados acá para que EvaluateDecisions los
// incorpore a Issues (ver evaluate.go, tarea 0.8).
type LoadDecisionsResult struct {
	Decisions []decision.Decision

	// InvalidIDs son request_id con una decisión que se pudo leer (JSON
	// válido, con request_id) pero que no pasa decision.Validate() —
	// por ejemplo, un BLOCK sin Explanation ni ContributingSignals.
	InvalidIDs []string

	// CorruptLines son números de línea (1-indexado) que no se
	// pudieron interpretar en absoluto: JSON inválido, o JSON válido
	// pero sin un request_id utilizable para identificar la decisión
	// de otra forma.
	CorruptLines []int
}

// LoadDecisions lee un archivo decisions.jsonl — un decision.Decision
// por línea, serializado con el mismo contrato JSON de internal/decision
// (tarea 0.3) — y separa las decisiones utilizables de las que tienen
// algún problema.
//
// Una línea con problemas nunca interrumpe la carga de las demás: el
// objetivo es que un solo bug del motor (por ejemplo, olvidar la
// Explanation en un BLOCK) no tire abajo la evaluación completa, sino
// que quede visible como un problema de integridad puntual.
func LoadDecisions(path string) (LoadDecisionsResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return LoadDecisionsResult{}, fmt.Errorf("eval: opening decisions file: %w", err)
	}
	defer f.Close()

	var result LoadDecisionsResult

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var d decision.Decision
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			result.CorruptLines = append(result.CorruptLines, lineNum)
			continue
		}
		if strings.TrimSpace(d.RequestID) == "" {
			result.CorruptLines = append(result.CorruptLines, lineNum)
			continue
		}
		if err := decision.Validate(d); err != nil {
			result.InvalidIDs = append(result.InvalidIDs, d.RequestID)
			continue
		}
		result.Decisions = append(result.Decisions, d)
	}
	if err := scanner.Err(); err != nil {
		return LoadDecisionsResult{}, fmt.Errorf("eval: reading decisions file: %w", err)
	}

	return result, nil
}
