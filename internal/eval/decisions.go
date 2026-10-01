// Carga las decisiones de un motor desde JSONL, registrando las líneas inválidas.
package eval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
)

type LoadDecisionsResult struct {
	Decisions []decision.Decision

	InvalidIDs []string

	CorruptLines []int
}

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
