// Package eval compara las decisiones de un motor (real o ficticio)
// contra el ground truth generado en internal/datagen
package eval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type LoadLabelsResult struct {
	Labels map[string]groundtruth.Label

	DuplicateIDs []string

	UnknownLabelIDs []string
}

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
