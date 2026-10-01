// Define el contrato de decisión que devuelve el motor por cada evento y su validación.
package decision

import (
	"errors"
	"math"
	"strings"
	"time"
)

type Action string

const (
	ActionAllow     Action = "ALLOW"
	ActionChallenge Action = "CHALLENGE"
	ActionBlock     Action = "BLOCK"
)

func (a Action) Valid() bool {
	switch a {
	case ActionAllow, ActionChallenge, ActionBlock:
		return true
	default:
		return false
	}
}

type AttackVector string

const (
	AttackVectorCredentialStuffing AttackVector = "credential_stuffing"
	AttackVectorSlowScan           AttackVector = "slow_scan"
	AttackVectorUnknown            AttackVector = "unknown"
)

func (v AttackVector) Valid() bool {
	switch v {
	case AttackVectorCredentialStuffing, AttackVectorSlowScan, AttackVectorUnknown:
		return true
	default:
		return false
	}
}

type ContributingSignal struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Weight float64 `json:"weight"`
}

type Decision struct {
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
	EntityID  string    `json:"entity_id"`
	Action    Action    `json:"action"`

	ConfidenceScore float64 `json:"confidence_score"`

	AttackVector AttackVector `json:"attack_vector"`

	ContributingSignals []ContributingSignal `json:"contributing_signals,omitempty"`

	Explanation string `json:"explanation"`

	LLMExplanation *string `json:"llm_explanation,omitempty"`
}

var (
	ErrEmptyRequestID         = errors.New("decision: request_id is required")
	ErrInvalidTimestamp       = errors.New("decision: timestamp is required")
	ErrEmptyEntityID          = errors.New("decision: entity_id is required")
	ErrInvalidAction          = errors.New("decision: action must be ALLOW, CHALLENGE or BLOCK")
	ErrInvalidConfidenceScore = errors.New("decision: confidence_score must be between 0 and 1")
	ErrInvalidAttackVector    = errors.New("decision: attack_vector must be credential_stuffing, slow_scan or unknown")

	ErrMissingExplanation         = errors.New("decision: explanation is required for CHALLENGE and BLOCK actions")
	ErrMissingContributingSignals = errors.New("decision: at least one contributing_signal is required for CHALLENGE and BLOCK actions")
	ErrEmptySignalName            = errors.New("decision: contributing_signal name is required")
	ErrInvalidSignalValue         = errors.New("decision: contributing_signal value must be a finite number")
	ErrInvalidSignalWeight        = errors.New("decision: contributing_signal weight must be a finite, non-negative number")
)

func Validate(d Decision) error {
	var errs []error

	if strings.TrimSpace(d.RequestID) == "" {
		errs = append(errs, ErrEmptyRequestID)
	}
	if d.Timestamp.IsZero() {
		errs = append(errs, ErrInvalidTimestamp)
	}
	if strings.TrimSpace(d.EntityID) == "" {
		errs = append(errs, ErrEmptyEntityID)
	}
	if !d.Action.Valid() {
		errs = append(errs, ErrInvalidAction)
	}
	if d.ConfidenceScore < 0 || d.ConfidenceScore > 1 {
		errs = append(errs, ErrInvalidConfidenceScore)
	}
	if !d.AttackVector.Valid() {
		errs = append(errs, ErrInvalidAttackVector)
	}

	if d.Action == ActionChallenge || d.Action == ActionBlock {
		if strings.TrimSpace(d.Explanation) == "" {
			errs = append(errs, ErrMissingExplanation)
		}
		if len(d.ContributingSignals) == 0 {
			errs = append(errs, ErrMissingContributingSignals)
		}
	}

	for _, sig := range d.ContributingSignals {
		if strings.TrimSpace(sig.Name) == "" {
			errs = append(errs, ErrEmptySignalName)
		}
		if math.IsNaN(sig.Value) || math.IsInf(sig.Value, 0) {
			errs = append(errs, ErrInvalidSignalValue)
		}
		if math.IsNaN(sig.Weight) || math.IsInf(sig.Weight, 0) || sig.Weight < 0 {
			errs = append(errs, ErrInvalidSignalWeight)
		}
	}

	return errors.Join(errs...)
}
