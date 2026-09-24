package decision

import (
	"errors"
	"math"
	"testing"
	"time"
)

var referenceNow = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

// validDecision devuelve una Decision completamente bien formada (un
// BLOCK con explicación y señales), así cada caso de test solo necesita
// describir el campo que quiere romper.
func validDecision() Decision {
	return Decision{
		RequestID:       "r-000123",
		Timestamp:       referenceNow,
		EntityID:        "ip:203.0.113.7",
		Action:          ActionBlock,
		ConfidenceScore: 0.93,
		AttackVector:    AttackVectorCredentialStuffing,
		Explanation:     "cluster fail ratio exceeded the configured threshold",
		ContributingSignals: []ContributingSignal{
			{Name: "cluster_fail_ratio_wilson", Value: 0.81, Weight: 0.6},
			{Name: "cluster_user_diversity", Value: 0.97, Weight: 0.4},
		},
	}
}

func TestValidate_Accepts(t *testing.T) {
	cases := map[string]Decision{
		"ALLOW without explanation or contributing_signals": func() Decision {
			d := validDecision()
			d.Action = ActionAllow
			d.AttackVector = AttackVectorUnknown
			d.ConfidenceScore = 0
			d.Explanation = ""
			d.ContributingSignals = nil
			return d
		}(),
		"CHALLENGE with slow_scan vector": func() Decision {
			d := validDecision()
			d.Action = ActionChallenge
			d.AttackVector = AttackVectorSlowScan
			return d
		}(),
		"BLOCK with credential_stuffing vector": validDecision(),
		"confidence at the lower boundary (0)": func() Decision {
			d := validDecision()
			d.ConfidenceScore = 0
			return d
		}(),
		"confidence at the upper boundary (1)": func() Decision {
			d := validDecision()
			d.ConfidenceScore = 1
			return d
		}(),
		"a signal with zero weight": func() Decision {
			d := validDecision()
			d.ContributingSignals = []ContributingSignal{{Name: "s1", Value: 0.1, Weight: 0}}
			return d
		}(),
		"weights that don't sum to 1 (not required yet)": func() Decision {
			d := validDecision()
			d.ContributingSignals = []ContributingSignal{
				{Name: "s1", Value: 0.1, Weight: 5.0},
				{Name: "s2", Value: 0.2, Weight: 0.01},
			}
			return d
		}(),
	}

	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Validate(d); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestValidate_Rejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(Decision) Decision
		wantErr error
	}{
		{
			name:    "empty request_id",
			mutate:  func(d Decision) Decision { d.RequestID = ""; return d },
			wantErr: ErrEmptyRequestID,
		},
		{
			name:    "zero-value timestamp",
			mutate:  func(d Decision) Decision { d.Timestamp = time.Time{}; return d },
			wantErr: ErrInvalidTimestamp,
		},
		{
			name:    "empty entity_id",
			mutate:  func(d Decision) Decision { d.EntityID = ""; return d },
			wantErr: ErrEmptyEntityID,
		},
		{
			name:    "unknown action",
			mutate:  func(d Decision) Decision { d.Action = Action("REDIRECT"); return d },
			wantErr: ErrInvalidAction,
		},
		{
			name:    "confidence_score below 0",
			mutate:  func(d Decision) Decision { d.ConfidenceScore = -0.1; return d },
			wantErr: ErrInvalidConfidenceScore,
		},
		{
			name:    "confidence_score above 1",
			mutate:  func(d Decision) Decision { d.ConfidenceScore = 1.1; return d },
			wantErr: ErrInvalidConfidenceScore,
		},
		{
			name:    "unknown attack_vector",
			mutate:  func(d Decision) Decision { d.AttackVector = AttackVector("sql_injection"); return d },
			wantErr: ErrInvalidAttackVector,
		},
		{
			name:    "BLOCK without explanation",
			mutate:  func(d Decision) Decision { d.Explanation = ""; return d },
			wantErr: ErrMissingExplanation,
		},
		{
			name:    "CHALLENGE without explanation",
			mutate:  func(d Decision) Decision { d.Action = ActionChallenge; d.Explanation = ""; return d },
			wantErr: ErrMissingExplanation,
		},
		{
			name:    "BLOCK without contributing_signals",
			mutate:  func(d Decision) Decision { d.ContributingSignals = nil; return d },
			wantErr: ErrMissingContributingSignals,
		},
		{
			name: "signal with empty name",
			mutate: func(d Decision) Decision {
				d.ContributingSignals = []ContributingSignal{{Name: "", Value: 0.5, Weight: 0.5}}
				return d
			},
			wantErr: ErrEmptySignalName,
		},
		{
			name: "signal with NaN value",
			mutate: func(d Decision) Decision {
				d.ContributingSignals = []ContributingSignal{{Name: "s1", Value: math.NaN(), Weight: 0.5}}
				return d
			},
			wantErr: ErrInvalidSignalValue,
		},
		{
			name: "signal with +Inf value",
			mutate: func(d Decision) Decision {
				d.ContributingSignals = []ContributingSignal{{Name: "s1", Value: math.Inf(1), Weight: 0.5}}
				return d
			},
			wantErr: ErrInvalidSignalValue,
		},
		{
			name: "signal with negative weight",
			mutate: func(d Decision) Decision {
				d.ContributingSignals = []ContributingSignal{{Name: "s1", Value: 0.5, Weight: -0.01}}
				return d
			},
			wantErr: ErrInvalidSignalWeight,
		},
		{
			name: "signal with NaN weight",
			mutate: func(d Decision) Decision {
				d.ContributingSignals = []ContributingSignal{{Name: "s1", Value: 0.5, Weight: math.NaN()}}
				return d
			},
			wantErr: ErrInvalidSignalWeight,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.mutate(validDecision()))
			if err == nil {
				t.Fatalf("Validate() = nil, want an error wrapping %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() = %v, want it to wrap %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidate_MultipleFailuresAreAllReported comprueba que una Decision
// rota de dos formas distintas se reporta con los dos errores centinela
// a la vez.
func TestValidate_MultipleFailuresAreAllReported(t *testing.T) {
	d := validDecision()
	d.RequestID = ""
	d.ConfidenceScore = 2

	err := Validate(d)
	if !errors.Is(err, ErrEmptyRequestID) {
		t.Errorf("expected error to wrap ErrEmptyRequestID, got %v", err)
	}
	if !errors.Is(err, ErrInvalidConfidenceScore) {
		t.Errorf("expected error to wrap ErrInvalidConfidenceScore, got %v", err)
	}
}

// TestValidate_LLMExplanationIsNeverRequired comprueba que
// LLMExplanation, al ser una capacidad asíncrona y todavía no
// implementada, nunca es un campo obligatorio para que una decisión sea
// válida — ni siquiera en BLOCK.
func TestValidate_LLMExplanationIsNeverRequired(t *testing.T) {
	d := validDecision()
	d.LLMExplanation = nil

	if err := Validate(d); err != nil {
		t.Fatalf("Validate() = %v, want nil (LLMExplanation must not be required)", err)
	}
}
