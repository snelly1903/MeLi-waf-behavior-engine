package baseline

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

type CountMode string

const (
	CountModeAll CountMode = "all"

	CountModeAuth CountMode = "auth"
)

func (m CountMode) Valid() bool {
	switch m {
	case CountModeAll, CountModeAuth:
		return true
	default:
		return false
	}
}

type Config struct {
	MaxRequests int

	Window time.Duration

	Mode CountMode

	AuthMatcher *event.AuthPathMatcher
}

var (
	ErrInvalidMaxRequests = errors.New("baseline: max_requests must be greater than 0")
	ErrInvalidWindow      = errors.New("baseline: window must be greater than 0")
	ErrInvalidMode        = errors.New("baseline: mode must be \"all\" or \"auth\"")
)

func (cfg Config) Validate() error {
	var errs []error
	if cfg.MaxRequests <= 0 {
		errs = append(errs, ErrInvalidMaxRequests)
	}
	if cfg.Window <= 0 {
		errs = append(errs, ErrInvalidWindow)
	}
	if !cfg.Mode.Valid() {
		errs = append(errs, ErrInvalidMode)
	}
	return errors.Join(errs...)
}

var ErrEventsOutOfOrder = errors.New("baseline: events must be sorted by timestamp, ascending")

func Detect(events []event.Event, cfg Config) ([]decision.Decision, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	for i := 1; i < len(events); i++ {
		if events[i].Timestamp.Before(events[i-1].Timestamp) {
			return nil, fmt.Errorf("%w: event %d (request_id=%q) is before event %d (request_id=%q)",
				ErrEventsOutOfOrder, i, events[i].RequestID, i-1, events[i-1].RequestID)
		}
	}

	matcher := cfg.AuthMatcher
	if matcher == nil {
		matcher = event.DefaultAuthPathMatcher()
	}

	windows := make(map[netip.Addr][]time.Time)
	decisions := make([]decision.Decision, 0, len(events))

	for _, e := range events {
		counted := cfg.Mode == CountModeAll || matcher.IsAuthPath(e.Path)
		if !counted {
			decisions = append(decisions, allowDecision(e))
			continue
		}

		queue := windows[e.ClientIP]
		cutoff := e.Timestamp.Add(-cfg.Window)
		start := 0
		for start < len(queue) && queue[start].Before(cutoff) {
			start++
		}
		queue = append(queue[start:], e.Timestamp)
		windows[e.ClientIP] = queue

		count := len(queue)
		if count > cfg.MaxRequests {
			decisions = append(decisions, blockDecision(e, count, cfg.MaxRequests))
		} else {
			decisions = append(decisions, allowDecision(e))
		}
	}

	return decisions, nil
}

func entityID(e event.Event) string {
	return "ip:" + e.ClientIP.String()
}

func allowDecision(e event.Event) decision.Decision {
	return decision.Decision{
		RequestID:    e.RequestID,
		Timestamp:    e.Timestamp,
		EntityID:     entityID(e),
		Action:       decision.ActionAllow,
		AttackVector: decision.AttackVectorUnknown,
	}
}

func confidenceScore(count, maxRequests int) float64 {
	score := 1 - float64(maxRequests)/float64(count)
	if score < 0 {
		return 0
	}
	return score
}

func blockDecision(e event.Event, count, maxRequests int) decision.Decision {
	return decision.Decision{
		RequestID:       e.RequestID,
		Timestamp:       e.Timestamp,
		EntityID:        entityID(e),
		Action:          decision.ActionBlock,
		ConfidenceScore: confidenceScore(count, maxRequests),
		AttackVector:    decision.AttackVectorUnknown,
		ContributingSignals: []decision.ContributingSignal{
			{Name: "requests_in_window", Value: float64(count), Weight: 1},
		},
		Explanation: fmt.Sprintf("%d requests from this IP in the configured window (limit: %d)", count, maxRequests),
	}
}
