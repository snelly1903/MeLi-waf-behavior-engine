package engine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

func TestAllowAllDecider_Decide_ProducesValidDecision(t *testing.T) {
	e := event.Event{
		RequestID:  "r-1",
		Timestamp:  time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC),
		ClientIP:   netip.MustParseAddr("203.0.113.7"),
		Method:     "GET",
		Path:       "/",
		StatusCode: 200,
	}

	d := AllowAllDecider{}.Decide(context.Background(), e)

	if err := decision.Validate(d); err != nil {
		t.Fatalf("decision.Validate(%+v) = %v, want nil", d, err)
	}
	if d.Action != decision.ActionAllow {
		t.Errorf("Action = %v, want ALLOW", d.Action)
	}
	if d.AttackVector != decision.AttackVectorUnknown {
		t.Errorf("AttackVector = %v, want unknown", d.AttackVector)
	}
	if d.RequestID != e.RequestID {
		t.Errorf("RequestID = %q, want %q", d.RequestID, e.RequestID)
	}
	if !d.Timestamp.Equal(e.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", d.Timestamp, e.Timestamp)
	}
	if d.EntityID != "ip:203.0.113.7" {
		t.Errorf("EntityID = %q, want %q", d.EntityID, "ip:203.0.113.7")
	}
	if d.Explanation == "" {
		t.Error("Explanation is empty, want a deterministic, auditable message even for ALLOW")
	}
}
