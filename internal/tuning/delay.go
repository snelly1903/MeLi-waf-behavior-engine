// Calcula el retraso de detección por campaña de ataque.
package tuning

import (
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type CampaignDelay struct {
	Vector      groundtruth.Label
	CampaignKey string

	TotalRequests int

	FirstEventAt time.Time

	Detected bool

	RequestsToDetection int

	TimeToDetection time.Duration
}

func campaignKey(label groundtruth.Label, e event.Event, resolver credstuffing.NetworkResolver) (string, bool) {
	switch label {
	case groundtruth.LabelCredentialStuffing:
		group, ok := resolver.Resolve(e.ClientIP)
		if !ok {
			return "", false
		}
		return "network:" + group, true
	case groundtruth.LabelSlowScan:
		if e.SessionID != "" {
			return "session:" + e.SessionID, true
		}
		return "ip:" + e.ClientIP.String(), true
	default:
		return "", false
	}
}

type campaignState struct {
	vector              groundtruth.Label
	firstEventAt        time.Time
	requestsSeen        int
	detected            bool
	requestsToDetection int
	timeToDetection     time.Duration
}

func ComputeDetectionDelay(events []groundtruth.LabeledEvent, decisions []decision.Decision, resolver credstuffing.NetworkResolver, policy eval.Policy) []CampaignDelay {
	states := make(map[string]*campaignState)
	var order []string

	for i, le := range events {
		if le.Label == groundtruth.LabelLegit {
			continue
		}
		key, ok := campaignKey(le.Label, le.Event, resolver)
		if !ok {
			continue
		}

		st, exists := states[key]
		if !exists {
			st = &campaignState{vector: le.Label, firstEventAt: le.Event.Timestamp}
			states[key] = st
			order = append(order, key)
		}
		st.requestsSeen++

		if !st.detected && policy.IsPositive(decisions[i].Action) {
			st.detected = true
			st.requestsToDetection = st.requestsSeen
			st.timeToDetection = le.Event.Timestamp.Sub(st.firstEventAt)
		}
	}

	sort.Strings(order)
	result := make([]CampaignDelay, 0, len(order))
	for _, key := range order {
		st := states[key]
		cd := CampaignDelay{
			Vector:        st.vector,
			CampaignKey:   key,
			TotalRequests: st.requestsSeen,
			FirstEventAt:  st.firstEventAt,
			Detected:      st.detected,
		}
		if st.detected {
			cd.RequestsToDetection = st.requestsToDetection
			cd.TimeToDetection = st.timeToDetection
		}
		result = append(result, cd)
	}
	return result
}
