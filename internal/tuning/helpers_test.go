// Provee helpers compartidos para los tests de tuning.
package tuning

import (
	"net/netip"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type fakeCampaignResolver map[netip.Addr]string

func (r fakeCampaignResolver) Resolve(ip netip.Addr) (string, bool) {
	group, ok := r[ip]
	return group, ok
}

var testBase = time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC)

func labeledEvent(label groundtruth.Label, requestID string, offset time.Duration, ip netip.Addr, path string, status int) groundtruth.LabeledEvent {
	return groundtruth.LabeledEvent{
		Label: label,
		Event: event.Event{
			RequestID:  requestID,
			Timestamp:  testBase.Add(offset),
			ClientIP:   ip,
			Method:     "GET",
			Path:       path,
			StatusCode: status,
		},
	}
}
