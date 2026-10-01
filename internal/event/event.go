// Define el contrato del evento HTTP que recibe el motor y su normalización.
package event

import (
	"net/netip"
	"strings"
	"time"
)

type Event struct {
	RequestID string `json:"request_id"`

	Timestamp time.Time `json:"timestamp"`

	ClientIP netip.Addr `json:"client_ip"`

	SessionID string `json:"session_id,omitempty"`

	Method string `json:"method"`

	Path string `json:"path"`

	QueryParams []string `json:"query_params,omitempty"`

	StatusCode int `json:"status_code"`

	UserAgent string `json:"user_agent,omitempty"`

	Referer string `json:"referer,omitempty"`

	LoginUserHash string `json:"login_user_hash,omitempty"`
}

func (e Event) Normalize() Event {
	n := e
	n.RequestID = strings.TrimSpace(e.RequestID)
	n.SessionID = trimToEmpty(e.SessionID)
	n.Method = strings.TrimSpace(e.Method)
	n.UserAgent = trimToEmpty(e.UserAgent)
	n.Referer = trimToEmpty(e.Referer)
	n.LoginUserHash = trimToEmpty(e.LoginUserHash)
	if e.QueryParams != nil {
		params := make([]string, 0, len(e.QueryParams))
		for _, p := range e.QueryParams {
			if p = strings.TrimSpace(p); p != "" {
				params = append(params, p)
			}
		}
		n.QueryParams = params
	}
	return n
}

func trimToEmpty(s string) string {
	if trimmed := strings.TrimSpace(s); trimmed != "" {
		return trimmed
	}
	return ""
}
