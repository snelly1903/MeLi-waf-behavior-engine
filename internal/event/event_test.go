package event

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

// referenceNow es la "hora actual" fija que usan todos los tests de
// este archivo, a través de un ManualClock — ningún test espera al
// reloj real.
var referenceNow = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

// validEvent devuelve un Event completamente bien formado que pasa
// todas las reglas de validación, así cada caso de test solo necesita
// describir el único campo que quiere romper.
func validEvent() Event {
	return Event{
		RequestID:     "r-000123",
		Timestamp:     referenceNow,
		ClientIP:      netip.MustParseAddr("203.0.113.7"), // TEST-NET-3, public
		SessionID:     "s-9f2a",
		Method:        "GET",
		Path:          "/dashboard",
		QueryParams:   []string{"page"},
		StatusCode:    200,
		UserAgent:     "Mozilla/5.0",
		Referer:       "https://example.com/",
		LoginUserHash: "",
	}
}

func newTestValidator() *Validator {
	return NewValidator(NewManualClock(referenceNow))
}

func TestValidate_Accepts(t *testing.T) {
	v := newTestValidator()

	cases := map[string]Event{
		"fully populated event": validEvent(),
		"minimal event (only required fields)": {
			RequestID:  "r-1",
			Timestamp:  referenceNow,
			ClientIP:   netip.MustParseAddr("198.51.100.9"), // TEST-NET-2, public
			Method:     "GET",
			Path:       "/",
			StatusCode: 200,
		},
		"no session_id (API client)": func() Event {
			e := validEvent()
			e.SessionID = ""
			return e
		}(),
		"well-formed login_user_hash on an auth path": func() Event {
			e := validEvent()
			e.Method = "POST"
			e.Path = "/login"
			e.LoginUserHash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
			return e
		}(),
		"unusual but syntactically valid HTTP method": func() Event {
			e := validEvent()
			e.Method = "TRACE"
			return e
		}(),
		"timestamp exactly at the past tolerance boundary": func() Event {
			e := validEvent()
			e.Timestamp = referenceNow.Add(-DefaultMaxPastAge)
			return e
		}(),
		"timestamp exactly at the future tolerance boundary": func() Event {
			e := validEvent()
			e.Timestamp = referenceNow.Add(DefaultMaxFutureSkew)
			return e
		}(),
	}

	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			if err := v.Validate(e); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestValidate_Rejects(t *testing.T) {
	v := newTestValidator()

	cases := []struct {
		name    string
		mutate  func(Event) Event
		wantErr error
	}{
		{
			name:    "empty request_id",
			mutate:  func(e Event) Event { e.RequestID = ""; return e },
			wantErr: ErrEmptyRequestID,
		},
		{
			name:    "whitespace-only request_id",
			mutate:  func(e Event) Event { e.RequestID = "   "; return e },
			wantErr: ErrEmptyRequestID,
		},
		{
			name:    "zero-value timestamp",
			mutate:  func(e Event) Event { e.Timestamp = time.Time{}; return e },
			wantErr: ErrInvalidTimestamp,
		},
		{
			name:    "timestamp older than the past tolerance",
			mutate:  func(e Event) Event { e.Timestamp = referenceNow.Add(-DefaultMaxPastAge - time.Second); return e },
			wantErr: ErrTimestampTooOld,
		},
		{
			name:    "timestamp further ahead than the future skew",
			mutate:  func(e Event) Event { e.Timestamp = referenceNow.Add(DefaultMaxFutureSkew + time.Second); return e },
			wantErr: ErrTimestampTooFuture,
		},
		{
			name:    "zero-value (invalid) client_ip",
			mutate:  func(e Event) Event { e.ClientIP = netip.Addr{}; return e },
			wantErr: ErrInvalidClientIP,
		},
		{
			name:    "private client_ip (RFC1918)",
			mutate:  func(e Event) Event { e.ClientIP = netip.MustParseAddr("10.0.0.5"); return e },
			wantErr: ErrPrivateClientIP,
		},
		{
			name:    "loopback client_ip",
			mutate:  func(e Event) Event { e.ClientIP = netip.MustParseAddr("127.0.0.1"); return e },
			wantErr: ErrPrivateClientIP,
		},
		{
			name:    "empty method",
			mutate:  func(e Event) Event { e.Method = ""; return e },
			wantErr: ErrEmptyMethod,
		},
		{
			name: "method too long",
			mutate: func(e Event) Event {
				e.Method = "AVERYUNUSUALLYLONGMETHODNAME"
				return e
			},
			wantErr: ErrMethodTooLong,
		},
		{
			name:    "method with invalid characters",
			mutate:  func(e Event) Event { e.Method = "GET /path"; /* contiene un espacio */ return e },
			wantErr: ErrInvalidMethodChars,
		},
		{
			name:    "empty path",
			mutate:  func(e Event) Event { e.Path = ""; return e },
			wantErr: ErrEmptyPath,
		},
		{
			name:    "path missing leading slash",
			mutate:  func(e Event) Event { e.Path = "dashboard"; return e },
			wantErr: ErrInvalidPath,
		},
		{
			name: "path exceeds max length",
			mutate: func(e Event) Event {
				long := make([]byte, DefaultMaxPathLength+1)
				for i := range long {
					long[i] = 'a'
				}
				e.Path = "/" + string(long)
				return e
			},
			wantErr: ErrPathTooLong,
		},
		{
			name:    "status_code below 100",
			mutate:  func(e Event) Event { e.StatusCode = 0; return e },
			wantErr: ErrInvalidStatusCode,
		},
		{
			name:    "status_code above 599",
			mutate:  func(e Event) Event { e.StatusCode = 999; return e },
			wantErr: ErrInvalidStatusCode,
		},
		{
			name:    "login_user_hash looks like an email",
			mutate:  func(e Event) Event { e.LoginUserHash = "someone@example.com"; return e },
			wantErr: ErrInvalidLoginUserHash,
		},
		{
			name:    "login_user_hash too short to be a real hash",
			mutate:  func(e Event) Event { e.LoginUserHash = "abc123"; return e },
			wantErr: ErrInvalidLoginUserHash,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.mutate(validEvent()))
			if err == nil {
				t.Fatalf("Validate() = nil, want an error wrapping %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() = %v, want it to wrap %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidate_MultipleFailuresAreAllReported comprueba que un único
// Event roto de dos formas distintas se reporta con los dos errores
// centinela a la vez, no solo con el primero que se encuentra.
func TestValidate_MultipleFailuresAreAllReported(t *testing.T) {
	v := newTestValidator()
	e := validEvent()
	e.RequestID = ""
	e.StatusCode = 0

	err := v.Validate(e)
	if !errors.Is(err, ErrEmptyRequestID) {
		t.Errorf("expected error to wrap ErrEmptyRequestID, got %v", err)
	}
	if !errors.Is(err, ErrInvalidStatusCode) {
		t.Errorf("expected error to wrap ErrInvalidStatusCode, got %v", err)
	}
}

// TestNormalize_WhitespaceSessionIDIsNotAnError comprueba la regla
// aprobada: un session_id compuesto solo por espacios no se rechaza, se
// trata como si el campo nunca se hubiera enviado.
func TestNormalize_WhitespaceSessionIDIsNotAnError(t *testing.T) {
	v := newTestValidator()
	e := validEvent()
	e.SessionID = "   "

	if err := v.Validate(e); err != nil {
		t.Fatalf("Validate() = %v, want nil (whitespace session_id must not fail validation)", err)
	}

	normalized := e.Normalize()
	if normalized.SessionID != "" {
		t.Fatalf("Normalize().SessionID = %q, want \"\"", normalized.SessionID)
	}
}

func TestNormalize_TrimsFieldsAndDropsBlankQueryParams(t *testing.T) {
	e := Event{
		RequestID:   "  r-1  ",
		Method:      " GET ",
		UserAgent:   "  ",
		Referer:     "",
		QueryParams: []string{" id ", "   ", "page"},
	}

	n := e.Normalize()

	if n.RequestID != "r-1" {
		t.Errorf("RequestID = %q, want %q", n.RequestID, "r-1")
	}
	if n.Method != "GET" {
		t.Errorf("Method = %q, want %q", n.Method, "GET")
	}
	if n.UserAgent != "" {
		t.Errorf("UserAgent = %q, want \"\" (whitespace-only)", n.UserAgent)
	}
	want := []string{"id", "page"}
	if len(n.QueryParams) != len(want) {
		t.Fatalf("QueryParams = %v, want %v", n.QueryParams, want)
	}
	for i, p := range want {
		if n.QueryParams[i] != p {
			t.Errorf("QueryParams[%d] = %q, want %q", i, n.QueryParams[i], p)
		}
	}
}
