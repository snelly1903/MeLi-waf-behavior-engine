// Valida los campos de un evento HTTP antes de que llegue al motor.
package event

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultMaxPastAge      = 5 * time.Minute
	DefaultMaxFutureSkew   = 1 * time.Minute
	DefaultMaxPathLength   = 2048
	DefaultMaxMethodLength = 20
)

var methodPattern = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

var loginHashPattern = regexp.MustCompile(`^[0-9a-f]{32,128}$`)

type Validator struct {
	Clock Clock

	MaxPastAge time.Duration

	MaxFutureSkew time.Duration

	MaxPathLength int

	MaxMethodLength int
}

func NewValidator(clock Clock) *Validator {
	return &Validator{
		Clock:           clock,
		MaxPastAge:      DefaultMaxPastAge,
		MaxFutureSkew:   DefaultMaxFutureSkew,
		MaxPathLength:   DefaultMaxPathLength,
		MaxMethodLength: DefaultMaxMethodLength,
	}
}

func (v *Validator) Validate(e Event) error {
	var errs []error

	if strings.TrimSpace(e.RequestID) == "" {
		errs = append(errs, ErrEmptyRequestID)
	}

	if e.Timestamp.IsZero() {
		errs = append(errs, ErrInvalidTimestamp)
	} else {
		now := v.Clock.Now()
		if e.Timestamp.Before(now.Add(-v.MaxPastAge)) {
			errs = append(errs, ErrTimestampTooOld)
		}
		if e.Timestamp.After(now.Add(v.MaxFutureSkew)) {
			errs = append(errs, ErrTimestampTooFuture)
		}
	}

	if !e.ClientIP.IsValid() {
		errs = append(errs, ErrInvalidClientIP)
	} else if e.ClientIP.IsPrivate() || e.ClientIP.IsLoopback() ||
		e.ClientIP.IsUnspecified() || e.ClientIP.IsLinkLocalUnicast() {
		errs = append(errs, ErrPrivateClientIP)
	}

	method := strings.TrimSpace(e.Method)
	if method == "" {
		errs = append(errs, ErrEmptyMethod)
	} else {
		if len(method) > v.MaxMethodLength {
			errs = append(errs, ErrMethodTooLong)
		}
		if !methodPattern.MatchString(method) {
			errs = append(errs, ErrInvalidMethodChars)
		}
	}

	if e.Path == "" {
		errs = append(errs, ErrEmptyPath)
	} else {
		if !strings.HasPrefix(e.Path, "/") {
			errs = append(errs, ErrInvalidPath)
		}
		if len(e.Path) > v.MaxPathLength {
			errs = append(errs, ErrPathTooLong)
		}
	}

	if e.StatusCode < 100 || e.StatusCode > 599 {
		errs = append(errs, ErrInvalidStatusCode)
	}

	if hash := strings.TrimSpace(e.LoginUserHash); hash != "" && !loginHashPattern.MatchString(hash) {
		errs = append(errs, ErrInvalidLoginUserHash)
	}

	return errors.Join(errs...)
}
