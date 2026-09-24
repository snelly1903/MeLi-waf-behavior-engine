package event

import "errors"

// Errores centinela de validación. Validate los devuelve unidos con
// errors.Join, así quien llama puede comprobar una regla específica con
// errors.Is incluso cuando fallaron varias reglas sobre el mismo Event.
var (
	ErrEmptyRequestID = errors.New("event: request_id is required")

	ErrInvalidTimestamp   = errors.New("event: timestamp is required and must be a valid date")
	ErrTimestampTooOld    = errors.New("event: timestamp is older than the allowed past tolerance")
	ErrTimestampTooFuture = errors.New("event: timestamp is further in the future than the allowed skew")

	ErrInvalidClientIP = errors.New("event: client_ip is required and must be a valid IP address")
	ErrPrivateClientIP = errors.New("event: client_ip must be a public address (private/loopback/link-local rejected)")

	ErrEmptyMethod        = errors.New("event: method is required")
	ErrMethodTooLong      = errors.New("event: method exceeds the maximum allowed length")
	ErrInvalidMethodChars = errors.New("event: method contains characters not allowed in an HTTP token")

	ErrEmptyPath   = errors.New("event: path is required")
	ErrInvalidPath = errors.New("event: path must start with \"/\"")
	ErrPathTooLong = errors.New("event: path exceeds the maximum allowed length")

	ErrInvalidStatusCode = errors.New("event: status_code must be between 100 and 599")

	ErrInvalidLoginUserHash = errors.New("event: login_user_hash must look like a hash, not an email or raw identifier")
)
