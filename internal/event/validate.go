package event

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Tolerancias por defecto del Validator, según lo acordado para el
// prototipo: 5 minutos de tolerancia para eventos que llegan tarde, 1
// minuto para un pequeño desfase futuro (deriva de reloj entre el
// sistema que produce el evento y este validador). Ambas son
// deliberadamente configurables — ver docs/formato-eventos.md para cómo
// se relacionan con, y en qué se diferencian de, el manejo de eventos
// tardíos en las ventanas del motor (Fase 1).
const (
	DefaultMaxPastAge      = 5 * time.Minute
	DefaultMaxFutureSkew   = 1 * time.Minute
	DefaultMaxPathLength   = 2048
	DefaultMaxMethodLength = 20
)

// methodPattern reconoce un token de método HTTP según RFC 7230 §3.2.6:
// cualquier secuencia no vacía de caracteres de token. Esto acepta
// deliberadamente métodos inusuales como TRACE o un verbo inventado —
// el contrato no decide qué cuenta como "sospechoso", eso lo decide un
// detector, más adelante.
var methodPattern = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

// loginHashPattern reconoce una cadena hexadecimal en minúsculas de
// entre 32 y 128 caracteres — un rango amplio para cubrir largos
// comunes de salida de HMAC (SHA-256 en hex son 64 caracteres) sin
// aceptar por error un email o un nombre de usuario escrito a mano.
var loginHashPattern = regexp.MustCompile(`^[0-9a-f]{32,128}$`)

// Validator comprueba si un Event está lo suficientemente bien formado
// como para entrar al motor. No contiene ninguna lógica de negocio
// sobre ataques — solo reglas estructurales y de seguridad (campos
// obligatorios, formatos, límites de tiempo razonables).
type Validator struct {
	// Clock provee el "ahora" para las comprobaciones de rango del
	// timestamp.
	Clock Clock

	// MaxPastAge es cuánto puede tener de antigüedad un timestamp antes
	// de ser rechazado directamente (a diferencia de solo estar
	// "tarde" para la ventana a la que hubiera pertenecido, algo que el
	// motor maneja aparte en la Fase 1).
	MaxPastAge time.Duration

	// MaxFutureSkew es cuánto puede adelantarse al futuro un timestamp
	// antes de ser rechazado.
	MaxFutureSkew time.Duration

	// MaxPathLength limita el largo de la ruta del request, para que un
	// request no pueda hacer crecer sin límite el estado rastreado de
	// una entidad (o una línea de log).
	MaxPathLength int

	// MaxMethodLength limita el largo del método por la misma razón.
	MaxMethodLength int
}

// NewValidator devuelve un Validator con las tolerancias por defecto
// del prototipo, usando clock para resolver el "ahora". Quien lo llama
// puede sobrescribir cualquier campo del Validator devuelto antes de
// usarlo.
func NewValidator(clock Clock) *Validator {
	return &Validator{
		Clock:           clock,
		MaxPastAge:      DefaultMaxPastAge,
		MaxFutureSkew:   DefaultMaxFutureSkew,
		MaxPathLength:   DefaultMaxPathLength,
		MaxMethodLength: DefaultMaxMethodLength,
	}
}

// Validate comprueba e contra todas las reglas y devuelve nil si e está
// bien formado, o un error combinado que lista cada regla que falló
// (verificable individualmente con errors.Is). Validate nunca modifica
// e ni consulta el ground truth — no tiene cómo, ya que Event no tiene
// ese campo.
//
// Un SessionID compuesto solo por espacios se trata como equivalente a
// uno ausente y nunca provoca un error de validación; llamar primero a
// Event.Normalize si se quiere que quede convertido en "" en el valor
// que se conserva.
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
