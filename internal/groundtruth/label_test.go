package groundtruth

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

var referenceNow = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

// validEvent devuelve un event.Event completamente bien formado, para
// no repetir su construcción en cada test de este archivo.
func validEvent() event.Event {
	return event.Event{
		RequestID:  "r-000123",
		Timestamp:  referenceNow,
		ClientIP:   netip.MustParseAddr("203.0.113.7"),
		Method:     "POST",
		Path:       "/login",
		StatusCode: 401,
	}
}

func newTestValidator() *event.Validator {
	return event.NewValidator(event.NewManualClock(referenceNow))
}

func TestLabel_Valid(t *testing.T) {
	valid := []Label{LabelLegit, LabelCredentialStuffing, LabelSlowScan}
	for _, l := range valid {
		if !l.Valid() {
			t.Errorf("Label(%q).Valid() = false, want true", l)
		}
	}

	invalid := []Label{"", "malicious", "CREDENTIAL_STUFFING", "sql_injection"}
	for _, l := range invalid {
		if l.Valid() {
			t.Errorf("Label(%q).Valid() = true, want false", l)
		}
	}
}

func TestLabeledEvent_Validate_Accepts(t *testing.T) {
	v := newTestValidator()
	le := LabeledEvent{Label: LabelCredentialStuffing, Event: validEvent()}

	if err := le.Validate(v); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestLabeledEvent_Validate_RejectsInvalidLabel(t *testing.T) {
	v := newTestValidator()
	le := LabeledEvent{Label: Label("not_a_real_label"), Event: validEvent()}

	err := le.Validate(v)
	if !errors.Is(err, ErrInvalidLabel) {
		t.Fatalf("Validate() = %v, want it to wrap ErrInvalidLabel", err)
	}
}

func TestLabeledEvent_Validate_RejectsInvalidEvent(t *testing.T) {
	v := newTestValidator()
	badEvent := validEvent()
	badEvent.RequestID = ""
	le := LabeledEvent{Label: LabelLegit, Event: badEvent}

	err := le.Validate(v)
	if !errors.Is(err, event.ErrEmptyRequestID) {
		t.Fatalf("Validate() = %v, want it to wrap event.ErrEmptyRequestID", err)
	}
}

func TestLabeledEvent_Validate_ReportsBothLabelAndEventErrors(t *testing.T) {
	v := newTestValidator()
	badEvent := validEvent()
	badEvent.StatusCode = 0
	le := LabeledEvent{Label: Label("bogus"), Event: badEvent}

	err := le.Validate(v)
	if !errors.Is(err, ErrInvalidLabel) {
		t.Errorf("expected error to wrap ErrInvalidLabel, got %v", err)
	}
	if !errors.Is(err, event.ErrInvalidStatusCode) {
		t.Errorf("expected error to wrap event.ErrInvalidStatusCode, got %v", err)
	}
}

// TestLabeledEvent_Payload_IsExactlyTheEvent comprueba que Payload() no
// hace nada más que devolver el Event contenido, sin transformarlo.
func TestLabeledEvent_Payload_IsExactlyTheEvent(t *testing.T) {
	e := validEvent()
	le := LabeledEvent{Label: LabelSlowScan, Event: e}

	if !reflect.DeepEqual(le.Payload(), e) {
		t.Fatalf("Payload() = %+v, want %+v", le.Payload(), e)
	}
}

// TestLabeledEvent_Payload_NeverCarriesLabel es el test central de
// aislamiento de esta tarea: serializa lo que efectivamente viajaría
// hacia el motor (el resultado de Payload(), no el LabeledEvent
// completo) y confirma que no existen las claves JSON "label" ni
// "ground_truth".
//
// Se comprueba por clave, no por substring en todo el documento: una
// fuga del ground truth solo puede entrar como un campo nuevo (la
// etiqueta no tiene ninguna razón para aparecer como el *valor* de un
// campo que ya existe), así que verificar la ausencia exacta de esas
// claves es una prueba precisa. Buscar palabras sueltas en todo el JSON
// sería, en cambio, una aproximación: fallaría en falso si mañana un
// campo legítimo (por ejemplo, una ruta como "/api/label-printer")
// contuviera esa palabra por casualidad, y no detectaría con certeza
// una fuga si la clave tuviera otra mayúscula o forma.
func TestLabeledEvent_Payload_NeverCarriesLabel(t *testing.T) {
	le := LabeledEvent{Label: LabelCredentialStuffing, Event: validEvent()}

	data, err := json.Marshal(le.Payload())
	if err != nil {
		t.Fatalf("json.Marshal(le.Payload()): %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(le.Payload()): %v", err)
	}

	for _, forbiddenKey := range []string{"label", "ground_truth"} {
		if _, exists := decoded[forbiddenKey]; exists {
			t.Errorf("serialized payload must not have a %q key, got: %s", forbiddenKey, data)
		}
	}
}

// TestLabeledEvent_Payload_PassesEventValidation comprueba que las dos
// piezas del contrato encastran: un LabeledEvent válido produce, a
// través de Payload(), un event.Event que el Validator de la tarea 0.2
// acepta sin cambios.
func TestLabeledEvent_Payload_PassesEventValidation(t *testing.T) {
	v := newTestValidator()
	le := LabeledEvent{Label: LabelLegit, Event: validEvent()}

	if err := v.Validate(le.Payload()); err != nil {
		t.Fatalf("Validate(le.Payload()) = %v, want nil", err)
	}
}

// TestLabeledEventJSON_RoundTrip comprueba la serialización completa del
// LabeledEvent (label + event), que es la forma en la que el generador
// de tráfico lo escribe en el dataset — nunca la forma en la que algo
// viaja hacia el motor.
func TestLabeledEventJSON_RoundTrip(t *testing.T) {
	original := LabeledEvent{Label: LabelSlowScan, Event: validEvent()}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded LabeledEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Label != original.Label {
		t.Errorf("Label round-trip mismatch: got %q, want %q", decoded.Label, original.Label)
	}
	if decoded.Event.RequestID != original.Event.RequestID {
		t.Errorf("Event.RequestID round-trip mismatch: got %q, want %q", decoded.Event.RequestID, original.Event.RequestID)
	}
}
