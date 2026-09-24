// Package groundtruth define la "hoja de respuestas" del proyecto: qué
// tan malicioso es en realidad cada evento generado. Es el único lugar
// del proyecto donde event.Event y una etiqueta de verdad se juntan.
//
// Regla de dependencia, verificada en docs/decisiones.md: groundtruth
// importa event (necesita saber qué es un evento para etiquetarlo), pero
// event nunca importa groundtruth, y el motor de detección (Fase 1)
// tampoco lo va a importar. Así, la separación entre "lo que el motor
// puede ver" y "la respuesta correcta" no depende de que nadie tenga
// cuidado al escribir código nuevo: el propio grafo de dependencias del
// módulo lo impide.
package groundtruth

import (
	"errors"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

// Label es la categoría real de un evento generado por el tráfico de
// prueba, según lo exige el PDF del challenge.
type Label string

const (
	LabelLegit              Label = "legit"
	LabelCredentialStuffing Label = "credential_stuffing"
	LabelSlowScan           Label = "slow_scan"
)

// Valid informa si l es una de las tres etiquetas conocidas.
func (l Label) Valid() bool {
	switch l {
	case LabelLegit, LabelCredentialStuffing, LabelSlowScan:
		return true
	default:
		return false
	}
}

// ErrInvalidLabel se devuelve cuando un Label no es ninguno de los
// valores conocidos.
var ErrInvalidLabel = errors.New("groundtruth: label must be legit, credential_stuffing or slow_scan")

// LabeledEvent junta un evento con su etiqueta de verdad. Es exactamente
// la forma que escribe el generador de tráfico (tarea 0.4 en adelante)
// en el dataset JSONL: una línea por evento, con su etiqueta al lado.
//
// Nada fuera de este paquete y del generador de tráfico debería
// construir o leer un LabeledEvent completo. Todo lo que se le envía al
// motor sale de Payload(), nunca de serializar LabeledEvent entero.
type LabeledEvent struct {
	Label Label       `json:"label"`
	Event event.Event `json:"event"`
}

// Payload devuelve únicamente la parte Event de le — lo único que viaja
// hacia el motor de detección. Nunca incluye Label, para que quien la
// llame no tenga ni la posibilidad de filtrar la etiqueta por accidente
// al armar el request HTTP hacia el motor.
func (le LabeledEvent) Payload() event.Event {
	return le.Event
}

// Validate comprueba que le tenga una etiqueta conocida y un evento
// válido según v, y devuelve todos los problemas encontrados unidos con
// errors.Join.
func (le LabeledEvent) Validate(v *event.Validator) error {
	var errs []error

	if !le.Label.Valid() {
		errs = append(errs, ErrInvalidLabel)
	}
	if err := v.Validate(le.Event); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}
