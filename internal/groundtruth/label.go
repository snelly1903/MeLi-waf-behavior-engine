// Define las etiquetas de ground truth y los eventos etiquetados.
package groundtruth

import (
	"errors"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

type Label string

const (
	LabelLegit              Label = "legit"
	LabelCredentialStuffing Label = "credential_stuffing"
	LabelSlowScan           Label = "slow_scan"
)

func (l Label) Valid() bool {
	switch l {
	case LabelLegit, LabelCredentialStuffing, LabelSlowScan:
		return true
	default:
		return false
	}
}

var ErrInvalidLabel = errors.New("groundtruth: label must be legit, credential_stuffing or slow_scan")

type LabeledEvent struct {
	Label Label       `json:"label"`
	Event event.Event `json:"event"`
}

func (le LabeledEvent) Payload() event.Event {
	return le.Event
}

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
