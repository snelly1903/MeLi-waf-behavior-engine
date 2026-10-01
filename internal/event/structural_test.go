// Verifica que el evento no tenga campos de ground truth.
package event

import (
	"reflect"
	"strings"
	"testing"
)

var forbiddenFieldSubstrings = []string{
	"label",
	"truth",
	"attacktype",
	"attack_vector",
	"ismalicious",
	"is_malicious",
}

func TestEvent_HasNoGroundTruthField(t *testing.T) {
	typ := reflect.TypeOf(Event{})

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		nameLower := strings.ToLower(field.Name)
		jsonTagLower := strings.ToLower(field.Tag.Get("json"))

		for _, forbidden := range forbiddenFieldSubstrings {
			if strings.Contains(nameLower, forbidden) {
				t.Errorf("Event field %q must not exist: it looks like a ground-truth field (matched %q)", field.Name, forbidden)
			}
			if strings.Contains(jsonTagLower, forbidden) {
				t.Errorf("Event field %q has json tag %q, which looks like a ground-truth field (matched %q)",
					field.Name, field.Tag.Get("json"), forbidden)
			}
		}
	}
}
