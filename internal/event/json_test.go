package event

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

// forbiddenJSONSubstrings son cadenas que nunca deben aparecer en la
// codificación JSON de un Event: credenciales en claro (este contrato
// nunca las lleva) y la forma "=valor" que tendría el *valor* de un
// parámetro de query si alguien serializara por error más que su
// nombre.
//
// A diferencia de TestEventJSON_GroundTruthNeverTravels, acá sí se
// busca por substring en todo el documento en lugar de por clave: una
// credencial filtrada no necesariamente entra como un campo nuevo,
// puede colarse como el *valor* de un campo que ya existe (alguien pega
// una contraseña dentro de UserAgent por error, por ejemplo). Buscar
// por clave no detectaría ese caso.
//
// Dicho esto, esta prueba es una red de seguridad, no una garantía: es
// una lista fija de palabras, y no sustituye la validación,
// minimización y sanitización de datos sensibles que hace falta aplicar
// en la ingesta real y en los logs del motor (Fase 1) — ahí es donde
// corresponde decidir, por ejemplo, qué hacer si un cliente manda un
// header con forma de credencial en un campo que no la espera.
var forbiddenJSONSubstrings = []string{
	"password",
	"passwd",
	"token",
	"cookie",
	"secret",
	"authorization",
}

func TestEventJSON_NeverCarriesCredentialLikeKeys(t *testing.T) {
	e := validEvent()
	e.Method = "POST"
	e.Path = "/login"
	e.LoginUserHash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	lower := strings.ToLower(string(data))

	for _, forbidden := range forbiddenJSONSubstrings {
		if strings.Contains(lower, forbidden) {
			t.Errorf("serialized Event contains forbidden substring %q: %s", forbidden, data)
		}
	}
}

func TestEventJSON_QueryParamsCarryOnlyNames(t *testing.T) {
	e := validEvent()
	e.QueryParams = []string{"id", "page", "sort"}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// El *valor* de un parámetro aparecería como "nombre=valor" en
	// alguna parte de una serialización ingenua. Nuestro QueryParams es
	// un []string simple de nombres, así que "=" nunca debería aparecer
	// dentro del propio arreglo query_params.
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	rawParams, ok := decoded["query_params"]
	if !ok {
		t.Fatal("expected a query_params field in the serialized event")
	}
	if strings.Contains(string(rawParams), "=") {
		t.Errorf("query_params must contain only parameter names, got %s", rawParams)
	}
}

func TestEventJSON_RoundTrip(t *testing.T) {
	original := validEvent()

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if !decoded.ClientIP.IsValid() || decoded.ClientIP != original.ClientIP {
		t.Errorf("ClientIP round-trip mismatch: got %v, want %v", decoded.ClientIP, original.ClientIP)
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp round-trip mismatch: got %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	if decoded.RequestID != original.RequestID {
		t.Errorf("RequestID round-trip mismatch: got %q, want %q", decoded.RequestID, original.RequestID)
	}
}

func TestEventJSON_MalformedIPFailsToUnmarshal(t *testing.T) {
	raw := `{"request_id":"r-1","timestamp":"2026-09-24T10:00:00Z","client_ip":"not-an-ip","method":"GET","path":"/","status_code":200}`

	var e Event
	if err := json.Unmarshal([]byte(raw), &e); err == nil {
		t.Fatal("expected json.Unmarshal to fail for a malformed client_ip, got nil error")
	}
}

// TestEventJSON_GroundTruthNeverTravels documenta, a nivel de los bytes
// que viajan por la red, la garantía descrita en
// TestEvent_HasNoGroundTruthField: incluso un Event completamente
// poblado, una vez serializado, no tiene ninguna de las claves JSON del
// vocabulario de etiquetas que usa internal/groundtruth.
//
// Se comprueba por clave, no por substring en todo el documento — ver
// el comentario de TestLabeledEvent_Payload_NeverCarriesLabel en
// internal/groundtruth/label_test.go para el razonamiento completo.
func TestEventJSON_GroundTruthNeverTravels(t *testing.T) {
	e := validEvent()
	e.ClientIP = netip.MustParseAddr("203.0.113.99")

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	for _, forbiddenKey := range []string{"label", "ground_truth", "groundtruth", "attack_type", "truth"} {
		if _, exists := decoded[forbiddenKey]; exists {
			t.Errorf("serialized Event must not have a %q key, got: %s", forbiddenKey, data)
		}
	}
}
