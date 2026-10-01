// Prueba la serialización JSON del evento y que nunca transporte credenciales ni ground truth.
package event

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

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
