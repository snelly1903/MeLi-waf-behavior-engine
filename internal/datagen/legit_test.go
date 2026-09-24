package datagen

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

var sessionStart = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

// TestGenerateLegitSession_Reproducible es el test central de esta
// tarea: la misma semilla, el mismo perfil y el mismo punto de partida
// tienen que producir exactamente el mismo JSON, byte a byte.
func TestGenerateLegitSession_Reproducible(t *testing.T) {
	for _, profile := range []LegitProfile{ProfileNavegante, ProfileAPIClient, ProfileOffice} {
		t.Run(profile.Name, func(t *testing.T) {
			ip := profile.Pool.RandomAddr(NewRNG(999)) // misma IP fija para ambas corridas

			a := GenerateLegitSession(NewRNG(42), profile, sessionStart, ip)
			b := GenerateLegitSession(NewRNG(42), profile, sessionStart, ip)

			dataA, err := json.Marshal(a)
			if err != nil {
				t.Fatalf("json.Marshal(a): %v", err)
			}
			dataB, err := json.Marshal(b)
			if err != nil {
				t.Fatalf("json.Marshal(b): %v", err)
			}
			if string(dataA) != string(dataB) {
				t.Fatalf("same seed produced different output:\nA=%s\nB=%s", dataA, dataB)
			}
		})
	}
}

// validatorAsOfEachEvent valida cada evento "como si se hubiera
// ingerido en el instante de su propio timestamp" — el reloj de la
// tolerancia de tiempo del Validator (5 min de pasado, 1 min de futuro)
// modela la ingesta en tiempo real, no la reproducción de un dataset ya
// generado que puede abarcar horas simuladas. Validar así separa esa
// comprobación de tiempo real (que no aplica acá) de la comprobación
// estructural (IP, método, path, status, formato del hash) que sí
// tiene que cumplir cualquier evento generado. Ver
// docs/formato-eventos.md, sección de timestamps, para el mismo
// razonamiento aplicado a la tarea 0.2.
func validatorAsOfEachEvent(le groundtruth.LabeledEvent) error {
	v := event.NewValidator(event.NewManualClock(le.Event.Timestamp))
	return le.Validate(v)
}

func TestGenerateLegitSession_EventsPassValidator(t *testing.T) {
	rng := NewRNG(5)
	for _, profile := range []LegitProfile{ProfileNavegante, ProfileAPIClient, ProfileOffice} {
		ip := profile.Pool.RandomAddr(rng)
		events := GenerateLegitSession(rng, profile, sessionStart, ip)
		if len(events) == 0 {
			t.Fatalf("profile %q generated zero events", profile.Name)
		}
		for i, le := range events {
			if err := validatorAsOfEachEvent(le); err != nil {
				t.Errorf("profile %q, event %d (%s %s): %v", profile.Name, i, le.Event.Method, le.Event.Path, err)
			}
		}
	}
}

func TestGenerateLegitSession_AllEventsAreLegit(t *testing.T) {
	rng := NewRNG(6)
	for _, profile := range []LegitProfile{ProfileNavegante, ProfileAPIClient, ProfileOffice} {
		ip := profile.Pool.RandomAddr(rng)
		for _, le := range GenerateLegitSession(rng, profile, sessionStart, ip) {
			if le.Label != groundtruth.LabelLegit {
				t.Errorf("profile %q produced an event labeled %q, want %q", profile.Name, le.Label, groundtruth.LabelLegit)
			}
		}
	}
}

func TestGenerateLegitSession_UniqueRequestIDs(t *testing.T) {
	rng := NewRNG(7)
	ip := ProfileNavegante.Pool.RandomAddr(rng)
	events := GenerateLegitSession(rng, ProfileNavegante, sessionStart, ip)

	seen := make(map[string]bool, len(events))
	for _, le := range events {
		if seen[le.Event.RequestID] {
			t.Fatalf("duplicate request_id: %s", le.Event.RequestID)
		}
		seen[le.Event.RequestID] = true
	}
}

func TestGenerateLegitSession_TimestampsNonDecreasing(t *testing.T) {
	rng := NewRNG(8)
	for _, profile := range []LegitProfile{ProfileNavegante, ProfileAPIClient, ProfileOffice} {
		ip := profile.Pool.RandomAddr(rng)
		events := GenerateLegitSession(rng, profile, sessionStart, ip)
		for i := 1; i < len(events); i++ {
			prev, cur := events[i-1].Event.Timestamp, events[i].Event.Timestamp
			if cur.Before(prev) {
				t.Fatalf("profile %q: timestamp went backwards at event %d: %v before %v", profile.Name, i, cur, prev)
			}
		}
	}
}

// TestProfilesProduceDifferentBehaviors comprueba que los tres perfiles
// no son intercambiables: cada uno tiene que mostrar, con la misma
// semilla, el rasgo que lo distingue.
func TestProfilesProduceDifferentBehaviors(t *testing.T) {
	seed := uint64(11)

	rngNav := NewRNG(seed)
	navEvents := GenerateLegitSession(rngNav, ProfileNavegante, sessionStart, ProfileNavegante.Pool.RandomAddr(rngNav))

	rngAPI := NewRNG(seed)
	apiEvents := GenerateLegitSession(rngAPI, ProfileAPIClient, sessionStart, ProfileAPIClient.Pool.RandomAddr(rngAPI))

	// El navegante manda referer y pide al menos un asset estático.
	navHasReferer, navHasAsset := false, false
	for _, le := range navEvents {
		if le.Event.Referer != "" {
			navHasReferer = true
		}
		for _, asset := range ProfileNavegante.StaticAssets {
			if le.Event.Path == asset {
				navHasAsset = true
			}
		}
	}
	if !navHasReferer {
		t.Error("ProfileNavegante never sent a Referer")
	}
	if !navHasAsset {
		t.Error("ProfileNavegante never fetched a static asset")
	}

	// El cliente API nunca manda referer, nunca pide un asset, y nunca
	// tiene sesión — la "trampa" del escaneo lento.
	for _, le := range apiEvents {
		if le.Event.Referer != "" {
			t.Errorf("ProfileAPIClient sent a Referer, want it to never do so: %q", le.Event.Referer)
		}
		if le.Event.SessionID != "" {
			t.Errorf("ProfileAPIClient carried a SessionID, want it to never do so: %q", le.Event.SessionID)
		}
		for _, asset := range ProfileNavegante.StaticAssets {
			if le.Event.Path == asset {
				t.Errorf("ProfileAPIClient fetched a static asset, want it to never do so: %q", le.Event.Path)
			}
		}
	}
}

// TestGenerateOfficeCluster_SharesIPButDistinctSessions comprueba la
// trampa de la oficina: varios empleados, todos con la misma IP
// (simulando el NAT corporativo) pero cada uno con su propio
// session_id.
func TestGenerateOfficeCluster_SharesIPButDistinctSessions(t *testing.T) {
	const employees = 5
	rng := NewRNG(13)
	events := GenerateOfficeCluster(rng, employees, sessionStart, 10*time.Minute)

	if len(events) == 0 {
		t.Fatal("GenerateOfficeCluster produced zero events")
	}

	ips := make(map[string]bool)
	sessions := make(map[string]bool)
	for _, le := range events {
		ips[le.Event.ClientIP.String()] = true
		sessions[le.Event.SessionID] = true
	}

	if len(ips) != 1 {
		t.Fatalf("office cluster used %d distinct IPs, want exactly 1 (shared NAT IP): %v", len(ips), ips)
	}
	if len(sessions) != employees {
		t.Fatalf("office cluster used %d distinct session_ids, want exactly %d (one per employee)", len(sessions), employees)
	}
}

// TestGenerateOfficeCluster_TimestampsAreSorted comprueba que, al
// juntar varias sesiones (una por empleado, cada una con su propio
// horario de inicio), el resultado queda ordenado por Timestamp —
// coherente en el tiempo sin necesitar ninguna espera real.
func TestGenerateOfficeCluster_TimestampsAreSorted(t *testing.T) {
	rng := NewRNG(14)
	events := GenerateOfficeCluster(rng, 6, sessionStart, 15*time.Minute)

	for i := 1; i < len(events); i++ {
		if events[i].Event.Timestamp.Before(events[i-1].Event.Timestamp) {
			t.Fatalf("timestamps not sorted at index %d: %v before %v", i, events[i].Event.Timestamp, events[i-1].Event.Timestamp)
		}
	}
}

func TestGenerateOfficeCluster_Reproducible(t *testing.T) {
	a := GenerateOfficeCluster(NewRNG(77), 4, sessionStart, 10*time.Minute)
	b := GenerateOfficeCluster(NewRNG(77), 4, sessionStart, 10*time.Minute)

	dataA, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("json.Marshal(a): %v", err)
	}
	dataB, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("json.Marshal(b): %v", err)
	}
	if string(dataA) != string(dataB) {
		t.Fatal("same seed produced different office cluster output")
	}
}
