package tuning

import (
	"reflect"
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
)

// TestBaselineCandidate_MatchesEngineDefaults es el guardrail pedido
// en la tarea 1.9 (ajuste 2 del plan): BaselineCandidate tiene que
// reflejar EXACTAMENTE lo mismo que engine.Default*Config()/DefaultPolicy()
// — los mismos que usa cmd/engine — nunca una copia a mano que
// pudiera desincronizarse. Como BaselineCandidate ya llama
// directamente a esas funciones, este test es sobre todo una alarma
// temprana: si algún día alguien reemplaza esas llamadas por
// literales hardcodeados, este test lo detecta de inmediato.
func TestBaselineCandidate_MatchesEngineDefaults(t *testing.T) {
	c := BaselineCandidate()

	if !reflect.DeepEqual(c.CredentialStuffing, engine.DefaultCredentialStuffingConfig()) {
		t.Errorf("CredentialStuffing = %+v, want engine.DefaultCredentialStuffingConfig() = %+v", c.CredentialStuffing, engine.DefaultCredentialStuffingConfig())
	}
	if !reflect.DeepEqual(c.SlowScan, engine.DefaultSlowScanConfig()) {
		t.Errorf("SlowScan = %+v, want engine.DefaultSlowScanConfig() = %+v", c.SlowScan, engine.DefaultSlowScanConfig())
	}
	if !reflect.DeepEqual(c.Anomaly, engine.DefaultAnomalyConfig()) {
		t.Errorf("Anomaly = %+v, want engine.DefaultAnomalyConfig() = %+v", c.Anomaly, engine.DefaultAnomalyConfig())
	}
	if c.Policy != engine.DefaultPolicy() {
		t.Errorf("Policy = %+v, want engine.DefaultPolicy() = %+v", c.Policy, engine.DefaultPolicy())
	}
}

func TestCandidate_Build_ConstructsUsableDecider(t *testing.T) {
	resolver := fakeCampaignResolver{}
	decider, err := BaselineCandidate().Build(resolver)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if decider == nil {
		t.Fatal("decider = nil, want a usable *engine.BehavioralDecider")
	}
}

// TestCandidate_Build_InvalidPolicy_ReturnsError confirma que un
// candidato con una Policy inválida falla en Build, no más adelante
// con un panic durante Replay.
func TestCandidate_Build_InvalidPolicy_ReturnsError(t *testing.T) {
	c := BaselineCandidate()
	c.Policy = engine.Policy{ChallengeThreshold: 0.8, BlockThreshold: 0.5}

	if _, err := c.Build(fakeCampaignResolver{}); err == nil {
		t.Fatal("Build() error = nil, want an error (challenge >= block)")
	}
}
