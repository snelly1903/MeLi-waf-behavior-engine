// Prueba la construcción de candidatos de configuración.
package tuning

import (
	"reflect"
	"testing"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
)

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

func TestCandidate_Build_InvalidPolicy_ReturnsError(t *testing.T) {
	c := BaselineCandidate()
	c.Policy = engine.Policy{ChallengeThreshold: 0.8, BlockThreshold: 0.5}

	if _, err := c.Build(fakeCampaignResolver{}); err == nil {
		t.Fatal("Build() error = nil, want an error (challenge >= block)")
	}
}
