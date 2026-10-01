// Define los candidatos de configuración del motor y cómo construir su decisor.
package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

type Candidate struct {
	Name string

	CredentialStuffing credstuffing.Config
	SlowScan           slowscan.Config
	Anomaly            anomaly.Config
	Policy             engine.Policy
}

func BaselineCandidate() Candidate {
	return Candidate{
		Name:               "baseline",
		CredentialStuffing: engine.DefaultCredentialStuffingConfig(),
		SlowScan:           engine.DefaultSlowScanConfig(),
		Anomaly:            engine.DefaultAnomalyConfig(),
		Policy:             engine.DefaultPolicy(),
	}
}

func (c Candidate) Build(resolver credstuffing.NetworkResolver) (*engine.BehavioralDecider, error) {
	csCfg := c.CredentialStuffing
	csCfg.Resolver = resolver
	cs, err := credstuffing.NewDetector(csCfg)
	if err != nil {
		return nil, fmt.Errorf("tuning: candidate %q: credential stuffing detector: %w", c.Name, err)
	}

	ss, err := slowscan.NewDetector(c.SlowScan)
	if err != nil {
		return nil, fmt.Errorf("tuning: candidate %q: slow scan detector: %w", c.Name, err)
	}

	an, err := anomaly.NewDetector(c.Anomaly)
	if err != nil {
		return nil, fmt.Errorf("tuning: candidate %q: anomaly detector: %w", c.Name, err)
	}

	decider, err := engine.NewBehavioralDecider(cs, ss, an, c.Policy, nil)
	if err != nil {
		return nil, fmt.Errorf("tuning: candidate %q: behavioral decider: %w", c.Name, err)
	}
	return decider, nil
}
