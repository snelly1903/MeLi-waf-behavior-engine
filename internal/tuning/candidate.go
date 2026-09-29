// Package tuning implementa la evaluación offline y la calibración
// del motor conductual: correr el *engine.BehavioralDecider real
// sobre un escenario generado por internal/datagen, medir su calidad
// con internal/eval, y comparar candidatos de configuración de forma
// reproducible.
//
// Este paquete nunca duplica infraestructura ya existente: reutiliza
// internal/datagen (generación y el resolver determinista de ASN),
// internal/baseline (LoadEvents/WriteDecisions, I/O genérico de
// eventos/decisiones — nunca fue específico del rate limit),
// internal/eval (matriz de confusión, políticas strict/broad, N/A
// real) e internal/engine (BehavioralDecider, Policy, y los valores
// por defecto en defaults.go).
package tuning

import (
	"fmt"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
)

// Candidate agrupa los cuatro "knobs" que este paquete calibra: la
// configuración de los tres detectores y la Policy. Deliberadamente
// NO incluye el NetworkResolver de credential stuffing — el resolver
// no es algo que se calibre, es fijo para toda la evaluación offline
// (SimulatedASNResolver, ver internal/datagen/asnresolver.go) y se
// pasa por separado a Build.
type Candidate struct {
	// Name identifica este candidato en los reportes — por ejemplo
	// "baseline", "anomaly-z2-t015". Nunca se usa para lógica, solo
	// para que los reportes sean legibles.
	Name string

	CredentialStuffing credstuffing.Config
	SlowScan           slowscan.Config
	Anomaly            anomaly.Config
	Policy             engine.Policy
}

// BaselineCandidate refleja EXACTAMENTE los valores por defecto de
// cmd/engine — nunca los repite a mano. Los tres Config y la Policy
// vienen de internal/engine.Default*Config()/DefaultPolicy(), el
// mismo lugar de verdad que usa cmd/engine/main.go: si alguien cambia
// un default de producción, BaselineCandidate lo refleja
// automáticamente, sin que nadie tenga que acordarse de actualizar
// esta evaluación también. Ver TestBaselineCandidate_MatchesEngineDefaults.
func BaselineCandidate() Candidate {
	return Candidate{
		Name:               "baseline",
		CredentialStuffing: engine.DefaultCredentialStuffingConfig(),
		SlowScan:           engine.DefaultSlowScanConfig(),
		Anomaly:            engine.DefaultAnomalyConfig(),
		Policy:             engine.DefaultPolicy(),
	}
}

// Build construye un *engine.BehavioralDecider nuevo a partir de c,
// con resolver como NetworkResolver de credential stuffing. "Nuevo"
// es la palabra clave: cada llamada crea sus propios
// credstuffing.Detector/slowscan.Detector/anomaly.Detector, cada uno
// con su propio internal/profile.Store y baseline vacíos — así cada
// corrida de evaluación arranca con estado limpio (profiles vacíos,
// baseline de anomaly vacío, sin necesitar ningún "reset" explícito;
// ver docs/decisiones.md, sección "Estado").
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

	// recorder=nil: BehavioralDecider degrada sola a un
	// FindingsRecorder no-op — esta evaluación offline nunca necesita
	// telemetría real.
	decider, err := engine.NewBehavioralDecider(cs, ss, an, c.Policy, nil)
	if err != nil {
		return nil, fmt.Errorf("tuning: candidate %q: behavioral decider: %w", c.Name, err)
	}
	return decider, nil
}
