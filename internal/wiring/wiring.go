// Package wiring arma el stack real del motor (los tres detectores
// conductuales + BehavioralDecider + httpapi.Server) a partir de
// flags/parámetros — la MISMA construcción que usa cmd/engine en
// producción, extraída acá para que también la use cmd/loadtest y
// los microbenchmarks de internal/engine, sin duplicar ni un valor
// de configuración. FinalConfigs()/FinalPolicy() son la ÚNICA fuente
// de verdad de la configuración RUNTIME final congelada tras el
// holdout — antes de esto, cmd/engine servía engine.Default*Config()
// sin calibrar mientras internal/tuning/cmd/holdout ya evaluaba con
// otra configuración: cmd/engine y cmd/loadtest ahora consumen
// exactamente lo mismo.
package wiring

import (
	"fmt"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/anomaly"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/asn"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/engine"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/httpapi"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/slowscan"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/telemetry"
)

// Nombres válidos de --asn-provider.
const (
	ASNProviderNone     = "none"
	ASNProviderRIPEStat = "ripestat"
)

// FinalConfigs es la configuración RUNTIME final de los tres
// detectores — la ÚNICA fuente de verdad, congelada tras el holdout
// (checkpoint pre-holdout, commit 6abed47): credential_stuffing CSw2
// (Window=90m, MinDistinctIPs=16), slow_scan S3
// (MaxVisitorsForNovelPath=3, MinNovelPathRatio=0.35),
// statistical_anomaly A3 (AccountDiversityWeight=0.5) — el resto de
// cada Config, incluido ScoreFloor, es el default sin tocar
// (engine.Default*Config()). cmd/engine (producción) y cmd/loadtest
// (medición de performance) consumen EXACTAMENTE esto — antes
// cmd/engine servía engine.Default*Config() sin calibrar, mientras
// internal/tuning/cmd/holdout ya evaluaba con esta configuración:
// este helper cierra esa brecha, sin cambiar ni un valor (nunca es
// un re-tuning, es wiring de lo ya decidido). La configuración
// BASELINE (sin ningún override) sigue viviendo EXCLUSIVAMENTE en
// internal/engine.Default*Config(), consumida directamente por
// internal/tuning.BaselineCandidate() para evaluación/comparación —
// internal/wiring nunca la expone como su propio default.
func FinalConfigs() (credstuffing.Config, slowscan.Config, anomaly.Config) {
	cs := engine.DefaultCredentialStuffingConfig()
	cs.Window = 90 * time.Minute
	cs.MinDistinctIPs = 16

	ss := engine.DefaultSlowScanConfig()
	ss.MaxVisitorsForNovelPath = 3
	ss.MinNovelPathRatio = 0.35

	an := engine.DefaultAnomalyConfig()
	an.Weights.AccountDiversity = 0.5

	return cs, ss, an
}

// FinalPolicy es la Policy final congelada tras el holdout:
// ChallengeThreshold=0.50, BlockThreshold=0.75. ScoreFloor no es
// parte de Policy (vive en cada Config de detector, ver
// FinalConfigs) y nunca se tocó durante el holdout.
func FinalPolicy() engine.Policy {
	return engine.Policy{ChallengeThreshold: 0.50, BlockThreshold: 0.75}
}

// Los vars de paquete son la configuración que BuildDecider/
// BuildServer (usados por cmd/engine) sirven por default —
// inicializados desde FinalConfigs(), nunca desde
// engine.Default*Config() directamente, para que cmd/engine y
// cmd/loadtest consuman la MISMA fuente de verdad. Acá solo falta
// completar credentialStuffingConfig.Resolver, que se hace en
// BuildDecider con credstuffing.UnavailableNetworkResolver o
// internal/asn.Resolver según el proveedor de ASN pedido — es la
// única pieza que cambia entre producción y evaluación/medición
// offline.
var credentialStuffingConfig, slowScanConfig, anomalyConfig = FinalConfigs()

// BuildCredentialStuffingResolver arma el credstuffing.NetworkResolver
// según provider. Ver docs/decisiones.md para el porqué de las
// alternativas descartadas, y para "ripestat". "none" (default
// seguro) nunca hace tráfico de salida a Internet.
func BuildCredentialStuffingResolver(provider string, timeout time.Duration, successTTL time.Duration, metrics asn.MetricsRecorder) (credstuffing.NetworkResolver, error) {
	switch provider {
	case "", ASNProviderNone:
		return credstuffing.UnavailableNetworkResolver{}, nil
	case ASNProviderRIPEStat:
		return asn.NewResolver(asn.Config{
			BaseURL:               asn.DefaultBaseURL,
			SourceApp:             "meli-waf-behavior-engine-challenge",
			Timeout:               timeout,
			MaxConcurrentRequests: 5,
			SuccessTTL:            successTTL,
			FailureTTL:            5 * time.Minute,
			Metrics:               metrics,
		})
	default:
		return nil, fmt.Errorf("wiring: unknown ASN provider %q (want %q or %q)", provider, ASNProviderNone, ASNProviderRIPEStat)
	}
}

// BuildDecider arma un *engine.BehavioralDecider real, con los tres
// detectores y la Policy configurada — sin la capa HTTP encima. Es
// lo que usan los microbenchmarks de internal/engine, que miden
// Decide() directamente. recorders es opcional: nil es válido y
// significa "sin telemetría" — cada detector ya sabe degradar a un
// recorder no-op por su cuenta.
func BuildDecider(challengeThreshold, blockThreshold float64, asnProvider string, asnTimeout, asnCacheTTL time.Duration, recorders *telemetry.Recorders) (*engine.BehavioralDecider, error) {
	var asnRecorder asn.MetricsRecorder
	if recorders != nil {
		asnRecorder = recorders.ASN
	}

	resolver, err := BuildCredentialStuffingResolver(asnProvider, asnTimeout, asnCacheTTL, asnRecorder)
	if err != nil {
		return nil, err
	}
	return BuildDeciderWithResolver(challengeThreshold, blockThreshold, resolver, recorders)
}

// BuildDeciderWithResolver es la misma construcción que BuildDecider,
// pero recibe el credstuffing.NetworkResolver YA CONSTRUIDO en vez de
// elegirlo por nombre de proveedor — pensado para cmd/loadtest, que
// necesita el resolver DETERMINISTA de
// internal/datagen.NewSimulatedASNResolver() para ejercitar la
// correlación real de credential_stuffing sin tocar la red (ni
// "none", que lo dejaría estructuralmente inerte, ni "ripestat", que
// mediría latencia de Internet). internal/wiring nunca importa
// internal/datagen directamente — eso mezclaría producción con un
// generador de datos de prueba — así que quien llama es responsable
// de construir el resolver que corresponda. Usa los tres Config de
// FinalConfigs() (los vars de paquete) — la MISMA configuración final
// que sirve cmd/engine — ver BuildDeciderWithConfigs para pasar
// Config explícitos distintos (por ejemplo, la configuración
// BASELINE de engine.Default*Config(), si algún día hiciera falta
// comparar performance baseline-vs-final).
func BuildDeciderWithResolver(challengeThreshold, blockThreshold float64, resolver credstuffing.NetworkResolver, recorders *telemetry.Recorders) (*engine.BehavioralDecider, error) {
	return BuildDeciderWithConfigs(credentialStuffingConfig, slowScanConfig, anomalyConfig, challengeThreshold, blockThreshold, resolver, recorders)
}

// BuildDeciderWithConfigs es el constructor más explícito: los tres
// Config de detector se reciben como parámetro, nunca desde los vars
// de paquete ni desde FinalConfigs() — disponible para quien
// necesite construir con una configuración DISTINTA de la final
// (por ejemplo, BASELINE, para una comparación de performance que
// todavía no se pidió). cmd/engine y cmd/loadtest usan
// BuildDecider/BuildServer y BuildDeciderWithResolver/
// BuildServerWithResolver — que ya sirven FinalConfigs() por
// default — no esta función directamente.
func BuildDeciderWithConfigs(csCfg credstuffing.Config, ssCfg slowscan.Config, anCfg anomaly.Config, challengeThreshold, blockThreshold float64, resolver credstuffing.NetworkResolver, recorders *telemetry.Recorders) (*engine.BehavioralDecider, error) {
	var engineRecorder engine.FindingsRecorder
	if recorders != nil {
		engineRecorder = recorders.Engine
	}

	csCfg.Resolver = resolver
	csDetector, err := credstuffing.NewDetector(csCfg)
	if err != nil {
		return nil, fmt.Errorf("wiring: credential stuffing detector: %w", err)
	}

	ssDetector, err := slowscan.NewDetector(ssCfg)
	if err != nil {
		return nil, fmt.Errorf("wiring: slow scan detector: %w", err)
	}

	anomalyDetector, err := anomaly.NewDetector(anCfg)
	if err != nil {
		return nil, fmt.Errorf("wiring: anomaly detector: %w", err)
	}

	policy := engine.Policy{ChallengeThreshold: challengeThreshold, BlockThreshold: blockThreshold}
	return engine.NewBehavioralDecider(csDetector, ssDetector, anomalyDetector, policy, engineRecorder)
}

// BuildServer arma el *httpapi.Server real — BuildDecider envuelto
// en la capa HTTP (validación + routing). Es lo que usa cmd/engine en
// producción.
func BuildServer(challengeThreshold, blockThreshold float64, asnProvider string, asnTimeout, asnCacheTTL time.Duration, recorders *telemetry.Recorders) (*httpapi.Server, error) {
	decider, err := BuildDecider(challengeThreshold, blockThreshold, asnProvider, asnTimeout, asnCacheTTL, recorders)
	if err != nil {
		return nil, err
	}
	return wrapServer(decider, recorders), nil
}

// BuildServerWithResolver es el equivalente de BuildServer para
// cmd/loadtest: recibe el resolver ya construido, ver
// BuildDeciderWithResolver.
func BuildServerWithResolver(challengeThreshold, blockThreshold float64, resolver credstuffing.NetworkResolver, recorders *telemetry.Recorders) (*httpapi.Server, error) {
	decider, err := BuildDeciderWithResolver(challengeThreshold, blockThreshold, resolver, recorders)
	if err != nil {
		return nil, err
	}
	return wrapServer(decider, recorders), nil
}

// BuildServerWithConfigs es el equivalente de BuildServer con los
// tres Config explícitos — ver BuildDeciderWithConfigs. Es lo que usa
// cmd/loadtest para medir la configuración FINAL congelada tras el
// holdout, nunca los defaults sin calibrar.
func BuildServerWithConfigs(csCfg credstuffing.Config, ssCfg slowscan.Config, anCfg anomaly.Config, challengeThreshold, blockThreshold float64, resolver credstuffing.NetworkResolver, recorders *telemetry.Recorders) (*httpapi.Server, error) {
	decider, err := BuildDeciderWithConfigs(csCfg, ssCfg, anCfg, challengeThreshold, blockThreshold, resolver, recorders)
	if err != nil {
		return nil, err
	}
	return wrapServer(decider, recorders), nil
}

func wrapServer(decider *engine.BehavioralDecider, recorders *telemetry.Recorders) *httpapi.Server {
	var httpRecorder httpapi.DecisionRecorder
	if recorders != nil {
		httpRecorder = recorders.HTTP
	}
	validator := event.NewValidator(event.SystemClock{})
	return httpapi.NewServer(validator, decider, httpRecorder)
}
