// Construye el stack real del motor (detectores, decisor y servidor HTTP) con la configuración final.
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

const (
	ASNProviderNone     = "none"
	ASNProviderRIPEStat = "ripestat"
)

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

func FinalPolicy() engine.Policy {
	return engine.Policy{ChallengeThreshold: 0.50, BlockThreshold: 0.75}
}

var credentialStuffingConfig, slowScanConfig, anomalyConfig = FinalConfigs()

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

func BuildDeciderWithResolver(challengeThreshold, blockThreshold float64, resolver credstuffing.NetworkResolver, recorders *telemetry.Recorders) (*engine.BehavioralDecider, error) {
	return BuildDeciderWithConfigs(credentialStuffingConfig, slowScanConfig, anomalyConfig, challengeThreshold, blockThreshold, resolver, recorders)
}

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

func BuildServer(challengeThreshold, blockThreshold float64, asnProvider string, asnTimeout, asnCacheTTL time.Duration, recorders *telemetry.Recorders) (*httpapi.Server, error) {
	decider, err := BuildDecider(challengeThreshold, blockThreshold, asnProvider, asnTimeout, asnCacheTTL, recorders)
	if err != nil {
		return nil, err
	}
	return wrapServer(decider, recorders), nil
}

func BuildServerWithResolver(challengeThreshold, blockThreshold float64, resolver credstuffing.NetworkResolver, recorders *telemetry.Recorders) (*httpapi.Server, error) {
	decider, err := BuildDeciderWithResolver(challengeThreshold, blockThreshold, resolver, recorders)
	if err != nil {
		return nil, err
	}
	return wrapServer(decider, recorders), nil
}

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
