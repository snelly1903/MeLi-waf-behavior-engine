package datagen

import (
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// CredentialStuffingCampaign configura una campaña de credential
// stuffing distribuido. Los valores de DefaultCredentialStuffingCampaign
// son un punto de partida razonable para generar el dataset de prueba
// del challenge — NO son umbrales de detección: el motor (Fase 1) va a
// definir sus propios umbrales de forma independiente de cómo se generó
// este tráfico.
type CredentialStuffingCampaign struct {
	// Pool es la red simulada de la que salen las IPs atacantes — todas
	// del mismo ASN simulado, para que exista algo real que
	// correlacionar.
	Pool IPPool

	// IPCount es cuántas IPs distintas participan de la campaña. No
	// puede superar la capacidad del Pool (254 direcciones para un
	// /24; ver ipspace.go).
	IPCount int

	// MinAttemptsPerIP / MaxAttemptsPerIP acota cuántos intentos de
	// login hace cada IP en TODA la campaña — deliberadamente bajo,
	// para que ningún límite por IP individual lo detecte nunca.
	MinAttemptsPerIP, MaxAttemptsPerIP int

	// Window es la duración total de la campaña; cada intento cae en un
	// instante aleatorio dentro de esta ventana, no en ráfaga.
	Window time.Duration

	// LoginPath es el endpoint de login objetivo.
	LoginPath string

	// SuccessProbability es la probabilidad de que un intento sea
	// exitoso (200) en lugar de fallido (401/403).
	SuccessProbability float64

	// AccountReuseProbability es la probabilidad de que un intento
	// reutilice una cuenta ya probada antes en esta campaña, en lugar
	// de probar una cuenta nueva. Un valor bajo pero mayor a 0 es más
	// realista que una diversidad de cuentas del 100%: una lista de
	// credenciales filtrada real suele reciclarse parcialmente entre
	// bots.
	AccountReuseProbability float64

	// UserAgents es el pool de User-Agent que rota entre intentos —
	// mezclado a propósito (algunos parecen navegador normal, otros
	// claramente una herramienta de script), para que ningún único
	// User-Agent sea, por sí solo, una señal suficiente.
	UserAgents []string
}

// DefaultCredentialStuffingCampaign son los valores acordados para el
// dataset de prueba del challenge (ver docs/decisiones.md, tarea 0.5).
var DefaultCredentialStuffingCampaign = CredentialStuffingCampaign{
	Pool:                    PoolHostingSim,
	IPCount:                 150,
	MinAttemptsPerIP:        1,
	MaxAttemptsPerIP:        3,
	Window:                  3 * time.Hour,
	LoginPath:               DefaultLoginPath,
	SuccessProbability:      0.01,
	AccountReuseProbability: 0.05,
	UserAgents: []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15",
		"python-requests/2.31.0",
		"curl/8.4.0",
	},
}

// GenerateCredentialStuffingCampaign genera los eventos de una campaña
// de credential stuffing distribuido: cfg.IPCount IPs distintas del
// mismo ASN simulado, cada una con muy pocos intentos repartidos al
// azar en toda la ventana de la campaña, probando en su mayoría cuentas
// distintas. El resultado queda ordenado por Timestamp.
//
// A diferencia de GenerateLegitSession (tarea 0.4) y de
// GenerateSlowScanSession (esta misma tarea), acá no hay una "sesión"
// continua por IP: cada IP participa con 1 a 3 sondas aisladas, así que
// no hace falta un event.ManualClock que avance paso a paso — cada
// timestamp se calcula directo como un desplazamiento aleatorio dentro
// de start..start+cfg.Window, y después se ordena todo el conjunto.
func GenerateCredentialStuffingCampaign(rng *RNG, cfg CredentialStuffingCampaign, start time.Time) []groundtruth.LabeledEvent {
	ips := cfg.Pool.DistinctAddrs(rng, cfg.IPCount)

	var usedAccounts []string
	var events []groundtruth.LabeledEvent

	for _, ip := range ips {
		attempts := rng.IntRange(cfg.MinAttemptsPerIP, cfg.MaxAttemptsPerIP)

		// Si una misma IP tiene más de un intento, sus propios
		// timestamps quedan ordenados entre sí antes de generarlos.
		offsets := make([]time.Duration, attempts)
		for i := range offsets {
			offsets[i] = rng.DurationRange(0, cfg.Window)
		}
		sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })

		for _, offset := range offsets {
			var accountHash string
			if len(usedAccounts) > 0 && rng.Bool(cfg.AccountReuseProbability) {
				accountHash = Pick(rng, usedAccounts)
			} else {
				accountHash = rng.HexHash(64)
				usedAccounts = append(usedAccounts, accountHash)
			}

			// "Comportamiento variable": la enorme mayoría falla
			// (401), una porción de las fallidas se modela como 403
			// (cuenta bloqueada, firma de WAF, etc.), y una fracción
			// muy pequeña tiene éxito.
			status := 401
			if rng.Bool(cfg.SuccessProbability) {
				status = 200
			} else if rng.Bool(0.3) {
				status = 403
			}

			e := event.Event{
				RequestID:     rng.ID("r-"),
				Timestamp:     start.Add(offset),
				ClientIP:      ip,
				Method:        "POST",
				Path:          cfg.LoginPath,
				StatusCode:    status,
				UserAgent:     Pick(rng, cfg.UserAgents),
				LoginUserHash: accountHash,
			}
			events = append(events, groundtruth.LabeledEvent{Label: groundtruth.LabelCredentialStuffing, Event: e})
		}
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Event.Timestamp.Before(events[j].Event.Timestamp)
	})
	return events
}
