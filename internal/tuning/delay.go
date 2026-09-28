package tuning

import (
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/credstuffing"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/eval"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// CampaignDelay resume, para UNA campaña de ataque, cuántos requests
// (y cuánto tiempo) hicieron falta hasta la primera decisión positiva
// — nunca para ocultar un falso negativo inicial: TotalRequests y
// Detected siempre quedan visibles, incluso cuando Detected es false
// (ver docs/decisiones.md, tarea 1.9, "No uses estas métricas para
// ocultar false negatives iniciales").
type CampaignDelay struct {
	Vector      groundtruth.Label
	CampaignKey string

	// TotalRequests es cuántos requests tuvo esta campaña en total,
	// detectados o no.
	TotalRequests int

	FirstEventAt time.Time

	// Detected es si ALGÚN request de esta campaña recibió alguna vez
	// una decisión positiva (según policy) — "eventual campaign
	// detection". Si es false, RequestsToDetection y TimeToDetection
	// no tienen ningún valor válido (quedan en su cero, nunca se leen).
	Detected bool

	// RequestsToDetection es la posición (1-indexada, dentro de ESTA
	// campaña, no del escenario completo) del primer request que
	// recibió una decisión positiva. Solo válido si Detected.
	RequestsToDetection int

	// TimeToDetection es cuánto tiempo pasó entre el primer evento de
	// la campaña y el primero detectado. Solo válido si Detected.
	TimeToDetection time.Duration
}

// campaignKey decide la clave de agrupación de un evento malicioso
// según su vector — nunca la misma regla para los dos ataques,
// porque no se corresponden con la misma entidad real (tarea 1.9,
// ajuste 1):
//
//   - slow_scan: la entidad que escanea, igual que
//     internal/slowscan.Detector la ve (sesión si existe, si no la
//     IP) — cada escáner es su propia campaña.
//   - credential_stuffing: el grupo de red (ASN simulado) al que
//     resuelve la IP, exactamente como lo ve
//     internal/credstuffing.Detector — el detector correlaciona por
//     grupo, nunca por IP individual, así que medir el delay por IP
//     sería conceptualmente incorrecto: todas las IPs de la misma
//     campaña distribuida comparten una sola campaña.
//
// ok=false cuando la IP no se pudo resolver a ningún grupo (solo
// puede pasar para credential_stuffing, con una IP fuera de los
// pools simulados conocidos) — ese evento no se cuenta en ninguna
// campaña, nunca se inventa una.
func campaignKey(label groundtruth.Label, e event.Event, resolver credstuffing.NetworkResolver) (string, bool) {
	switch label {
	case groundtruth.LabelCredentialStuffing:
		group, ok := resolver.Resolve(e.ClientIP)
		if !ok {
			return "", false
		}
		return "network:" + group, true
	case groundtruth.LabelSlowScan:
		if e.SessionID != "" {
			return "session:" + e.SessionID, true
		}
		return "ip:" + e.ClientIP.String(), true
	default:
		return "", false
	}
}

// campaignState es el acumulador mutable por campaña mientras se
// recorren los eventos en orden — nunca se expone, CampaignDelay es
// la vista de solo lectura que sí se devuelve.
type campaignState struct {
	vector              groundtruth.Label
	firstEventAt        time.Time
	requestsSeen        int
	detected            bool
	requestsToDetection int
	timeToDetection     time.Duration
}

// ComputeDetectionDelay agrupa events (con su Label) y decisions —
// deben venir en el mismo orden y con la misma longitud que produjo
// Replay, ya que se cruzan por índice, no por RequestID — en
// campañas según campaignKey, y calcula cuántos requests (y cuánto
// tiempo) hizo falta ver hasta la primera decisión positiva de cada
// una. policy decide qué acción cuenta como positiva — mismo criterio
// que BuildConfusionMatrix (Policy.IsPositive, tarea 1.9), para que
// "detectado" signifique exactamente lo mismo en ambos lados del
// reporte.
//
// El tráfico legítimo (groundtruth.LabelLegit) nunca forma una
// campaña — solo tiene sentido medir delay de detección para tráfico
// que sí es un ataque real. El resultado queda ordenado por
// CampaignKey para que sea determinista.
func ComputeDetectionDelay(events []groundtruth.LabeledEvent, decisions []decision.Decision, resolver credstuffing.NetworkResolver, policy eval.Policy) []CampaignDelay {
	states := make(map[string]*campaignState)
	var order []string

	for i, le := range events {
		if le.Label == groundtruth.LabelLegit {
			continue
		}
		key, ok := campaignKey(le.Label, le.Event, resolver)
		if !ok {
			continue
		}

		st, exists := states[key]
		if !exists {
			st = &campaignState{vector: le.Label, firstEventAt: le.Event.Timestamp}
			states[key] = st
			order = append(order, key)
		}
		st.requestsSeen++

		if !st.detected && policy.IsPositive(decisions[i].Action) {
			st.detected = true
			st.requestsToDetection = st.requestsSeen
			st.timeToDetection = le.Event.Timestamp.Sub(st.firstEventAt)
		}
	}

	sort.Strings(order)
	result := make([]CampaignDelay, 0, len(order))
	for _, key := range order {
		st := states[key]
		cd := CampaignDelay{
			Vector:        st.vector,
			CampaignKey:   key,
			TotalRequests: st.requestsSeen,
			FirstEventAt:  st.firstEventAt,
			Detected:      st.detected,
		}
		if st.detected {
			cd.RequestsToDetection = st.requestsToDetection
			cd.TimeToDetection = st.timeToDetection
		}
		result = append(result, cd)
	}
	return result
}
