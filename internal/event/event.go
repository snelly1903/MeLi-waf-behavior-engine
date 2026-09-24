// Package event define el contrato del evento HTTP: el único dato que el
// motor de detección puede ver sobre un request que ya ocurrió. Es el
// puerto de entrada de la arquitectura hexagonal — nada río arriba de
// este paquete (generador de tráfico, envío de logs, adaptador de WAF)
// puede entregarle al motor algo que no tenga esta forma, y nada río
// abajo (el motor, los detectores) puede ver más de lo que esta forma
// expone.
//
// Deliberadamente ausente de este paquete: cualquier noción de ground
// truth (la verdad conocida). Un Event nunca lleva una etiqueta como
// "legit" o "credential_stuffing" — eso vive en internal/groundtruth, un
// paquete que el motor nunca importa.
package event

import (
	"net/netip"
	"strings"
	"time"
)

// Event describe un request HTTP que ya ocurrió, tal como lo reporta lo
// que sea que esté delante del motor (el log de acceso de un servidor
// web, un WAF, un balanceador de carga). Solo RequestID, Timestamp,
// ClientIP, Method, Path y StatusCode son obligatorios — ver
// docs/formato-eventos.md para el porqué de mantener chico el conjunto
// de campos obligatorios.
type Event struct {
	// RequestID identifica este request de forma única. Es cómo el
	// evaluador (cmd/eval) cruza una decisión del motor con su etiqueta
	// de ground truth — nunca influye en la detección en sí misma.
	RequestID string `json:"request_id"`

	// Timestamp es cuándo ocurrió el request (event time), no cuándo lo
	// procesó el motor. La agregación por ventanas agrupa eventos por
	// este campo, de modo que un reloj simulado en el generador de
	// tráfico pueda comprimir horas de comportamiento de escaneo lento
	// en segundos de tiempo de prueba.
	Timestamp time.Time `json:"timestamp"`

	// ClientIP es la clave de entidad para los perfiles de
	// comportamiento por IP. Usar netip.Addr en lugar de un string
	// simple hace que una dirección mal formada falle al deserializar
	// antes incluso de que corra la validación, y que las comparaciones
	// y los usos como clave de mapa más adelante sean baratos y sin
	// asignaciones de memoria extra.
	ClientIP netip.Addr `json:"client_ip"`

	// SessionID es la clave de entidad para los perfiles de
	// comportamiento por sesión. Es opcional: muchos bots y clientes de
	// API nunca la traen, y forzar un valor inventado ensuciaría el
	// análisis por sesión en lugar de dejarlo honestamente ausente.
	SessionID string `json:"session_id,omitempty"`

	// Method es el método HTTP tal como llegó. Deliberadamente no está
	// restringido a la lista clásica de verbos (ver
	// docs/formato-eventos.md) — un método inusual es en sí mismo una
	// señal que un detector puede querer usar más adelante, no algo que
	// el contrato deba filtrar.
	Method string `json:"method"`

	// Path es la ruta del request, sin incluir nunca la cadena de
	// parámetros.
	Path string `json:"path"`

	// QueryParams guarda solo los *nombres* de los parámetros, nunca
	// sus valores. Un valor puede llevar datos sensibles (un número de
	// tarjeta, un token); el detector de escaneo lento solo necesita
	// saber cuántos nombres de parámetro distintos probó una entidad.
	QueryParams []string `json:"query_params,omitempty"`

	// StatusCode es el estado de la respuesta HTTP. Es el campo más
	// importante de todo el contrato: tanto el ratio de 401/403
	// (credential stuffing) como el ratio de 404 (escaneo lento) salen
	// de acá, y ninguna de las dos señales existe sin este dato.
	StatusCode int `json:"status_code"`

	// UserAgent es el User-Agent declarado por el cliente, si lo hay.
	UserAgent string `json:"user_agent,omitempty"`

	// Referer es el header Referer, si lo hay. Su ausencia es en sí
	// misma una señal para el detector de escaneo lento.
	Referer string `json:"referer,omitempty"`

	// LoginUserHash identifica qué cuenta intentó usar un login,
	// disfrazada detrás de un hash con clave (HMAC) calculado por quien
	// produce el evento. Nunca es un email o nombre de usuario en
	// claro — ver docs/formato-eventos.md para el formato y la
	// justificación de privacidad.
	LoginUserHash string `json:"login_user_hash,omitempty"`
}

// Normalize devuelve una copia de e con los espacios en blanco al
// principio y al final recortados de sus campos de texto, y cualquier
// campo que esté presente pero compuesto solo por espacios convertido en
// "" (tratado como "no provisto" en vez de como un error). Normalize
// nunca modifica e ni rechaza nada — eso es trabajo de Validator, no de
// este método.
func (e Event) Normalize() Event {
	n := e
	n.RequestID = strings.TrimSpace(e.RequestID)
	n.SessionID = trimToEmpty(e.SessionID)
	n.Method = strings.TrimSpace(e.Method)
	n.UserAgent = trimToEmpty(e.UserAgent)
	n.Referer = trimToEmpty(e.Referer)
	n.LoginUserHash = trimToEmpty(e.LoginUserHash)
	if e.QueryParams != nil {
		params := make([]string, 0, len(e.QueryParams))
		for _, p := range e.QueryParams {
			if p = strings.TrimSpace(p); p != "" {
				params = append(params, p)
			}
		}
		n.QueryParams = params
	}
	return n
}

// trimToEmpty recorta espacios en blanco y convierte un string compuesto
// solo por espacios en "", así un campo como "   " se trata igual que un
// campo ausente.
func trimToEmpty(s string) string {
	if trimmed := strings.TrimSpace(s); trimmed != "" {
		return trimmed
	}
	return ""
}
