// Package asn implementa un credstuffing.NetworkResolver real,
// consultando RIPEstat (RIPE NCC) para mapear una IP a su ASN — el
// enriquecimiento real de IP que exige el challenge. internal/asn
// nunca importa internal/credstuffing: Resolver satisface la
// interfaz NetworkResolver (Resolve(ip netip.Addr) (string, bool))
// por tipado estructural de Go, no por herencia explícita — el
// detector nunca sabe qué proveedor hay detrás.
//
// Fuente de datos: https://stat.ripe.net/data/network-info/,
// gratuita y sin API key (nada que hardcodear como secreto). Es una
// fuente apropiada para este challenge/prototipo — RIPE NCC es uno de
// los cinco Regional Internet Registries reales, no un scraper de
// terceros —, pero sus términos de uso actuales restringen ciertos
// usos comerciales sin permiso explícito
// (https://www.ripe.net/support/legal/terms/); NO se presenta acá
// como el proveedor definitivo de un despliegue de producción, sino
// como la fuente pública/gratuita razonable para demostrar el
// enriquecimiento real en esta etapa. Cambiar de proveedor más
// adelante es reemplazar este archivo, no tocar
// internal/credstuffing ni internal/engine.
//
// Advertencia de diseño, documentada explícitamente: este Resolver
// hace un lookup remoto SÍNCRONO dentro del camino de cada request
// (credstuffing.Detector.Observe lo llama directamente). Es aceptable
// para este prototipo — el caché agresivo (ver cacheEntry) absorbe la
// gran mayoría de las consultas repetidas —, pero NO sería el diseño
// correcto para tráfico masivo con muchas IPs nunca vistas: ahí
// haría falta resolver de forma asíncrona (una cola, un enriquecimiento
// diferido que no bloquee la decisión inicial) en vez de esperar la
// respuesta de un tercero dentro del camino síncrono de cada
// request.
package asn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

// DefaultBaseURL es el endpoint de RIPEstat que este Resolver
// consulta por defecto.
const DefaultBaseURL = "https://stat.ripe.net/data/network-info/data.json"

// Config configura el Resolver.
type Config struct {
	// BaseURL es el endpoint a consultar — configurable para que los
	// tests puedan apuntar a un httptest.Server en vez de a RIPEstat
	// real. Nunca hardcodeado dentro de este paquete.
	BaseURL string

	// SourceApp identifica a este proyecto ante RIPEstat, según su
	// propia guía de uso (parámetro sourceapp) — para que un uso
	// regular/automatizado quede identificable, no anónimo. No es un
	// secreto: es solo un nombre.
	SourceApp string

	// Timeout acota el tiempo TOTAL de Resolve — incluyendo el tiempo
	// que pueda pasar esperando un cupo del límite de concurrencia
	// (ver MaxConcurrentRequests) y la llamada HTTP en sí. Si el
	// plazo se consume esperando cupo, Resolve devuelve ("", false)
	// sin haber llegado a hacer ninguna petición de red. Debe ser
	// mayor que 0.
	Timeout time.Duration

	// MaxConcurrentRequests acota cuántas consultas HTTP a RIPEstat
	// puede haber en vuelo al mismo tiempo — buena práctica hacia un
	// servicio público gratuito, y protección contra una ráfaga de
	// IPs nunca vistas (por ejemplo, un ataque real) disparando
	// muchas llamadas simultáneas. Debe ser mayor que 0.
	MaxConcurrentRequests int

	// SuccessTTL es cuánto se cachea una resolución exitosa. Un ASN
	// real cambia rara vez — puede ser largo (horas).
	SuccessTTL time.Duration

	// FailureTTL es cuánto se cachea un fallo (caché negativo) — más
	// corto que SuccessTTL, para no reintentar en cada request contra
	// un proveedor caído, pero sí reintentar razonablemente pronto
	// cuando vuelva.
	FailureTTL time.Duration

	// Clock provee el "ahora" para el TTL del caché — reutiliza
	// event.Clock (tarea 0.2) en vez de otra interfaz de reloj más.
	// Si es nil, se usa event.SystemClock{}.
	Clock event.Clock

	// HTTPClient es el cliente HTTP a usar. Si es nil, se construye
	// uno por defecto. Inyectable para tests.
	HTTPClient *http.Client
}

// Errores centinela de configuración, comprobables individualmente
// con errors.Is.
var (
	ErrInvalidBaseURL               = errors.New("asn: base_url is required")
	ErrInvalidSourceApp             = errors.New("asn: source_app is required")
	ErrInvalidTimeout               = errors.New("asn: timeout must be greater than 0")
	ErrInvalidMaxConcurrentRequests = errors.New("asn: max_concurrent_requests must be greater than 0")
	ErrInvalidSuccessTTL            = errors.New("asn: success_ttl must be greater than 0")
	ErrInvalidFailureTTL            = errors.New("asn: failure_ttl must be greater than 0")
)

// Validate comprueba que cfg tenga valores utilizables.
func (cfg Config) Validate() error {
	var errs []error
	if strings.TrimSpace(cfg.BaseURL) == "" {
		errs = append(errs, ErrInvalidBaseURL)
	}
	if strings.TrimSpace(cfg.SourceApp) == "" {
		errs = append(errs, ErrInvalidSourceApp)
	}
	if cfg.Timeout <= 0 {
		errs = append(errs, ErrInvalidTimeout)
	}
	if cfg.MaxConcurrentRequests <= 0 {
		errs = append(errs, ErrInvalidMaxConcurrentRequests)
	}
	if cfg.SuccessTTL <= 0 {
		errs = append(errs, ErrInvalidSuccessTTL)
	}
	if cfg.FailureTTL <= 0 {
		errs = append(errs, ErrInvalidFailureTTL)
	}
	return errors.Join(errs...)
}

// cacheEntry es lo que se retiene por IP: el resultado (positivo o
// negativo) y cuándo vence.
type cacheEntry struct {
	group     string
	ok        bool
	expiresAt time.Time
}

// Resolver implementa credstuffing.NetworkResolver consultando
// RIPEstat, con caché (positivo y negativo, con TTL) y un límite de
// concurrencia. Es seguro para uso concurrente.
type Resolver struct {
	cfg        Config
	httpClient *http.Client
	clock      event.Clock

	sem chan struct{}

	mu    sync.Mutex
	cache map[netip.Addr]cacheEntry
}

// NewResolver construye un Resolver. Devuelve error si cfg no es
// utilizable.
func NewResolver(cfg Config) (*Resolver, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	clock := cfg.Clock
	if clock == nil {
		clock = event.SystemClock{}
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Resolver{
		cfg:        cfg,
		httpClient: httpClient,
		clock:      clock,
		sem:        make(chan struct{}, cfg.MaxConcurrentRequests),
		cache:      make(map[netip.Addr]cacheEntry),
	}, nil
}

// networkInfoResponse es la forma mínima de la respuesta de RIPEstat
// que este Resolver necesita.
type networkInfoResponse struct {
	Status string `json:"status"`
	Data   struct {
		ASNs []string `json:"asns"`
	} `json:"data"`
}

// Resolve implementa credstuffing.NetworkResolver. Nunca bloquea más
// allá de cfg.Timeout en total — esa cota cubre tanto la espera de un
// cupo de concurrencia como la llamada HTTP.
func (r *Resolver) Resolve(ip netip.Addr) (string, bool) {
	if group, ok, found := r.cacheGet(ip); found {
		return group, ok
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
	defer cancel()

	if !r.acquire(ctx) {
		// El plazo se consumió esperando un cupo de concurrencia —
		// nunca se llegó a consultar a RIPEstat. No se cachea: esto
		// es contención local pasajera, no una respuesta real del
		// proveedor sobre esta IP, así que cachearlo podría suprimir
		// injustamente un reintento una vez que la contención baje.
		return "", false
	}
	defer r.release()

	group, ok := r.fetch(ctx, ip)
	r.cacheSet(ip, group, ok)
	return group, ok
}

// acquire toma un cupo del semáforo de concurrencia, o devuelve false
// si ctx se cancela (por el timeout) antes de conseguirlo.
func (r *Resolver) acquire(ctx context.Context) bool {
	select {
	case r.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (r *Resolver) release() {
	<-r.sem
}

// fetch hace la consulta HTTP real a RIPEstat y aplica la política de
// interpretación de la respuesta (ver el comentario de
// parseASNs).
func (r *Resolver) fetch(ctx context.Context, ip netip.Addr) (string, bool) {
	url := fmt.Sprintf("%s?resource=%s&sourceapp=%s", r.cfg.BaseURL, ip.String(), r.cfg.SourceApp)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}

	var parsed networkInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", false
	}
	if parsed.Status != "ok" {
		return "", false
	}

	return parseASNs(parsed.Data.ASNs)
}

// parseASNs aplica la política conservadora acordada: RIPEstat puede
// devolver más de un ASN para una IP (multi-homing) — en vez de
// elegir uno arbitrariamente (lo que inventaría una correlación de
// grupo que no está garantizada), este prototipo solo confía en el
// caso sin ambigüedad:
//
//	0 ASN        -> ("", false)
//	exactamente 1 -> ("asn:<numero>", true)
//	más de 1      -> ("", false)
func parseASNs(asns []string) (string, bool) {
	if len(asns) != 1 {
		return "", false
	}
	number := strings.TrimPrefix(strings.TrimPrefix(asns[0], "AS"), "as")
	number = strings.TrimSpace(number)
	if number == "" {
		return "", false
	}
	return "asn:" + number, true
}

func (r *Resolver) cacheGet(ip netip.Addr) (group string, ok, found bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.cache[ip]
	if !exists {
		return "", false, false
	}
	if r.clock.Now().After(entry.expiresAt) {
		delete(r.cache, ip)
		return "", false, false
	}
	return entry.group, entry.ok, true
}

func (r *Resolver) cacheSet(ip netip.Addr, group string, ok bool) {
	ttl := r.cfg.FailureTTL
	if ok {
		ttl = r.cfg.SuccessTTL
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[ip] = cacheEntry{group: group, ok: ok, expiresAt: r.clock.Now().Add(ttl)}
}

// Sweep elimina del caché cualquier entrada vencida respecto a now, y
// devuelve cuántas eliminó — mismo patrón que
// internal/profile.Store.Sweep, internal/credstuffing.Detector.Sweep
// e internal/anomaly.Detector.Sweep (tareas 1.2/1.3/1.6). now se
// recibe como parámetro (nunca time.Now() internamente), así que
// sigue siendo determinista y testeable. Conectarlo a un scheduler
// real queda fuera del alcance de esta tarea.
func (r *Resolver) Sweep(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	removed := 0
	for ip, entry := range r.cache {
		if now.After(entry.expiresAt) {
			delete(r.cache, ip)
			removed++
		}
	}
	return removed
}
