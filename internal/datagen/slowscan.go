package datagen

import (
	"net/netip"
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// SlowScanProfile configura una sesión de escaneo lento. Los valores de
// DefaultSlowScanProfile son un punto de partida razonable para el
// dataset de prueba del challenge — NO son umbrales de detección.
type SlowScanProfile struct {
	// Pool es la red simulada de la que salen las IPs escaneadoras.
	Pool IPPool

	// MinRequests / MaxRequests acota cuántos requests hace una sesión
	// de escaneo.
	MinRequests, MaxRequests int

	// MinGap / MaxGap acota el tiempo entre un request y el siguiente —
	// deliberadamente largo, para representar delays aleatorios, no una
	// ráfaga.
	MinGap, MaxGap time.Duration

	// SensitivePaths es el vocabulario "tipo wordlist" del que sale la
	// mayoría de las rutas pedidas — rutas que ningún perfil legítimo
	// visita jamás (ver paths.go y paths_test.go).
	SensitivePaths []string

	// ValidPaths es un pequeño subconjunto de rutas REALES de la
	// aplicación (tomadas de los perfiles legítimos) que el escáner
	// visita con probabilidad ValidPathProbability, en lugar de una
	// ruta del wordlist — así el escáner no es "100% rutas
	// desconocidas", que sería una señal artificialmente fácil.
	ValidPaths []string

	// ValidPathProbability es la probabilidad de que un request del
	// escáner apunte a una ruta real en vez de una sensible.
	ValidPathProbability float64

	// FuzzParams son los nombres de parámetro (nunca valores — ver
	// docs/formato-eventos.md) que se agregan a algunos requests contra
	// rutas válidas.
	FuzzParams []string

	// FuzzParamProbability es la probabilidad de que un request contra
	// una ruta válida lleve parámetros fuzzeados.
	FuzzParamProbability float64

	// UserAgents es el pool de User-Agent que rota entre requests —
	// mezclado a propósito (alguno se hace pasar por navegador, otros
	// claramente son herramientas de script).
	UserAgents []string

	// Methods son los métodos HTTP posibles cuando se activa la
	// diversidad de métodos (ver MethodDiversityProbability); casi
	// siempre el método es GET.
	Methods                    []string
	MethodDiversityProbability float64
}

// DefaultValidScanPaths reutiliza las rutas reales de ProfileNavegante
// (tarea 0.4), más el login, para que el escáner a veces "pise" rutas
// legítimas de la misma aplicación que navegan los usuarios reales, en
// lugar de un catálogo de rutas válidas inventado aparte.
var DefaultValidScanPaths = append([]string{DefaultLoginPath}, ProfileNavegante.Paths...)

// DefaultSlowScanProfile son los valores acordados para el dataset de
// prueba del challenge (ver docs/decisiones.md, tarea 0.5).
var DefaultSlowScanProfile = SlowScanProfile{
	Pool:                 PoolHostingSim,
	MinRequests:          20,
	MaxRequests:          60,
	MinGap:               20 * time.Second,
	MaxGap:               3 * time.Minute,
	SensitivePaths:       SensitivePaths,
	ValidPaths:           DefaultValidScanPaths,
	ValidPathProbability: 0.15,
	FuzzParams:           FuzzParams,
	FuzzParamProbability: 0.20,
	UserAgents: []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", // se hace pasar por navegador
		"python-requests/2.31.0",
		"Go-http-client/1.1",
		"Mozilla/5.0 (compatible; scanner/1.0)",
	},
	Methods:                    []string{"GET", "GET", "GET", "GET", "HEAD", "OPTIONS"},
	MethodDiversityProbability: 0.08,
}

// GenerateSlowScanSession genera la secuencia de eventos de un único
// escáner, empezando en start, reutilizando el mismo patrón de sesión
// continua con event.ManualClock que GenerateLegitSession (tarea 0.4):
// acá sí hace falta un reloj que avance paso a paso, porque, a
// diferencia del credential stuffing, esto es una única entidad
// explorando de forma continua a lo largo del tiempo, no sondas
// aisladas.
func GenerateSlowScanSession(rng *RNG, profile SlowScanProfile, start time.Time, clientIP netip.Addr) []groundtruth.LabeledEvent {
	clock := event.NewManualClock(start)
	requestCount := rng.IntRange(profile.MinRequests, profile.MaxRequests)

	var events []groundtruth.LabeledEvent
	for i := 0; i < requestCount; i++ {
		var path string
		var status int
		var params []string

		if rng.Bool(profile.ValidPathProbability) {
			path = Pick(rng, profile.ValidPaths)
			status = 200
			if rng.Bool(profile.FuzzParamProbability) {
				n := rng.IntRange(1, 3)
				params = make([]string, 0, n)
				for j := 0; j < n; j++ {
					params = append(params, Pick(rng, profile.FuzzParams))
				}
			}
		} else {
			path = Pick(rng, profile.SensitivePaths)
			status = 404
		}

		method := "GET"
		if rng.Bool(profile.MethodDiversityProbability) {
			method = Pick(rng, profile.Methods)
		}

		e := event.Event{
			RequestID:   rng.ID("r-"),
			Timestamp:   clock.Now(),
			ClientIP:    clientIP,
			Method:      method,
			Path:        path,
			QueryParams: params,
			StatusCode:  status,
			UserAgent:   Pick(rng, profile.UserAgents),
		}
		events = append(events, groundtruth.LabeledEvent{Label: groundtruth.LabelSlowScan, Event: e})
		clock.Advance(rng.DurationRange(profile.MinGap, profile.MaxGap))
	}

	return events
}

// GenerateSlowScanCampaign genera scanners escáneres independientes
// (IPs distintas, sin correlación entre sí — a diferencia del
// credential stuffing, la señal del escaneo lento es por entidad
// individual, no agregada entre IPs), cada uno con su propio horario de
// inicio dentro de startJitter respecto de campaignStart. El resultado
// queda ordenado por Timestamp.
func GenerateSlowScanCampaign(rng *RNG, profile SlowScanProfile, scanners int, campaignStart time.Time, startJitter time.Duration) []groundtruth.LabeledEvent {
	ips := profile.Pool.DistinctAddrs(rng, scanners)

	var all []groundtruth.LabeledEvent
	for _, ip := range ips {
		scannerStart := campaignStart.Add(rng.DurationRange(0, startJitter))
		all = append(all, GenerateSlowScanSession(rng, profile, scannerStart, ip)...)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Event.Timestamp.Before(all[j].Event.Timestamp)
	})
	return all
}
