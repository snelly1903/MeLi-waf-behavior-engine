package datagen

import (
	"net/netip"
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

// LegitProfile describe cómo se comporta un tipo de usuario legítimo.
// Los tres perfiles predefinidos más abajo (ProfileNavegante,
// ProfileAPIClient, ProfileOffice) son instancias de este mismo struct
// con valores distintos — no hay una implementación de código separada
// por perfil, para no repetir tres veces la misma lógica de
// generación.
type LegitProfile struct {
	// Name identifica el perfil en los tests y en los reportes.
	Name string

	// Pool es de dónde sale la IP del usuario cuando quien llama a
	// GenerateLegitSession le pide a este pool una dirección nueva.
	Pool IPPool

	// UserAgents es el conjunto de User-Agent posibles para una sesión
	// de este perfil. Se elige uno solo al empezar la sesión y se
	// mantiene fijo durante toda ella — a diferencia de un atacante
	// (tarea 0.5), un usuario real no rota de navegador a mitad de
	// sesión.
	UserAgents []string

	// HasSession indica si el usuario manda session_id.
	HasSession bool

	// SendsReferer indica si el usuario manda el header Referer al
	// navegar entre páginas.
	SendsReferer bool

	// FetchesStaticAssets indica si, además de las páginas, el usuario
	// pide recursos estáticos (CSS, JS, imágenes) — algo que hace un
	// navegador real y normalmente no hace un cliente de API.
	FetchesStaticAssets bool

	// Paths son las páginas que este perfil navega. StaticAssets, si no
	// está vacío, son los recursos estáticos que pide después de cada
	// página (solo si FetchesStaticAssets es true).
	Paths        []string
	StaticAssets []string

	// LoginPath, si no es "", es la ruta de login que este perfil
	// visita ocasionalmente (ver LoginRetryProbability).
	LoginPath string

	// LoginRetryProbability es la probabilidad de que la sesión incluya
	// un intento de login fallido (401) seguido de un reintento
	// exitoso con la MISMA cuenta — un typo humano, no un ataque. La
	// diferencia clave con el credential stuffing (tarea 0.5) es
	// exactamente esa: acá se reintenta la misma cuenta; en el ataque,
	// cada intento prueba una cuenta distinta.
	LoginRetryProbability float64

	// BrokenLinkProbability es la probabilidad de que una visita a una
	// página cualquiera devuelva 404 en lugar de 200 — un link roto
	// legítimo. Es a propósito uno de los "casos difíciles" que pediste
	// cubrir: un ratio de 404 mayor a cero en tráfico legítimo es lo
	// que impide que la regla del detector de escaneo lento sea
	// simplemente "cualquier 404 es sospechoso".
	BrokenLinkProbability float64

	// MinRequests / MaxRequests acota cuántas páginas visita una sesión
	// de este perfil (sin contar los assets estáticos ni el login).
	MinRequests, MaxRequests int

	// MinGap / MaxGap acota el tiempo entre el fin de un request y el
	// comienzo del siguiente.
	MinGap, MaxGap time.Duration
}

var (
	// ProfileNavegante es el caso "normal": navega con referer, pide
	// assets estáticos, tiene sesión, y a veces se equivoca de
	// contraseña y reintenta con la misma cuenta, o llega a un link
	// roto.
	ProfileNavegante = LegitProfile{
		Name: "navegante",
		Pool: PoolResidentialSimA,
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
		},
		HasSession:            true,
		SendsReferer:          true,
		FetchesStaticAssets:   true,
		Paths:                 []string{"/", "/dashboard", "/products", "/products/42", "/account", "/help", "/settings"},
		StaticAssets:          []string{"/static/app.css", "/static/app.js", "/static/logo.png"},
		LoginPath:             "/login",
		LoginRetryProbability: 0.15,
		BrokenLinkProbability: 0.05,
		MinRequests:           5,
		MaxRequests:           15,
		MinGap:                2 * time.Second,
		MaxGap:                40 * time.Second,
	}

	// ProfileAPIClient es la "trampa" del escaneo lento: nunca manda
	// referer ni pide assets estáticos — lo mismo que haría un bot de
	// fuzzing — pero es tráfico completamente legítimo de una app móvil
	// o de un cliente de API.
	ProfileAPIClient = LegitProfile{
		Name: "api_client",
		Pool: PoolResidentialSimB,
		UserAgents: []string{
			"MeLiApp/4.12.0 (iOS 17.4; iPhone15,3)",
			"MeLiApp/4.12.0 (Android 14; Pixel8)",
		},
		HasSession:            false,
		SendsReferer:          false,
		FetchesStaticAssets:   false,
		Paths:                 []string{"/api/v1/products", "/api/v1/orders", "/api/v1/account", "/api/v1/orders/8831", "/api/v1/notifications"},
		LoginPath:             "/api/login",
		LoginRetryProbability: 0.05,
		BrokenLinkProbability: 0.02,
		MinRequests:           3,
		MaxRequests:           10,
		MinGap:                500 * time.Millisecond,
		MaxGap:                5 * time.Second,
	}

	// ProfileOffice es la "trampa" de cualquier regla ingenua basada
	// solo en volumen por IP: varios empleados navegan normalmente,
	// cada uno con su propia sesión, pero todos salen a Internet por la
	// misma IP (un NAT corporativo). Este struct describe el
	// comportamiento de un único empleado; GenerateOfficeCluster es
	// quien arma el agrupamiento completo.
	ProfileOffice = LegitProfile{
		Name: "office_employee",
		Pool: PoolResidentialSimA,
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120",
		},
		HasSession:            true,
		SendsReferer:          true,
		FetchesStaticAssets:   true,
		Paths:                 []string{"/", "/dashboard", "/reports", "/reports/quarterly", "/account"},
		StaticAssets:          []string{"/static/app.css", "/static/app.js"},
		LoginPath:             "/login",
		LoginRetryProbability: 0.1,
		BrokenLinkProbability: 0.05,
		MinRequests:           4,
		MaxRequests:           12,
		MinGap:                1 * time.Second,
		MaxGap:                25 * time.Second,
	}
)

// GenerateLegitSession genera la secuencia de eventos de una sesión de
// un usuario legítimo según profile, empezando en start. clientIP es
// explícito (esta función no lo sortea) para que quien la llame decida
// si cada sesión tiene su propia IP o si varias sesiones comparten
// una — ese es exactamente el mecanismo que usa GenerateOfficeCluster.
//
// Coherencia de tiempo al mezclar sesiones: esta función usa un
// event.ManualClock propio e interno que solo avanza hacia adelante
// dentro de esta sesión — no hace falta esperar tiempo real, y no se
// crea un tipo de reloj nuevo (se reutiliza el de la tarea 0.2). Los
// eventos de una misma sesión quedan en orden por construcción. Cuando
// la tarea 0.6 mezcle muchas sesiones —de distintos perfiles y con
// distintos horarios de inicio— en un único dataset, la forma correcta
// de lograr que el archivo final quede coherente en el tiempo es
// generar cada sesión por separado (con su propio start) y después
// ordenar todos los eventos por Timestamp al juntarlos, en vez de
// compartir un único reloj entre sesiones. GenerateOfficeCluster, más
// abajo, ya hace ese ordenamiento para las sesiones que junta.
func GenerateLegitSession(rng *RNG, profile LegitProfile, start time.Time, clientIP netip.Addr) []groundtruth.LabeledEvent {
	clock := event.NewManualClock(start)
	userAgent := Pick(rng, profile.UserAgents)

	var sessionID string
	if profile.HasSession {
		sessionID = rng.ID("s-")
	}

	var events []groundtruth.LabeledEvent
	requestCount := rng.IntRange(profile.MinRequests, profile.MaxRequests)
	lastPath := ""

	emit := func(method, path string, status int, referer, loginUserHash string) {
		e := event.Event{
			RequestID:     rng.ID("r-"),
			Timestamp:     clock.Now(),
			ClientIP:      clientIP,
			SessionID:     sessionID,
			Method:        method,
			Path:          path,
			StatusCode:    status,
			UserAgent:     userAgent,
			Referer:       referer,
			LoginUserHash: loginUserHash,
		}
		events = append(events, groundtruth.LabeledEvent{Label: groundtruth.LabelLegit, Event: e})
		clock.Advance(rng.DurationRange(profile.MinGap, profile.MaxGap))
	}

	// Intento de login ocasional, con la MISMA cuenta en el reintento —
	// a diferencia del credential stuffing (tarea 0.5), que prueba una
	// cuenta distinta en cada intento.
	if profile.LoginPath != "" && rng.Bool(profile.LoginRetryProbability) {
		accountHash := rng.HexHash(64)
		emit("POST", profile.LoginPath, 401, lastPath, accountHash)
		emit("POST", profile.LoginPath, 200, profile.LoginPath, accountHash)
		lastPath = profile.LoginPath
	}

	for i := 0; i < requestCount; i++ {
		path := Pick(rng, profile.Paths)
		status := 200
		if rng.Bool(profile.BrokenLinkProbability) {
			status = 404
		}

		referer := ""
		if profile.SendsReferer {
			referer = lastPath
		}
		emit("GET", path, status, referer, "")

		if profile.FetchesStaticAssets && len(profile.StaticAssets) > 0 {
			asset := Pick(rng, profile.StaticAssets)
			assetReferer := ""
			if profile.SendsReferer {
				assetReferer = path
			}
			emit("GET", asset, 200, assetReferer, "")
		}

		lastPath = path
	}

	return events
}

// GenerateOfficeCluster genera employees sesiones de ProfileOffice que
// comparten una única IP (sorteada una sola vez), simulando un NAT
// corporativo. Cada empleado tiene su propia sesión (su propio
// session_id) y su propio horario de inicio dentro de una ventana de
// startJitter respecto de clusterStart. El resultado queda ordenado por
// Timestamp antes de devolverse — es, en sí misma, una mezcla de varias
// sesiones, así que aplica acá el mismo principio de ordenar al final
// que se documentó para la tarea 0.6.
func GenerateOfficeCluster(rng *RNG, employees int, clusterStart time.Time, startJitter time.Duration) []groundtruth.LabeledEvent {
	sharedIP := ProfileOffice.Pool.RandomAddr(rng)

	var all []groundtruth.LabeledEvent
	for i := 0; i < employees; i++ {
		employeeStart := clusterStart.Add(rng.DurationRange(0, startJitter))
		all = append(all, GenerateLegitSession(rng, ProfileOffice, employeeStart, sharedIP)...)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Event.Timestamp.Before(all[j].Event.Timestamp)
	})
	return all
}
