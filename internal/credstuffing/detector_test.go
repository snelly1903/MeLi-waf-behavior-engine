package credstuffing

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/decision"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
)

var testBase = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

// fakeResolver es un NetworkResolver determinista, exclusivamente para
// tests — nunca código de producción. Un IP ausente del mapa se
// reporta como no resoluble (ok=false).
type fakeResolver map[netip.Addr]string

func (r fakeResolver) Resolve(ip netip.Addr) (string, bool) {
	group, ok := r[ip]
	return group, ok
}

// ipFor arma una dirección determinista y distinta para el índice i,
// dentro de 203.0.113.0/24 (RFC 5737, documentación).
func ipFor(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + i%254)})
}

const loginPath = "/login"

func authEvent(ip netip.Addr, offset time.Duration, accountHash string, status int) event.Event {
	return event.Event{
		RequestID:     "r",
		Timestamp:     testBase.Add(offset),
		ClientIP:      ip,
		Method:        "POST",
		Path:          loginPath,
		StatusCode:    status,
		LoginUserHash: accountHash,
	}
}

func nonAuthEvent(ip netip.Addr, offset time.Duration) event.Event {
	return event.Event{
		RequestID:  "r",
		Timestamp:  testBase.Add(offset),
		ClientIP:   ip,
		Method:     "GET",
		Path:       "/home",
		StatusCode: 200,
	}
}

// baseConfig son los umbrales usados por la mayoría de los tests de
// este archivo — valores de prueba elegidos para que sean fáciles de
// razonar a mano, NUNCA los umbrales finales de calibración (eso es
// una tarea posterior, contra un dataset separado, igual que se hizo
// con internal/baseline en la tarea 0.9).
func baseConfig(resolver NetworkResolver) Config {
	return Config{
		Window:              10 * time.Minute,
		MinDistinctIPs:      5,
		MinDistinctAccounts: 4,
		MinAttempts:         6,
		MinFailedRatio:      0.5,
		Weights:             ScoreWeights{IPs: 0.25, Accounts: 0.25, Attempts: 0.25, Ratio: 0.25},
		ScoreFloor:          0.2,
		Resolver:            resolver,
	}
}

func newTestDetector(t *testing.T, cfg Config) *Detector {
	t.Helper()
	d, err := NewDetector(cfg)
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	return d
}

// observe llama Observe y devuelve Evaluate para el mismo evento —
// el orden que el propio Detector documenta como precondición.
func observe(d *Detector, e event.Event) finding.Finding {
	d.Observe(e)
	return d.Evaluate(e)
}

// --- Config.Validate ---------------------------------------------------

func TestConfig_Validate_InvalidConfigurations(t *testing.T) {
	valid := baseConfig(fakeResolver{})
	tests := []struct {
		name   string
		break_ func(c Config) Config
		want   error
	}{
		{"zero window", func(c Config) Config { c.Window = 0; return c }, ErrInvalidWindow},
		{"zero min distinct ips", func(c Config) Config { c.MinDistinctIPs = 0; return c }, ErrInvalidMinDistinctIPs},
		{"negative min distinct accounts", func(c Config) Config { c.MinDistinctAccounts = -1; return c }, ErrInvalidMinDistinctAccounts},
		{"zero min attempts", func(c Config) Config { c.MinAttempts = 0; return c }, ErrInvalidMinAttempts},
		{"negative min failed ratio", func(c Config) Config { c.MinFailedRatio = -0.1; return c }, ErrInvalidMinFailedRatio},
		{"min failed ratio above 1", func(c Config) Config { c.MinFailedRatio = 1.1; return c }, ErrInvalidMinFailedRatio},
		{"zero score floor", func(c Config) Config { c.ScoreFloor = 0; return c }, ErrInvalidScoreFloor},
		{"score floor of 1", func(c Config) Config { c.ScoreFloor = 1; return c }, ErrInvalidScoreFloor},
		{"all weights zero", func(c Config) Config { c.Weights = ScoreWeights{}; return c }, ErrInvalidWeights},
		{"negative weight", func(c Config) Config { c.Weights.IPs = -1; return c }, ErrInvalidWeights},
		{"nil resolver", func(c Config) Config { c.Resolver = nil; return c }, ErrNilResolver},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.break_(valid).Validate()
			if !errors.Is(err, tc.want) {
				t.Errorf("Validate() = %v, want it to wrap %v", err, tc.want)
			}
		})
	}
}

func TestNewDetector_InvalidConfig_ReturnsError(t *testing.T) {
	cfg := baseConfig(fakeResolver{})
	cfg.Window = 0
	if _, err := NewDetector(cfg); !errors.Is(err, ErrInvalidWindow) {
		t.Errorf("NewDetector() error = %v, want it to wrap ErrInvalidWindow", err)
	}
}

// --- El caso central: campaña distribuida que dispara -------------------

func TestEvaluate_DistributedCampaign_Triggers(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 20; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	// 20 IPs distintas, cada una con 1 intento, 15 cuentas distintas
	// (algunas reutilizadas), 90% de fallos.
	for i := 0; i < 20; i++ {
		status := 401
		if i%10 == 0 { // 2 de 20 exitosos: ratio de fallo 0.9
			status = 200
		}
		account := "acct-" + string(rune('A'+i%15))
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, account, status)
		last = observe(d, e)
	}

	if !last.Triggered {
		t.Fatal("Triggered = false, want true for a clear distributed campaign")
	}
	if last.AttackVector != decision.AttackVectorCredentialStuffing {
		t.Errorf("AttackVector = %v, want credential_stuffing", last.AttackVector)
	}
	if last.RiskScore <= 0 || last.RiskScore >= 1 {
		t.Errorf("RiskScore = %v, want it in (0, 1)", last.RiskScore)
	}
	if len(last.ContributingSignals) != 4 {
		t.Errorf("ContributingSignals has %d entries, want 4", len(last.ContributingSignals))
	}
	if last.Explanation == "" {
		t.Error("Explanation is empty, want a deterministic message")
	}
	if last.EntityID != "network:asn:64512" {
		t.Errorf("EntityID = %q, want %q", last.EntityID, "network:asn:64512")
	}
}

// --- El caso central de la tarea: RiskScore nunca cero al disparar ------

// TestEvaluate_AllSignalsExactlyAtThreshold_TriggersWithPositiveScore es
// el test pedido explícitamente tras la corrección: con las cuatro
// señales EXACTAMENTE en su umbral configurado (5 IPs, 4 cuentas, 6
// intentos, ratio de fallo 0.5), Triggered tiene que dar true, y
// RiskScore tiene que ser estrictamente mayor que 0 — sin el piso
// (ScoreFloor), los cuatro componentes normalizados darían 0 y el
// score total sería 0 pese a haber disparado.
func TestEvaluate_AllSignalsExactlyAtThreshold_TriggersWithPositiveScore(t *testing.T) {
	resolver := fakeResolver{
		ipFor(0): "asn:64512",
		ipFor(1): "asn:64512",
		ipFor(2): "asn:64512",
		ipFor(3): "asn:64512",
		ipFor(4): "asn:64512",
	}
	d := newTestDetector(t, baseConfig(resolver))

	// 6 intentos, 5 IPs distintas (ipFor(0) se repite), 4 cuentas
	// distintas (A,B,C,D — D y A se reutilizan), 3 fallos de 6 (ratio
	// exacto 0.5).
	events := []event.Event{
		authEvent(ipFor(0), 0*time.Second, "acct-A", 401), // fallo
		authEvent(ipFor(0), 1*time.Second, "acct-B", 200),
		authEvent(ipFor(1), 2*time.Second, "acct-C", 401), // fallo
		authEvent(ipFor(2), 3*time.Second, "acct-D", 200),
		authEvent(ipFor(3), 4*time.Second, "acct-D", 403), // fallo
		authEvent(ipFor(4), 5*time.Second, "acct-A", 200),
	}

	var last finding.Finding
	for _, e := range events {
		last = observe(d, e)
	}

	if !last.Triggered {
		t.Fatal("Triggered = false, want true — all four signals are exactly at their configured threshold")
	}
	if last.RiskScore <= 0 {
		t.Errorf("RiskScore = %v, want it strictly greater than 0 even at the exact threshold", last.RiskScore)
	}
	if last.RiskScore >= 1 {
		t.Errorf("RiskScore = %v, want it strictly less than 1", last.RiskScore)
	}
	// En el borde exacto, los cuatro componentes normalizados dan 0, así
	// que el score tiene que ser EXACTAMENTE el piso configurado.
	if last.RiskScore != 0.2 {
		t.Errorf("RiskScore = %v, want exactly ScoreFloor (0.2) at the exact threshold", last.RiskScore)
	}
}

// --- Una sola IP no puede, por sí sola, demostrar el caso distribuido ---

func TestEvaluate_SingleIP_ManyAttempts_DoesNotTrigger(t *testing.T) {
	ip := ipFor(0)
	resolver := fakeResolver{ip: "asn:64512"}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	// 50 intentos, todos fallidos, todos desde la MISMA IP y la misma
	// cuenta — un flood clásico de una sola IP, no una campaña
	// distribuida.
	for i := 0; i < 50; i++ {
		e := authEvent(ip, time.Duration(i)*time.Second, "acct-A", 401)
		last = observe(d, e)
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — a single IP flood must never satisfy MinDistinctIPs by itself: %+v", last)
	}
}

// --- Tráfico legítimo compartiendo ASN con atacantes ---------------------

func TestEvaluate_LegitTenantSharingASNWithAttackers_DoesNotTrigger(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 30; i++ {
		resolver[ipFor(i)] = "asn:64512" // mismo grupo que usaría un atacante
	}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	// 30 IPs, 30 cuentas distintas, volumen alto — pero casi todos los
	// logins tienen éxito (ratio de fallo muy bajo): un tenant
	// legítimo real.
	for i := 0; i < 30; i++ {
		status := 200
		if i == 0 { // un único fallo entre 30 — normal, alguien tipeó mal
			status = 401
		}
		account := "acct-" + string(rune('A'+i%26))
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, account, status)
		last = observe(d, e)
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — legit traffic with a low failed-login ratio must not trigger: %+v", last)
	}
}

// --- Muchos 401 pero pocas cuentas (posible brute-force de una cuenta) --

func TestEvaluate_ManyFailuresFewAccounts_DoesNotTrigger(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 20; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	// 20 IPs distintas, volumen alto, 100% de fallos — pero todas
	// contra la MISMA cuenta (solo 1 distinta, muy por debajo de
	// MinDistinctAccounts=4).
	for i := 0; i < 20; i++ {
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, "acct-single-target", 401)
		last = observe(d, e)
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — too few distinct accounts for the distributed-stuffing gate: %+v", last)
	}
}

// --- Muchas cuentas pero pocos errores (login legítimo masivo) ----------

func TestEvaluate_ManyAccountsFewFailures_DoesNotTrigger(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 20; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	// 20 IPs, 20 cuentas distintas — pero todos exitosos.
	for i := 0; i < 20; i++ {
		account := "acct-" + string(rune('A'+i%20))
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, account, 200)
		last = observe(d, e)
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — a 0%% failed ratio must not trigger regardless of IP/account diversity: %+v", last)
	}
}

// --- Eventos fuera de ventana --------------------------------------------

func TestEvaluate_EventsOutsideWindow_StopCounting(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 6; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	// Primer lote: 6 intentos, 5 IPs distintas (ipFor(0) se repite), 4
	// cuentas distintas, ratio de fallo exacto 0.5 — cumple las cuatro
	// condiciones, dispara.
	var trigger finding.Finding
	batch := []event.Event{
		authEvent(ipFor(0), 0*time.Second, "acct-A", 401),
		authEvent(ipFor(0), 1*time.Second, "acct-B", 200),
		authEvent(ipFor(1), 2*time.Second, "acct-C", 401),
		authEvent(ipFor(2), 3*time.Second, "acct-D", 200),
		authEvent(ipFor(3), 4*time.Second, "acct-D", 403),
		authEvent(ipFor(4), 5*time.Second, "acct-A", 200),
	}
	for _, e := range batch {
		trigger = observe(d, e)
	}
	if !trigger.Triggered {
		t.Fatalf("first batch did not trigger, want it to (test setup issue): %+v", trigger)
	}

	// Segundo evento, 30 minutos después (Window=10min): para cuando
	// llega, todo el primer lote ya expiró. Por sí solo, un único
	// intento no alcanza ningún umbral.
	late := authEvent(ipFor(5), 30*time.Minute, "acct-E", 200)
	after := observe(d, late)

	if after.Triggered {
		t.Errorf("Triggered = true after the window elapsed, want false (the first batch should have expired): %+v", after)
	}
}

// --- ASN desconocido ------------------------------------------------------

func TestObserve_UnresolvedIP_ExcludedFromCorrelation(t *testing.T) {
	// unresolved no está en el mapa: Resolve le va a devolver ok=false.
	knownIP := ipFor(0)
	resolver := fakeResolver{knownIP: "asn:64512"}
	d := newTestDetector(t, baseConfig(resolver))

	// 20 IPs no resolubles, con toda la pinta de una campaña si se
	// las agrupara — pero como no resuelven, no deberían contar en
	// ningún grupo ni disparar nunca.
	var lastUnresolved finding.Finding
	for i := 1; i <= 20; i++ {
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, "acct-X", 401)
		lastUnresolved = observe(d, e)
	}
	if lastUnresolved.Triggered {
		t.Errorf("Triggered = true for an unresolved IP, want false: %+v", lastUnresolved)
	}

	// Confirmar que no contaminaron el grupo real conocido: un único
	// intento desde knownIP sigue evaluando como "no dispara" por sí
	// solo (no heredó ningún conteo de las IPs no resueltas).
	knownFinding := observe(d, authEvent(knownIP, 21*time.Second, "acct-Y", 401))
	if knownFinding.Triggered {
		t.Errorf("Triggered = true for the known group after only 1 attempt, want false (unresolved IPs must not have leaked into it): %+v", knownFinding)
	}
}

// --- Eventos sin login_user_hash ------------------------------------------

func TestEvaluate_MissingLoginUserHash_ExcludedFromAccountSet(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 6; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var last finding.Finding
	// 6 IPs, 6 intentos, ratio de fallo alto — pero login_user_hash
	// vacío en todos: DistinctAccounts debe quedar en 0, muy por
	// debajo de MinDistinctAccounts=4.
	for i := 0; i < 6; i++ {
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, "", 401)
		last = observe(d, e)
	}

	if last.Triggered {
		t.Errorf("Triggered = true, want false — empty login_user_hash must never count toward DistinctAccounts: %+v", last)
	}
}

// --- Un evento que no es de autenticación nunca dispara ni toca estado --

func TestObserveEvaluate_NonAuthEvent_NeverTriggers(t *testing.T) {
	ip := ipFor(0)
	resolver := fakeResolver{ip: "asn:64512"}
	d := newTestDetector(t, baseConfig(resolver))

	f := observe(d, nonAuthEvent(ip, 0))
	if f.Triggered {
		t.Errorf("Triggered = true for a non-auth event, want false: %+v", f)
	}
}

// --- Concurrencia ----------------------------------------------------------

// TestObserve_ConcurrentWrites_SameGroup corre muchas goroutines
// observando el mismo grupo de red en paralelo, cada una con IP y
// cuenta distintas y timestamps fijos y deterministas (nunca
// time.Now()), y confirma con go test -race que no hay condiciones de
// carrera y que el resultado final dispara con un score coherente.
func TestObserve_ConcurrentWrites_SameGroup(t *testing.T) {
	const n = 60
	resolver := fakeResolver{}
	for i := 0; i < n; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			account := "acct-" + string(rune('A'+i%26))
			d.Observe(authEvent(ipFor(i), time.Duration(i)*time.Millisecond, account, 401))
		}(i)
	}
	wg.Wait()

	// Evaluar con un último evento del mismo grupo, ya con todo lo
	// anterior observado.
	probe := authEvent(ipFor(0), time.Duration(n)*time.Millisecond, "acct-probe", 401)
	f := observe(d, probe)

	if !f.Triggered {
		t.Fatalf("Triggered = false after %d concurrent auth attempts across distinct IPs/accounts, want true: %+v", n, f)
	}
	if f.RiskScore <= 0 || f.RiskScore >= 1 {
		t.Errorf("RiskScore = %v, want it in (0, 1)", f.RiskScore)
	}
}

// TestSweep_RemovesOnlyIdleGroups confirma que Sweep elimina un grupo
// inactivo por más de idleTTL, y conserva uno activo.
func TestSweep_RemovesOnlyIdleGroups(t *testing.T) {
	idleIP := ipFor(0)
	activeIP := ipFor(1)
	resolver := fakeResolver{idleIP: "idle-group", activeIP: "active-group"}
	d := newTestDetector(t, baseConfig(resolver))

	d.Observe(authEvent(idleIP, 0, "acct-A", 401))
	d.Observe(authEvent(activeIP, 30*time.Minute, "acct-B", 401))

	now := testBase.Add(40 * time.Minute)
	removed := d.Sweep(now, 20*time.Minute)

	if removed != 1 {
		t.Fatalf("Sweep removed %d groups, want 1", removed)
	}
}
