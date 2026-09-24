package datagen

import (
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
)

var allPools = []IPPool{PoolHostingSim, PoolResidentialSimA, PoolResidentialSimB}

// TestPools_AddressesArePublic es la comprobación empírica que pediste
// antes de implementar: confirma que ninguna dirección sorteada de
// estos pools activa las reglas de "IP privada" del Validator (RFC1918,
// loopback, link-local, sin especificar). Se llegó a la misma
// conclusión "a mano" antes de escribir este archivo (ver
// docs/decisiones.md, tarea 0.4); este test la deja fijada como
// regresión permanente.
func TestPools_AddressesArePublic(t *testing.T) {
	rng := NewRNG(1)
	for _, pool := range allPools {
		for i := 0; i < 200; i++ {
			addr := pool.RandomAddr(rng)
			if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
				t.Fatalf("pool %q produced a non-public address: %v", pool.Name, addr)
			}
		}
	}
}

// TestPools_AddressesStayWithinPrefix confirma que cada dirección
// sorteada realmente pertenece al bloque CIDR declarado del pool.
func TestPools_AddressesStayWithinPrefix(t *testing.T) {
	rng := NewRNG(2)
	for _, pool := range allPools {
		for i := 0; i < 200; i++ {
			addr := pool.RandomAddr(rng)
			if !pool.Prefix.Contains(addr) {
				t.Fatalf("pool %q (%v) produced an address outside its prefix: %v", pool.Name, pool.Prefix, addr)
			}
		}
	}
}

// TestPools_AddressesPassEventValidator confirma que una IP sorteada de
// cualquiera de los tres pools, dentro de un Event por lo demás válido,
// pasa el Validator de la tarea 0.2 sin errores.
func TestPools_AddressesPassEventValidator(t *testing.T) {
	rng := NewRNG(3)
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	v := event.NewValidator(event.NewManualClock(now))

	for _, pool := range allPools {
		addr := pool.RandomAddr(rng)
		e := event.Event{
			RequestID:  "r-1",
			Timestamp:  now,
			ClientIP:   addr,
			Method:     "GET",
			Path:       "/",
			StatusCode: 200,
		}
		if err := v.Validate(e); err != nil {
			t.Errorf("pool %q: an event with ClientIP=%v failed validation: %v", pool.Name, addr, err)
		}
	}
}

// TestPools_HaveDistinctSimulatedASNsInPrivateUseRange confirma que los
// tres ASN simulados son todos distintos y caen dentro del rango
// 64512–65534 reservado por la IANA (RFC 6996) para uso privado — así
// ninguno se puede confundir con el ASN de un proveedor real.
func TestPools_HaveDistinctSimulatedASNsInPrivateUseRange(t *testing.T) {
	seen := make(map[SimulatedASN]string)
	for _, pool := range allPools {
		if pool.ASN < 64512 || pool.ASN > 65534 {
			t.Errorf("pool %q has ASN %d, outside the IANA private-use range 64512-65534", pool.Name, pool.ASN)
		}
		if existing, dup := seen[pool.ASN]; dup {
			t.Errorf("ASN %d is shared by pools %q and %q, want distinct ASNs per pool", pool.ASN, existing, pool.Name)
		}
		seen[pool.ASN] = pool.Name
	}
}
