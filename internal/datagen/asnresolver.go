package datagen

import (
	"fmt"
	"net/netip"
)

// SimulatedASNResolver resuelve una IP simulada a su ASN de
// generación (ver ipspace.go) — determinista, sin ninguna llamada de
// red, para usar en la evaluación offline del motor.
// Nunca se usa en producción: ahí corresponde internal/asn.Resolver,
// que consulta RIPEstat de verdad. Usar RIPEstat contra
// IPs sintéticas de RFC 5737 no tendría sentido — nunca va a
// devolver nada (ver docs/decisiones.md), así que la evaluación
// necesita su propio resolver, coherente con cómo se generaron los
// datos.
//
// Satisface credstuffing.NetworkResolver (Resolve(ip) (string, bool))
// por tipado estructural — este paquete nunca importa credstuffing,
// mismo criterio que internal/asn.Resolver.
type SimulatedASNResolver struct {
	pools []IPPool
}

// NewSimulatedASNResolver construye un resolver que conoce todos los
// IPPool simulados de este generador (PoolHostingSim,
// PoolResidentialSimA, PoolResidentialSimB) — exactamente los mismos
// tres que BuildScenario usa para generar tráfico legítimo y de
// ataque. El ASN que devuelve para cualquier IP generada por este
// paquete es correcto por construcción: no es una segunda tabla que
// pudiera desincronizarse de ipspace.go, es la misma fuente de
// verdad, solo consultada al revés (IP -> ASN en vez de ASN -> IP).
func NewSimulatedASNResolver() SimulatedASNResolver {
	return SimulatedASNResolver{pools: []IPPool{PoolHostingSim, PoolResidentialSimA, PoolResidentialSimB}}
}

// Resolve devuelve "asn:<número>" si ip cae dentro de alguno de los
// IPPool conocidos, o ("", false) si no — por ejemplo, para una IP
// fuera de los tres bloques RFC 5737 que usa este generador. Nunca
// adivina: una IP no reconocida queda genuinamente sin resolver,
// mismo criterio conservador que internal/asn.Resolver.
func (r SimulatedASNResolver) Resolve(ip netip.Addr) (string, bool) {
	for _, p := range r.pools {
		if p.Prefix.Contains(ip) {
			return fmt.Sprintf("asn:%d", p.ASN), true
		}
	}
	return "", false
}
