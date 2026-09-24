package datagen

import "net/netip"

// SimulatedASN identifica un número de sistema autónomo (ASN) asignado
// por este generador — nunca uno real. Los ASN públicos ocupan el
// rango 1–64511 y 65536 en adelante; el rango 64512–65534 está
// reservado por la IANA (RFC 6996) específicamente para uso privado o
// de documentación, así que un valor en ese rango no se puede confundir
// por accidente con el ASN de un proveedor real.
type SimulatedASN uint32

// IPPool es un conjunto de direcciones IP simuladas que representan una
// misma red, identificada por un ASN simulado. Todas las direcciones de
// todo IPPool definido en este archivo salen de bloques reservados para
// documentación por la IANA (RFC 5737: 192.0.2.0/24, 198.51.100.0/24 y
// 203.0.113.0/24) — ninguna es una dirección pública real ni pertenece
// a ningún proveedor de verdad. Se verificó (ver docs/decisiones.md,
// tarea 0.4) que ninguno de estos tres bloques activa las reglas de "IP
// privada" del Validator de la tarea 0.2, así que no hizo falta
// modificarlo. El enriquecimiento real de IP se integra más adelante
// (Fase 1) mediante un adaptador independiente que esta simulación no
// necesita conocer.
//
// Nota de alcance: RandomAddr asume que Prefix es exactamente un /24
// IPv4 — es lo único que necesita esta tarea. Si en la tarea 0.5 hiciera
// falta más espacio de direcciones (por ejemplo, para simular cientos
// de IPs de un clúster de credential stuffing), se ampliaría entonces
// — el candidato natural es el rango 198.18.0.0/15, reservado por el
// RFC 2544 para benchmarking, que da lugar a muchas más direcciones y
// tampoco activa las reglas de "IP privada".
type IPPool struct {
	Name   string
	ASN    SimulatedASN
	Prefix netip.Prefix
}

var (
	// PoolHostingSim simula una red "tipo hosting": poca diversidad de
	// usuarios reales detrás de ella. La va a usar el generador de
	// ataques (tarea 0.5); en esta tarea no se usa todavía, pero se
	// define acá junto con las otras dos redes simuladas para que
	// queden documentadas en un solo lugar.
	PoolHostingSim = IPPool{Name: "hosting-sim", ASN: 64512, Prefix: netip.MustParsePrefix("192.0.2.0/24")}

	// PoolResidentialSimA y PoolResidentialSimB simulan dos redes "tipo
	// residencial" distintas, usadas por el tráfico legítimo de esta
	// tarea.
	PoolResidentialSimA = IPPool{Name: "residential-sim-a", ASN: 64513, Prefix: netip.MustParsePrefix("198.51.100.0/24")}
	PoolResidentialSimB = IPPool{Name: "residential-sim-b", ASN: 64514, Prefix: netip.MustParsePrefix("203.0.113.0/24")}
)

// RandomAddr sortea una dirección dentro del pool usando rng, evitando
// los dos extremos del bloque (.0 y .255) por prolijidad — el Validator
// de todas formas las aceptaría, pero no representan la IP de un
// cliente real en ningún esquema de direccionamiento habitual.
func (p IPPool) RandomAddr(rng *RNG) netip.Addr {
	last := rng.IntRange(1, 254)
	octets := p.Prefix.Addr().As4()
	octets[3] = byte(last)
	return netip.AddrFrom4(octets)
}
