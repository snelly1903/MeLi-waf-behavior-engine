package datagen

import (
	"fmt"
	"net/netip"
)

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
// Nota de alcance: RandomAddr y DistinctAddrs asumen que Prefix es
// exactamente un /24 IPv4 (254 direcciones utilizables, .1 a .254) — es
// lo único que necesitan las tareas 0.4 y 0.5 (la campaña de credential
// stuffing de la tarea 0.5 usa 150 de esas 254). Si más adelante hiciera
// falta más espacio de direcciones, el candidato natural es el rango
// 198.18.0.0/15, reservado por el RFC 2544 para benchmarking, que da
// lugar a muchas más direcciones y tampoco activa las reglas de "IP
// privada".
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

// poolCapacity es cuántas direcciones utilizables tiene un /24 (los
// octetos .1 a .254; ver la nota de alcance más arriba).
const poolCapacity = 254

// DistinctAddrs sortea n direcciones DISTINTAS dentro del pool, sin
// reemplazo — necesario para el credential stuffing distribuido (tarea
// 0.5), donde cada IP atacante tiene que ser única. Mezcla el espacio
// de direcciones utilizables (Fisher-Yates) y toma las primeras n, así
// la selección es uniforme y sin un orden artificial (no son "las
// primeras n direcciones del bloque").
//
// Entra en pánico si n supera la capacidad del pool: pedir más IPs
// distintas de las que el bloque puede dar es un error de configuración
// de la campaña que se generó, no algo a resolver en tiempo de
// ejecución.
func (p IPPool) DistinctAddrs(rng *RNG, n int) []netip.Addr {
	if n > poolCapacity {
		panic(fmt.Sprintf("datagen: DistinctAddrs requested %d addresses from pool %q, which only has %d", n, p.Name, poolCapacity))
	}

	octets := make([]int, poolCapacity)
	for i := range octets {
		octets[i] = i + 1
	}
	for i := len(octets) - 1; i > 0; i-- {
		j := rng.IntRange(0, i)
		octets[i], octets[j] = octets[j], octets[i]
	}

	base := p.Prefix.Addr().As4()
	addrs := make([]netip.Addr, n)
	for i := 0; i < n; i++ {
		b := base
		b[3] = byte(octets[i])
		addrs[i] = netip.AddrFrom4(b)
	}
	return addrs
}

// DistinctAddrsExcluding funciona como DistinctAddrs, pero nunca
// devuelve ninguna dirección presente en exclude. Se usa cuando dos
// generadores distintos necesitan direcciones garantizadamente
// disjuntas del mismo pool — por ejemplo, en la tarea 0.6, para que un
// tenant legítimo (ProfileHostedTenant) y las IPs atacantes nunca
// coincidan dentro del mismo escenario, sin depender de la
// probabilidad de que dos sorteos independientes no se solapen.
//
// Entra en pánico si, después de descontar exclude, no quedan
// suficientes direcciones para dar las n pedidas.
func (p IPPool) DistinctAddrsExcluding(rng *RNG, n int, exclude []netip.Addr) []netip.Addr {
	excluded := make(map[netip.Addr]bool, len(exclude))
	for _, a := range exclude {
		excluded[a] = true
	}

	base := p.Prefix.Addr().As4()
	available := make([]int, 0, poolCapacity)
	for last := 1; last <= poolCapacity; last++ {
		b := base
		b[3] = byte(last)
		if !excluded[netip.AddrFrom4(b)] {
			available = append(available, last)
		}
	}

	if n > len(available) {
		panic(fmt.Sprintf("datagen: DistinctAddrsExcluding requested %d addresses from pool %q, only %d remain after excluding %d addresses",
			n, p.Name, len(available), len(exclude)))
	}

	for i := len(available) - 1; i > 0; i-- {
		j := rng.IntRange(0, i)
		available[i], available[j] = available[j], available[i]
	}

	addrs := make([]netip.Addr, n)
	for i := 0; i < n; i++ {
		b := base
		b[3] = byte(available[i])
		addrs[i] = netip.AddrFrom4(b)
	}
	return addrs
}
