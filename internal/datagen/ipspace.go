package datagen

import (
	"fmt"
	"net/netip"
)


type SimulatedASN uint32

type IPPool struct {
	Name   string
	ASN    SimulatedASN
	Prefix netip.Prefix
}

var (
	PoolHostingSim = IPPool{Name: "hosting-sim", ASN: 64512, Prefix: netip.MustParsePrefix("192.0.2.0/24")}
	PoolResidentialSimA = IPPool{Name: "residential-sim-a", ASN: 64513, Prefix: netip.MustParsePrefix("198.51.100.0/24")}
	PoolResidentialSimB = IPPool{Name: "residential-sim-b", ASN: 64514, Prefix: netip.MustParsePrefix("203.0.113.0/24")}
)

func (p IPPool) RandomAddr(rng *RNG) netip.Addr {
	last := rng.IntRange(1, 254)
	octets := p.Prefix.Addr().As4()
	octets[3] = byte(last)
	return netip.AddrFrom4(octets)
}

const poolCapacity = 254

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
