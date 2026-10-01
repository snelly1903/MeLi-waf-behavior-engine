// Resuelve de forma determinista los ASN simulados de los pools de IP sintéticos.
package datagen

import (
	"fmt"
	"net/netip"
)

type SimulatedASNResolver struct {
	pools []IPPool
}

func NewSimulatedASNResolver() SimulatedASNResolver {
	return SimulatedASNResolver{pools: []IPPool{PoolHostingSim, PoolResidentialSimA, PoolResidentialSimB}}
}

func (r SimulatedASNResolver) Resolve(ip netip.Addr) (string, bool) {
	for _, p := range r.pools {
		if p.Prefix.Contains(ip) {
			return fmt.Sprintf("asn:%d", p.ASN), true
		}
	}
	return "", false
}
