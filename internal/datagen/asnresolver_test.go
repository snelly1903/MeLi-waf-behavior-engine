package datagen

import (
	"net/netip"
	"testing"
)

func TestSimulatedASNResolver_ResolvesKnownPools(t *testing.T) {
	r := NewSimulatedASNResolver()

	tests := []struct {
		name string
		ip   netip.Addr
		want string
	}{
		{"hosting-sim", netip.MustParseAddr("192.0.2.42"), "asn:64512"},
		{"residential-sim-a", netip.MustParseAddr("198.51.100.7"), "asn:64513"},
		{"residential-sim-b", netip.MustParseAddr("203.0.113.200"), "asn:64514"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			group, ok := r.Resolve(tc.ip)
			if !ok {
				t.Fatalf("Resolve(%v) ok = false, want true", tc.ip)
			}
			if group != tc.want {
				t.Errorf("Resolve(%v) group = %q, want %q", tc.ip, group, tc.want)
			}
		})
	}
}

// TestSimulatedASNResolver_UnknownIP_NeverGuesses confirma que una IP
// fuera de los tres pools RFC 5737 conocidos queda sin resolver — el
// resolver nunca inventa un grupo para algo que no generó.
func TestSimulatedASNResolver_UnknownIP_NeverGuesses(t *testing.T) {
	r := NewSimulatedASNResolver()

	if _, ok := r.Resolve(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("Resolve(8.8.8.8) ok = true, want false (IP pública real, fuera de los pools simulados)")
	}
}

// TestSimulatedASNResolver_SameIPAlwaysSameGroup confirma que dos
// llamadas con la misma IP siempre devuelven el mismo grupo —
// determinismo puro, sin estado ni aleatoriedad.
func TestSimulatedASNResolver_SameIPAlwaysSameGroup(t *testing.T) {
	r := NewSimulatedASNResolver()
	ip := netip.MustParseAddr("192.0.2.99")

	first, okFirst := r.Resolve(ip)
	second, okSecond := r.Resolve(ip)
	if first != second || okFirst != okSecond {
		t.Errorf("Resolve(%v) no fue determinista: (%q,%v) luego (%q,%v)", ip, first, okFirst, second, okSecond)
	}
}
