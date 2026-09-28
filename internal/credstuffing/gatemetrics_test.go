package credstuffing

import (
	"testing"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/finding"
)

// TestEvaluateGateMetrics_MatchesEvaluate_WhenTriggered confirma que,
// para el mismo escenario que TestEvaluate_DistributedCampaign_Triggers,
// EvaluateGateMetrics reporta los mismos números crudos que ya
// terminan en el Finding real de Evaluate (tarea 1.9).
func TestEvaluateGateMetrics_MatchesEvaluate_WhenTriggered(t *testing.T) {
	resolver := fakeResolver{}
	for i := 0; i < 20; i++ {
		resolver[ipFor(i)] = "asn:64512"
	}
	d := newTestDetector(t, baseConfig(resolver))

	var lastFinding finding.Finding
	var lastGate GateMetrics
	var lastFound bool
	for i := 0; i < 20; i++ {
		status := 401
		if i%10 == 0 {
			status = 200
		}
		account := "acct-" + string(rune('A'+i%15))
		e := authEvent(ipFor(i), time.Duration(i)*time.Second, account, status)
		d.Observe(e)
		lastFinding = d.Evaluate(e)
		lastGate, lastFound = d.EvaluateGateMetrics(e)
	}

	if !lastFinding.Triggered {
		t.Fatal("setup inválido: Evaluate no disparó")
	}
	if !lastFound {
		t.Fatal("EvaluateGateMetrics found = false, want true")
	}
	if !lastGate.Triggered {
		t.Error("GateMetrics.Triggered = false, want true (mismo tráfico que ya dispara en Evaluate)")
	}
	if lastGate.Group != "network:asn:64512" {
		t.Errorf("Group = %q, want %q", lastGate.Group, "network:asn:64512")
	}
	for _, sig := range lastFinding.ContributingSignals {
		switch sig.Name {
		case "distinct_ips_in_window":
			if float64(lastGate.DistinctIPs) != sig.Value {
				t.Errorf("DistinctIPs = %v, ContributingSignal = %v, want iguales", lastGate.DistinctIPs, sig.Value)
			}
		case "distinct_accounts_in_window":
			if float64(lastGate.DistinctAccounts) != sig.Value {
				t.Errorf("DistinctAccounts = %v, ContributingSignal = %v, want iguales", lastGate.DistinctAccounts, sig.Value)
			}
		case "auth_attempts_in_window":
			if float64(lastGate.TotalAttempts) != sig.Value {
				t.Errorf("TotalAttempts = %v, ContributingSignal = %v, want iguales", lastGate.TotalAttempts, sig.Value)
			}
		case "failed_auth_ratio":
			if lastGate.FailedRatio != sig.Value {
				t.Errorf("FailedRatio = %v, ContributingSignal = %v, want iguales", lastGate.FailedRatio, sig.Value)
			}
		}
	}
}

// TestEvaluateGateMetrics_ExposesRawNumbers_WhenNotTriggered es el
// punto central de este método: Evaluate descarta los cuatro números
// del gate cuando no dispara (devuelve finding.Finding{}) —
// EvaluateGateMetrics los expone siempre.
func TestEvaluateGateMetrics_ExposesRawNumbers_WhenNotTriggered(t *testing.T) {
	resolver := fakeResolver{ipFor(0): "asn:64512"}
	d := newTestDetector(t, baseConfig(resolver))

	// Una sola IP, muchos intentos -- nunca cruza MinDistinctIPs.
	var lastGate GateMetrics
	for i := 0; i < 10; i++ {
		e := authEvent(ipFor(0), time.Duration(i)*time.Second, "acct-A", 401)
		d.Observe(e)
		var found bool
		lastGate, found = d.EvaluateGateMetrics(e)
		if !found {
			t.Fatalf("evento %d: found = false, want true", i)
		}
	}

	if lastGate.Triggered {
		t.Fatal("Triggered = true, want false — una sola IP nunca puede cruzar MinDistinctIPs")
	}
	if lastGate.DistinctIPs != 1 {
		t.Errorf("DistinctIPs = %d, want 1 (expuesto aunque no disparó)", lastGate.DistinctIPs)
	}
	if lastGate.TotalAttempts != 10 {
		t.Errorf("TotalAttempts = %d, want 10", lastGate.TotalAttempts)
	}
}

// TestEvaluateGateMetrics_NonAuthOrUnresolved_ReturnsNotFound cubre
// los dos casos en que Evaluate devuelve un Finding vacío sin tocar
// ningún estado: una ruta que no es de autenticación, y una IP que no
// se pudo resolver a ningún grupo.
func TestEvaluateGateMetrics_NonAuthOrUnresolved_ReturnsNotFound(t *testing.T) {
	resolver := fakeResolver{ipFor(0): "asn:64512"}
	d := newTestDetector(t, baseConfig(resolver))

	nonAuth := authEvent(ipFor(0), 0, "acct-A", 401)
	nonAuth.Path = "/"
	if _, found := d.EvaluateGateMetrics(nonAuth); found {
		t.Error("found = true para una ruta no-auth, want false")
	}

	unresolved := authEvent(ipFor(99), 0, "acct-A", 401) // IP fuera del resolver
	if _, found := d.EvaluateGateMetrics(unresolved); found {
		t.Error("found = true para una IP sin resolver, want false")
	}
}
