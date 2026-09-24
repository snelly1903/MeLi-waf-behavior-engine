package datagen

import "testing"

// allLegitPaths reúne todas las rutas que puede visitar cualquiera de
// los tres perfiles legítimos (tarea 0.4): páginas, assets estáticos y
// endpoints de login.
func allLegitPaths() map[string]bool {
	paths := make(map[string]bool)
	for _, profile := range []LegitProfile{ProfileNavegante, ProfileAPIClient, ProfileOffice} {
		for _, p := range profile.Paths {
			paths[p] = true
		}
		for _, p := range profile.StaticAssets {
			paths[p] = true
		}
		if profile.LoginPath != "" {
			paths[profile.LoginPath] = true
		}
	}
	return paths
}

// TestSensitivePaths_NeverOverlapWithLegitPaths es la comprobación
// explícita (no supuesta) de que el vocabulario "tipo wordlist" del
// escaneo lento nunca coincide con una ruta que algún perfil legítimo
// visite — si coincidiera, "ruta nunca vista en usuarios legítimos"
// dejaría de ser una señal válida.
func TestSensitivePaths_NeverOverlapWithLegitPaths(t *testing.T) {
	legit := allLegitPaths()
	for _, p := range SensitivePaths {
		if legit[p] {
			t.Errorf("SensitivePaths contains %q, which is also used by a legit profile", p)
		}
	}
}

// TestDefaultValidScanPaths_AreAllLegitPaths confirma lo contrario: las
// rutas "válidas" que a veces visita el escáner son todas rutas reales
// de la aplicación, no inventadas aparte.
func TestDefaultValidScanPaths_AreAllLegitPaths(t *testing.T) {
	legit := allLegitPaths()
	for _, p := range DefaultValidScanPaths {
		if !legit[p] {
			t.Errorf("DefaultValidScanPaths contains %q, which no legit profile uses", p)
		}
	}
}

// TestSensitivePathsAndValidPaths_AreDisjoint confirma que las dos
// listas no se superponen entre sí — cada ruta que genera el escáner es
// o bien "sensible" (404 esperado) o bien "válida" (200 esperado),
// nunca ambas cosas.
func TestSensitivePathsAndValidPaths_AreDisjoint(t *testing.T) {
	valid := make(map[string]bool)
	for _, p := range DefaultValidScanPaths {
		valid[p] = true
	}
	for _, p := range SensitivePaths {
		if valid[p] {
			t.Errorf("path %q appears in both SensitivePaths and DefaultValidScanPaths", p)
		}
	}
}
