// Verifica que las rutas sensibles y las rutas legítimas no se solapen.
package datagen

import "testing"

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

func TestSensitivePaths_NeverOverlapWithLegitPaths(t *testing.T) {
	legit := allLegitPaths()
	for _, p := range SensitivePaths {
		if legit[p] {
			t.Errorf("SensitivePaths contains %q, which is also used by a legit profile", p)
		}
	}
}

func TestDefaultValidScanPaths_AreAllLegitPaths(t *testing.T) {
	legit := allLegitPaths()
	for _, p := range DefaultValidScanPaths {
		if !legit[p] {
			t.Errorf("DefaultValidScanPaths contains %q, which no legit profile uses", p)
		}
	}
}

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
