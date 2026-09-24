package event

import "strings"

// AuthPathMatcher decide si una ruta de request es un endpoint de
// autenticación. Está deliberadamente separado de Event y de Validator:
// qué ruta significa "login" es un hecho sobre la aplicación protegida,
// no una propiedad del contrato del evento, así que tiene que quedar
// configurable en lugar de fijo dentro de la validación. Un Validator
// nunca usa este tipo; un detector (Fase 1) sí, para decidir qué
// eventos alimentan las señales de credential stuffing (el ratio de
// 401/403, la diversidad de cuentas probadas).
type AuthPathMatcher struct {
	exact    map[string]struct{}
	prefixes []string
}

// NewAuthPathMatcher construye un matcher a partir de una lista
// explícita de rutas. Una ruta que termina en "/" se trata como un
// prefijo (coincide con todo lo que esté debajo); cualquier otra ruta
// debe coincidir exactamente. La comparación no distingue mayúsculas de
// minúsculas e ignora una barra final en la ruta de entrada.
func NewAuthPathMatcher(paths ...string) *AuthPathMatcher {
	m := &AuthPathMatcher{exact: make(map[string]struct{})}
	for _, p := range paths {
		p = strings.ToLower(p)
		if strings.HasSuffix(p, "/") {
			m.prefixes = append(m.prefixes, p)
		} else {
			m.exact[p] = struct{}{}
		}
	}
	return m
}

// DefaultAuthPathMatcher devuelve un matcher que cubre las formas
// habituales de ruta de autenticación usadas por el generador de
// tráfico de este proyecto y las aplicaciones que modela. Es un punto
// de partida, no una afirmación de que estas sean las únicas rutas de
// login que tendría un despliegue real — en producción esta lista se
// cargaría desde configuración en lugar de estar fija acá.
func DefaultAuthPathMatcher() *AuthPathMatcher {
	return NewAuthPathMatcher(
		"/login",
		"/signin",
		"/sign-in",
		"/api/login",
		"/oauth/token",
		"/auth/",
		"/api/auth/",
		"/sso/",
	)
}

// IsAuthPath informa si path debe tratarse como un endpoint de
// autenticación.
func (m *AuthPathMatcher) IsAuthPath(path string) bool {
	normalized := strings.ToLower(path)
	if normalized != "/" {
		normalized = strings.TrimSuffix(normalized, "/")
	}
	if _, ok := m.exact[normalized]; ok {
		return true
	}
	for _, prefix := range m.prefixes {
		if strings.HasPrefix(normalized+"/", prefix) {
			return true
		}
	}
	return false
}
