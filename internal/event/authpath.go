// Identifica si una ruta corresponde a un endpoint de autenticación.
package event

import "strings"

type AuthPathMatcher struct {
	exact    map[string]struct{}
	prefixes []string
}

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
