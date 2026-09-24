package event

import "testing"

func TestDefaultAuthPathMatcher(t *testing.T) {
	m := DefaultAuthPathMatcher()

	authPaths := []string{
		"/login",
		"/LOGIN",  // case-insensitive
		"/login/", // trailing slash tolerated
		"/signin",
		"/api/login",
		"/oauth/token",
		"/auth/session", // under the "/auth/" prefix
		"/api/auth/mfa", // under the "/api/auth/" prefix
		"/sso/saml/acs", // under the "/sso/" prefix
	}
	for _, p := range authPaths {
		if !m.IsAuthPath(p) {
			t.Errorf("IsAuthPath(%q) = false, want true", p)
		}
	}

	nonAuthPaths := []string{
		"/",
		"/dashboard",
		"/api/products/123",
		"/authors", // must not match "/auth/" as a naive substring
		"/static/app.js",
	}
	for _, p := range nonAuthPaths {
		if m.IsAuthPath(p) {
			t.Errorf("IsAuthPath(%q) = true, want false", p)
		}
	}
}

func TestNewAuthPathMatcher_CustomList(t *testing.T) {
	m := NewAuthPathMatcher("/custom-login", "/legacy/")

	if !m.IsAuthPath("/custom-login") {
		t.Error("expected /custom-login to match an exact custom entry")
	}
	if !m.IsAuthPath("/legacy/session") {
		t.Error("expected /legacy/session to match the /legacy/ prefix")
	}
	if m.IsAuthPath("/login") {
		t.Error("a matcher built from a custom list must not fall back to the defaults")
	}
}
