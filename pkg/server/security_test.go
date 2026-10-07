package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalAccessNeedsNoTokenAndRemoteRequiresAuthentication(t *testing.T) {
	t.Setenv("NETCUT_API_TOKEN", "a-test-token-for-remote-access")
	t.Setenv("ALLOWED_ORIGIN", "")
	s := &Server{}
	handler := s.secureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, tc := range []struct {
		name, host, remote, origin, auth, forwarded string
		status                                      int
	}{
		{"localhost without login", "localhost:8080", "127.0.0.1:5000", "", "", "", 204},
		{"local IP without login", "127.0.0.1:8080", "127.0.0.1:5000", "", "", "", 204},
		{"remote missing token", "192.168.1.28:8080", "192.168.1.24:5000", "", "", "", 401},
		{"remote spoofed host", "localhost:8080", "192.168.1.24:5000", "", "", "", 401},
		{"remote valid token", "192.168.1.28:8080", "192.168.1.24:5000", "", "Bearer a-test-token-for-remote-access", "", 204},
		{"evil origin with token", "localhost:8080", "127.0.0.1:5000", "https://evil.example", "Bearer a-test-token-for-remote-access", "", 403},
		{"userinfo origin spoof", "localhost:8080", "127.0.0.1:5000", "http://localhost:8080@evil.example", "", "", 403},
		{"forwarded remote not local", "localhost:8080", "127.0.0.1:5000", "", "", "192.168.1.24", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://"+tc.host+"/api/v1/freeze", nil)
			r.RemoteAddr = tc.remote
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Authorization", tc.auth)
			r.Header.Set("X-Forwarded-For", tc.forwarded)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRemoteAndDNSRebindingDeniedWithoutToken(t *testing.T) {
	t.Setenv("NETCUT_API_TOKEN", "")
	s := &Server{}
	handler := s.secureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("unauthorized request reached handler") }))
	r := httptest.NewRequest(http.MethodPost, "http://rebound.example/api/v1/freeze", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
}
