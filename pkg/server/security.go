package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return strings.EqualFold(host, "localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}

func (s *Server) validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	} // CLI requests do not carry browser origins.
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if u.Scheme == scheme && strings.EqualFold(u.Host, r.Host) {
		return true
	}
	if configured := os.Getenv("ALLOWED_ORIGIN"); configured != "" && origin == configured {
		return true
	}
	return u.Scheme == "http" && loopbackHost(u.Host) && loopbackHost(r.Host)
}

func (s *Server) secureHandler(next http.Handler) http.Handler {
	// Capture configuration at server construction; never expose secrets in URLs.
	token := os.Getenv("NETCUT_API_TOKEN")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		if !s.validOrigin(r) {
			http.Error(w, "untrusted request origin", http.StatusForbidden)
			return
		}
		remoteHost, _, remoteErr := net.SplitHostPort(r.RemoteAddr)
		local := loopbackHost(r.Host) && remoteErr == nil && loopbackHost(remoteHost) && r.Header.Get("Forwarded") == "" && r.Header.Get("X-Forwarded-For") == ""
		if token == "" && !local {
			http.Error(w, "remote access requires NETCUT_API_TOKEN", http.StatusForbidden)
			return
		}
		if token != "" && !local && r.Method != http.MethodOptions {
			credential := ""
			if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
				credential = strings.TrimPrefix(header, "Bearer ")
			}
			if _, password, ok := r.BasicAuth(); ok {
				credential = password
			}
			if subtle.ConstantTimeCompare([]byte(credential), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Open-NetCut", charset="UTF-8"`)
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}
