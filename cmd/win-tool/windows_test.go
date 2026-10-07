//go:build windows

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveDeviceIDHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		// Even a decodable array must not be treated as an authorized inventory.
		_, _ = w.Write([]byte(`[{"id":"dev1","primary_ip":"192.168.1.24"}]`))
	}))
	defer server.Close()
	t.Setenv("OPEN_NETCUT_SERVER", server.URL)
	_, err := resolveDeviceID(server.Client(), "192.168.1.24")
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("expected actionable HTTP rejection, got %v", err)
	}
}

func TestResolveDeviceIDTargetLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"dev1","primary_ip":"192.168.1.24","primary_mac":"02:00:00:00:00:24"}]`))
	}))
	defer server.Close()
	t.Setenv("OPEN_NETCUT_SERVER", server.URL)
	for _, target := range []string{"dev1", "192.168.1.24", "02-00-00-00-00-24"} {
		id, err := resolveDeviceID(server.Client(), target)
		if err != nil || id != "dev1" {
			t.Fatalf("lookup %q: id=%q error=%v", target, id, err)
		}
	}
}
