package apiclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenIsSentButNotForwardedToAnotherOrigin(t *testing.T) {
	t.Setenv("NETCUT_API_TOKEN", "test-remote-token")
	visited := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { visited = true }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-remote-token" {
			t.Error("missing API token")
		}
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer server.Close()
	resp, err := New(time.Second).Get(server.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || visited {
		t.Fatalf("redirect err=%v visited=%v", err, visited)
	}
}
