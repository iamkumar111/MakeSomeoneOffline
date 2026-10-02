package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeJPEG builds a minimal valid JPEG body (>1KB so the size gate passes).
func fakeJPEG() []byte {
	body := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00}
	for len(body) < 2048 {
		body = append(body, 0x00)
	}
	return body
}

func TestTrySnapshotURLFindsImage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/snapshot.jpg" {
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write(fakeJPEG())
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	ctx := context.Background()

	ct, n, ok := trySnapshotURL(client, ctx, srv.URL+"/snapshot.jpg")
	if !ok || ct != "image/jpeg" || n < 1024 {
		t.Fatalf("expected image found, got ct=%q n=%d ok=%v", ct, n, ok)
	}
	if _, _, ok := trySnapshotURL(client, ctx, srv.URL+"/nope.jpg"); ok {
		t.Fatal("expected 404 path to fail")
	}
}

func TestTrySnapshotURLRejectsNonImages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login.html":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><title>Login</title></html>")
		case "/tiny.jpg":
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write([]byte{0xFF, 0xD8, 0xFF}) // too small, no magic match
		case "/wrongtype.jpg":
			w.Header().Set("Content-Type", "image/jpeg")
			body := make([]byte, 2048) // right size, wrong bytes
			_, _ = w.Write(body)
		}
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	ctx := context.Background()
	for _, p := range []string{"/login.html", "/tiny.jpg", "/wrongtype.jpg"} {
		if _, _, ok := trySnapshotURL(client, ctx, srv.URL+p); ok {
			t.Fatalf("expected %s to be rejected", p)
		}
	}
}

func TestLooksLikeImage(t *testing.T) {
	jpeg := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, make([]byte, 100)...)
	if !looksLikeImage(jpeg) {
		t.Fatal("expected jpeg magic to pass")
	}
	if looksLikeImage([]byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatal("expected random bytes to fail")
	}
	if looksLikeImage([]byte{0xFF}) {
		t.Fatal("expected short input to fail")
	}
}
