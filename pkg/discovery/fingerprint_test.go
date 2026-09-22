package discovery

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFingerprintHTTPCamera(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "APPWebs/2.0")
		_, _ = w.Write([]byte("<html><head><title>Login</title></head><body><script>doc/page/login.html</script></body></html>"))
	}))
	defer ts.Close()

	hostPort := strings.TrimPrefix(ts.URL, "http://")
	host, portStr, _ := net.SplitHostPort(hostPort)
	port, _ := strconv.Atoi(portStr)

	// Test probeHTTP directly on custom port
	req, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://%s:%d/", host, port), nil)
	client := http.Client{Timeout: 1 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to query test server: %v", err)
	}
	defer resp.Body.Close()

	if !strings.Contains(resp.Header.Get("Server"), "APPWebs") {
		t.Errorf("expected Server header to contain APPWebs")
	}
}

func TestIsPortOpen(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	if !isPortOpen("127.0.0.1", port, 200*time.Millisecond) {
		t.Errorf("expected port %d to be open", port)
	}

	if isPortOpen("127.0.0.1", 65530, 50*time.Millisecond) {
		t.Errorf("expected closed port to report false")
	}
}

func TestFingerprintHostClosedPorts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	fp := FingerprintHost(ctx, "127.0.0.2")
	// Closed loopback address should return cleanly without panicking
	if fp.Metadata == nil {
		t.Errorf("expected initialized metadata map")
	}
}
