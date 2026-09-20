package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestMeasureLatencyLocalhost(t *testing.T) {
	// Spin up local TCP test listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	latency, err := MeasureLatency(context.Background(), "127.0.0.1", port, 1*time.Second)
	if err != nil {
		t.Fatalf("expected successful measurement, got: %v", err)
	}

	if latency <= 0 || latency > 100 {
		t.Errorf("expected reasonable local latency, got %f ms", latency)
	}
}
