package discovery

import (
	"context"
	"errors"
	"net"
	"syscall"
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

	// Very fast connects can be below the platform clock's resolution.
	if latency < 0 || latency > 100 {
		t.Errorf("expected reasonable local latency, got %f ms", latency)
	}
}

func TestOnlyConnectionRefusedCountsAsResponse(t *testing.T) {
	if !isConnectionRefused(&net.OpError{Err: syscall.ECONNREFUSED}) {
		t.Fatal("refusal not recognized")
	}
	for _, err := range []error{nil, context.DeadlineExceeded, errors.New("unreachable"), syscall.ENETUNREACH} {
		if isConnectionRefused(err) {
			t.Fatalf("misreported response for %v", err)
		}
	}
}
