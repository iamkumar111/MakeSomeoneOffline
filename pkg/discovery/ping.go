package discovery

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"
)

// MeasureLatency measures the TCP connect RTT to a host on a common port, or ICMP if available.
func MeasureLatency(ctx context.Context, ip string, port int, timeout time.Duration) (float64, error) {
	if port <= 0 {
		port = 80 // Default web port probe
	}
	target := net.JoinHostPort(ip, strconv.Itoa(port))

	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		// Even if rejected (connection refused), the round-trip still succeeded!
		rtt := float64(time.Since(start).Microseconds()) / 1000.0
		if isConnectionRefused(err) {
			return rtt, nil
		}
		return 0, err
	}
	defer conn.Close()

	rtt := float64(time.Since(start).Microseconds()) / 1000.0
	return rtt, nil
}

func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
