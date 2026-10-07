//go:build linux

package discovery

import (
	"context"
	"sync"
	"syscall"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// DHCPSnooper passively captures DHCP client requests (DISCOVER/REQUEST) via
// a raw AF_PACKET socket and extracts client MAC, requested IP, hostname
// (option 12) and server ID (option 54). Raw sockets are used instead of UDP
// :68 because the host's own DHCP client already owns that port.
//
// This is the highest-quality name source on most LANs: nearly every device
// (phones, IoT, Windows, printers) announces its hostname in DHCP, with no
// firewall or responder required on the device side.
type DHCPSnooper struct {
	fusionEngine *IdentityFusionEngine
	mu           sync.Mutex
	rawFD        int
	stopCh       chan struct{}
	running      bool
}

// NewDHCPSnooper creates the passive DHCP listener.
func NewDHCPSnooper(fusion *IdentityFusionEngine) *DHCPSnooper {
	return &DHCPSnooper{
		fusionEngine: fusion,
		stopCh:       make(chan struct{}),
	}
}

// Start begins background capture. No-op if the socket cannot be opened
// (needs root/CAP_NET_RAW); discovery continues via other sources.
func (s *DHCPSnooper) Start(ctx context.Context) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(snoopHtons(syscall.ETH_P_IP)))
	if err != nil {
		return
	}
	s.mu.Lock()
	s.rawFD = fd
	s.running = true
	s.mu.Unlock()

	go s.captureLoop(ctx)
}

// Stop terminates capture.
func (s *DHCPSnooper) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		close(s.stopCh)
		s.running = false
	}
	if s.rawFD > 0 {
		_ = syscall.Close(s.rawFD)
		s.rawFD = -1
	}
}

func (s *DHCPSnooper) captureLoop(ctx context.Context) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}
		s.mu.Lock()
		fd := s.rawFD
		s.mu.Unlock()
		if fd <= 0 {
			return
		}
		_ = syscall.SetNonblock(fd, true)
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				return
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}
		if mac, reqIP, hostname, serverIP, ok := parseDHCPPacket(buf[:n]); ok {
			attrs := map[string]interface{}{"service_proto": "dhcp-snoop"}
			if serverIP != "" {
				attrs["dhcp_server_ip"] = serverIP
			}
			s.fusionEngine.IngestObservation(models.Observation{
				Timestamp:  time.Now().UTC(),
				Source:     "dhcp",
				MAC:        mac,
				IP:         reqIP,
				Hostname:   hostname,
				Attributes: attrs,
			})
		}
	}
}

// snoopHtons converts host to network byte order for socket protocols.
func snoopHtons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
