//go:build linux

package discovery

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
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

// dhcpSnoopResult is the parsed identity from one DHCP client packet.
func parseDHCPPacket(frame []byte) (mac, reqIP, hostname, serverIP string, ok bool) { // Ethernet(14) + IPv4(>=20, proto UDP) + UDP(8, dport 67/68) + BOOTP(>=240).
	if len(frame) < 14+20+8+240 {
		return "", "", "", "", false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return "", "", "", "", false
	}
	ihl := int(frame[14]&0x0F) * 4
	if ihl < 20 || len(frame) < 14+ihl+8+240 {
		return "", "", "", "", false
	}
	ip := frame[14 : 14+ihl]
	if ip[9] != 17 { // UDP
		return "", "", "", "", false
	}
	udp := frame[14+ihl:]
	sport := binary.BigEndian.Uint16(udp[0:2])
	dport := binary.BigEndian.Uint16(udp[2:4])
	if (sport != 68 && dport != 67) && (sport != 67 && dport != 68) {
		return "", "", "", "", false
	}
	bootp := udp[8:]
	if len(bootp) < 240 {
		return "", "", "", "", false
	}
	if bootp[0] != 1 && bootp[0] != 2 { // BOOTREQUEST or BOOTREPLY
		return "", "", "", "", false
	}
	hwType, hwLen := bootp[1], int(bootp[2])
	if hwType != 1 || hwLen != 6 { // Ethernet
		return "", "", "", "", false
	}
	chaddr := net.HardwareAddr(bootp[28:34])
	if chaddr[0]&0x01 != 0 {
		return "", "", "", "", false // multicast/broadcast MAC
	}
	if binary.BigEndian.Uint32(bootp[236:240]) != 0x63825363 {
		return "", "", "", "", false // bad magic cookie
	}
	opts := bootp[240:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == 255 { // END
			break
		}
		if code == 0 { // PAD
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		ln := int(opts[i+1])
		if i+2+ln > len(opts) {
			break
		}
		val := opts[i+2 : i+2+ln]
		switch code {
		case 12: // Host Name
			hostname = sanitizeDHCPString(val)
		case 50: // Requested IP
			if len(val) == 4 {
				reqIP = net.IP(val).String()
			}
		case 54: // Server Identifier
			if len(val) == 4 {
				serverIP = net.IP(val).String()
			}
		}
		i += 2 + ln
	}
	// Fall back to the BOOTP yiaddr (offered/acked address) when the client
	// didn't include option 50 (e.g. DISCOVER without request, renewals).
	if reqIP == "" {
		if yiaddr := net.IP(bootp[16:20]); yiaddr.To4() != nil && !yiaddr.IsUnspecified() {
			reqIP = yiaddr.String()
		}
	}
	mac = chaddr.String()
	if hostname == "" && reqIP == "" {
		return "", "", "", "", false
	}
	return mac, reqIP, hostname, serverIP, true
}

// snoopHtons converts host to network byte order for socket protocols.
func snoopHtons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// sanitizeDHCPString keeps plausible hostnames, dropping binary garbage.
func sanitizeDHCPString(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			sb.WriteByte(c)
		} else if c == 0 {
			break
		} else {
			return ""
		}
	}
	s := sb.String()
	if len(s) < 2 || len(s) > 63 {
		return ""
	}
	return s
}
