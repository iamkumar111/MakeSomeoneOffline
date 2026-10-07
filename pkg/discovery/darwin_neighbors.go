package discovery

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// ParseDarwinARP accepts macOS arp -an output, including unpadded MAC octets.
func ParseDarwinARP(output string) []ArpNeighbor {
	var neighbors []ArpNeighbor
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[2] != "at" || f[4] != "on" {
			continue
		}
		ip := net.ParseIP(strings.Trim(f[1], "()"))
		if ip == nil || ip.To4() == nil {
			continue
		}
		parts := strings.Split(f[3], ":")
		if len(parts) != 6 {
			continue
		}
		for i, part := range parts {
			if len(part) == 1 {
				parts[i] = "0" + part
			}
		}
		mac, err := net.ParseMAC(strings.Join(parts, ":"))
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
			continue
		}
		neighbors = append(neighbors, ArpNeighbor{IPAddress: ip.String(), MACAddress: mac.String(), Interface: f[5], Type: "dynamic"})
	}
	return neighbors
}

func parseDarwinGateway(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "gateway:" {
			if ip := net.ParseIP(f[1]); ip != nil && ip.To4() != nil {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("IPv4 default gateway not found")
}

func (s *NetworkScanner) readDarwinArp(ctx context.Context) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/arp", "-an").Output()
	if err != nil {
		return
	}
	for _, n := range ParseDarwinARP(string(out)) {
		if !isPhysicalInterfaceName(n.Interface) {
			continue
		}
		s.fusionEngine.IngestObservation(models.Observation{Timestamp: time.Now().UTC(), Source: "arp_darwin", MAC: n.MACAddress, IP: n.IPAddress, Interface: n.Interface, Attributes: map[string]interface{}{"is_online": true}})
	}
}

func getDarwinDefaultGateway(ctx context.Context) (string, string, error) {
	out, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("macOS default route: %w", err)
	}
	ip, err := parseDarwinGateway(string(out))
	if err != nil {
		return "", "", err
	}
	out, err = exec.CommandContext(ctx, "/usr/sbin/arp", "-an").Output()
	if err == nil {
		for _, n := range ParseDarwinARP(string(out)) {
			if n.IPAddress == ip {
				return ip, n.MACAddress, nil
			}
		}
	}
	return ip, "", nil
}
