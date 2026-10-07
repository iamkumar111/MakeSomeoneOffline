package adapters

import (
	"fmt"
	"net"
	"strings"
)

func macRouteField(output, field string) string {
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == field+":" {
			return f[1]
		}
	}
	return ""
}

func macEthernetInterface(name string) bool {
	if !strings.HasPrefix(name, "en") || len(name) <= 2 || len(name) >= 16 {
		return false
	}
	for _, c := range name[2:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func parseMacNDP(output, iface string) map[string][]net.IP {
	out := make(map[string][]net.IP)
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[2] != iface || strings.EqualFold(f[4], "I") {
			continue
		}
		address := strings.Split(f[0], "%")
		if len(address) > 2 || (len(address) == 2 && address[1] != iface) {
			continue
		}
		ip := net.ParseIP(address[0])
		mac, err := macUnpaddedMAC(f[1])
		if ip == nil || ip.To4() != nil || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() || err != nil || !validUnicastMAC(mac) {
			continue
		}
		out[mac.String()] = append(out[mac.String()], ip)
	}
	return out
}
func macUnpaddedMAC(value string) (net.HardwareAddr, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid six-byte MAC")
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return net.ParseMAC(strings.Join(parts, ":"))
}
