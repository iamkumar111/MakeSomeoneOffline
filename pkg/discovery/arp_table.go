package discovery

import (
	"net"
	"regexp"
	"strings"
)

// ArpNeighbor is one parsed IPv4 neighbor entry from `arp -a`.
type ArpNeighbor struct {
	IPAddress  string
	MACAddress string
	Type       string
	Interface  string
}

var arpTableLine = regexp.MustCompile(`(?i)^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\s+(\S+)\s*$`)
var arpInterfaceLine = regexp.MustCompile(`(?i)^\s*interface:\s*(\d{1,3}(?:\.\d{1,3}){3})\b`)
var netshNeighLine = regexp.MustCompile(`(?i)^\s*([0-9a-f:]+:+[0-9a-f:.]+)\s+([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\s+(\S+)\s*$`)

// ParseArpTable parses Windows `arp -a` output. It tolerates hyphen- or
// colon-separated MAC addresses and ignores interface headers.
func ParseArpTable(output string) []ArpNeighbor {
	neighbors := make([]ArpNeighbor, 0)
	currentInterface := ""
	for _, line := range strings.Split(output, "\n") {
		if m := arpInterfaceLine.FindStringSubmatch(line); m != nil {
			currentInterface = m[1]
			continue
		}
		m := arpTableLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		typ := strings.ToLower(m[3])
		if typ != "dynamic" && typ != "static" {
			continue
		}
		neighbors = append(neighbors, ArpNeighbor{
			IPAddress:  m[1],
			MACAddress: strings.ToLower(strings.ReplaceAll(m[2], "-", ":")),
			Type:       typ,
			Interface:  currentInterface,
		})
	}
	return neighbors
}

// ParseNetshIPv6Neighbors parses `netsh interface ipv6 show neighbors`
// output into IPv6 addresses per lowercase MAC, skipping Unreachable and
// Incomplete entries (same semantics as parseIPv6Neigh on Linux).
func ParseNetshIPv6Neighbors(output string) map[string][]net.IP {
	out := make(map[string][]net.IP)
	for _, line := range strings.Split(output, "\n") {
		m := netshNeighLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		state := strings.ToUpper(m[3])
		if state == "UNREACHABLE" || state == "INCOMPLETE" {
			continue
		}
		ip := net.ParseIP(m[1])
		if ip == nil || ip.To4() != nil {
			continue
		}
		mac := strings.ToLower(strings.ReplaceAll(m[2], "-", ":"))
		out[mac] = append(out[mac], ip)
	}
	return out
}
