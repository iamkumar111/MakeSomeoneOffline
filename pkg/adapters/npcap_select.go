package adapters

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Pure Npcap device-selection logic (no syscalls): portable and unit-tested.
// The Windows transport feeds it enumeration results.

// selectDevice picks the capture device: NETCUT_WIN_IFACE override (NPF name
// substring or IPv4), else the device on the gateway's subnet (a multi-homed
// host often has VM/VPN adapters with private IPs — the first private IPv4
// is frequently the wrong network), else the first usable device.
func selectDevice(devices [][2]string, gatewayIP string) (name, ip string, err error) {
	if len(devices) == 0 {
		return "", "", fmt.Errorf("no Npcap devices with IPv4 addresses found (is Npcap installed and the npcap service running?)")
	}
	candidates := func() string {
		var b strings.Builder
		for _, d := range devices {
			fmt.Fprintf(&b, "\n  %s (%s)", d[0], d[1])
		}
		return b.String()
	}
	if want := strings.TrimSpace(strings.ToLower(os.Getenv("NETCUT_WIN_IFACE"))); want != "" {
		for _, d := range devices {
			if strings.Contains(strings.ToLower(d[0]), want) || strings.ToLower(d[1]) == want {
				return d[0], d[1], nil
			}
		}
		return "", "", fmt.Errorf("NETCUT_WIN_IFACE %q matched no Npcap device; candidates:%s", want, candidates())
	}
	if gw := net.ParseIP(gatewayIP); gw != nil {
		for _, d := range devices {
			if ip := net.ParseIP(d[1]); ip != nil && sameSlash24(ip, gw) {
				return d[0], d[1], nil
			}
		}
	}
	for _, d := range devices {
		if ip := net.ParseIP(d[1]); ip != nil && ip.IsPrivate() && !ip.IsLoopback() {
			return d[0], d[1], nil
		}
	}
	for _, d := range devices {
		if ip := net.ParseIP(d[1]); ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return d[0], d[1], nil
		}
	}
	return devices[0][0], devices[0][1], nil
}

// sameSlash24 reports whether two IPv4 addresses share a /24. The gateway
// practically always sits in the interface's own /24; this is a selection
// heuristic, not a subnet calculation.
func sameSlash24(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	return a4 != nil && b4 != nil && a4[0] == b4[0] && a4[1] == b4[1] && a4[2] == b4[2]
}
