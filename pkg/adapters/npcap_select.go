package adapters

import (
	"fmt"
	"net"
	"os"
	"strings"
)

type localIPv4Interface struct {
	mac     net.HardwareAddr
	network *net.IPNet
}

// localIPv4Interfaces uses the OS address table as the authority for local
// addresses. Npcap can still report an old address after a DHCP/adapter change.
func localIPv4Interfaces() ([]localIPv4Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []localIPv4Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("read addresses for %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			if network, ok := addr.(*net.IPNet); ok && network.IP.To4() != nil {
				out = append(out, localIPv4Interface{mac: iface.HardwareAddr, network: network})
			}
		}
	}
	return out, nil
}

// selectLocalDevice joins capture addresses to active local interfaces before
// selection, and requires an on-link path to the gateway and quarantine target.
// A remote or stale capture address must never be used as our host address.
func selectLocalDevice(devices [][2]string, locals []localIPv4Interface, gatewayIP, targetIP string) (name, ip string, mac net.HardwareAddr, err error) {
	gw := net.ParseIP(gatewayIP)
	if gw == nil || gw.To4() == nil {
		return "", "", nil, fmt.Errorf("invalid LAN gateway IPv4 %q", gatewayIP)
	}
	var target net.IP
	if targetIP != "" {
		target = net.ParseIP(targetIP)
		if target == nil || target.To4() == nil {
			return "", "", nil, fmt.Errorf("invalid target IPv4 %q", targetIP)
		}
	}
	var eligible [][2]string
	macs := make(map[string]net.HardwareAddr)
	for _, d := range devices {
		captureIP := net.ParseIP(d[1])
		for _, local := range locals {
			if local.network == nil || len(local.mac) != 6 || !local.network.IP.Equal(captureIP) {
				continue
			}
			if !local.network.Contains(gw) || (target != nil && !local.network.Contains(target)) {
				continue
			}
			eligible = append(eligible, d)
			macs[d[1]] = local.mac
			break
		}
	}
	if len(eligible) == 0 {
		var details strings.Builder
		for _, d := range devices {
			fmt.Fprintf(&details, "\n  Npcap: %s (%s)", d[0], d[1])
		}
		for _, local := range locals {
			if local.network != nil {
				fmt.Fprintf(&details, "\n  Local: %s (MAC %s)", local.network, local.mac)
			}
		}
		return "", "", nil, fmt.Errorf("no active local LAN interface exposed by Npcap can reach gateway %s and target %s; check the LAN connection and restart Npcap after address changes; candidates:%s", gatewayIP, targetIP, details.String())
	}
	name, ip, err = selectDevice(eligible, gatewayIP)
	if err != nil {
		return "", "", nil, err
	}
	return name, ip, macs[ip], nil
}

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
