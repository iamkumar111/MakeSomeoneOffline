package adapters

import (
	"net"
	"strings"
	"testing"
)

func TestSelectDevice(t *testing.T) {
	t.Setenv("NETCUT_WIN_IFACE", "")
	devs := [][2]string{
		{`\Device\NPF_Loopback`, "127.0.0.1"},
		{`\Device\NPF_{VM}`, "192.168.56.1"},
		{`\Device\NPF_{WIFI}`, "192.168.1.28"},
	}

	// Gateway-subnet match beats first-private-IP order.
	name, ip, err := selectDevice(devs, "192.168.1.1")
	if err != nil || ip != "192.168.1.28" || name != `\Device\NPF_{WIFI}` {
		t.Fatalf("gateway-subnet select failed: %s %s %v", name, ip, err)
	}
	// Unknown gateway falls back to first private, non-loopback.
	name, ip, err = selectDevice(devs, "")
	if err != nil || ip != "192.168.56.1" {
		t.Fatalf("fallback select failed: %s %s %v", name, ip, err)
	}
	// Override mismatch lists candidates instead of failing blind.
	t.Setenv("NETCUT_WIN_IFACE", "nope")
	_, _, err = selectDevice(devs, "192.168.1.1")
	if err == nil {
		t.Fatal("expected override-mismatch error")
	}
	// Override by IP works.
	t.Setenv("NETCUT_WIN_IFACE", "192.168.56.1")
	_, ip, err = selectDevice(devs, "192.168.1.1")
	if err != nil || ip != "192.168.56.1" {
		t.Fatalf("override-by-IP failed: %s %v", ip, err)
	}
	// Empty enumeration is a clear Npcap-missing error.
	if _, _, err := selectDevice(nil, ""); err == nil {
		t.Fatal("expected empty-device error")
	}
}

func TestSelectLocalDevice(t *testing.T) {
	local := func(ip, cidr, mac string) localIPv4Interface {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		network.IP = net.ParseIP(ip)
		hw, err := net.ParseMAC(mac)
		if err != nil {
			t.Fatal(err)
		}
		return localIPv4Interface{network: network, mac: hw}
	}
	wifi := local("192.168.1.28", "192.168.1.0/24", "02:00:00:00:00:28")
	vm := local("192.168.56.1", "192.168.56.0/24", "02:00:00:00:00:56")
	devs := [][2]string{
		{`\Device\NPF_{STALE}`, "192.168.1.24"},
		{`\Device\NPF_{VM}`, "192.168.56.1"},
		{`\Device\NPF_{WIFI}`, "192.168.1.28"},
	}
	t.Setenv("NETCUT_WIN_IFACE", "")

	t.Run("target address is never used as local address", func(t *testing.T) {
		name, ip, mac, err := selectLocalDevice(devs, []localIPv4Interface{vm, wifi}, "192.168.1.1", "192.168.1.24")
		if err != nil || name != devs[2][0] || ip != "192.168.1.28" || mac.String() != wifi.mac.String() {
			t.Fatalf("selected %s %s %s: %v", name, ip, mac, err)
		}
	})
	t.Run("actual subnet mask rather than slash24", func(t *testing.T) {
		lan := local("10.20.3.8", "10.20.0.0/16", "02:00:00:00:00:08")
		_, ip, _, err := selectLocalDevice([][2]string{{"lan", "10.20.3.8"}}, []localIPv4Interface{lan}, "10.20.0.1", "10.20.9.24")
		if err != nil || ip != "10.20.3.8" {
			t.Fatalf("IP %s: %v", ip, err)
		}
	})
	t.Run("off link target rejected", func(t *testing.T) {
		_, _, _, err := selectLocalDevice(devs, []localIPv4Interface{wifi}, "192.168.1.1", "192.168.2.24")
		if err == nil {
			t.Fatal("accepted target outside local LAN")
		}
	})
	t.Run("stale capture address rejected", func(t *testing.T) {
		_, _, _, err := selectLocalDevice(devs[:1], []localIPv4Interface{wifi}, "192.168.1.1", "192.168.1.24")
		if err == nil || !strings.Contains(err.Error(), "no active local LAN interface") {
			t.Fatalf("error: %v", err)
		}
	})
	t.Run("override cannot select wrong LAN", func(t *testing.T) {
		t.Setenv("NETCUT_WIN_IFACE", "192.168.56.1")
		_, _, _, err := selectLocalDevice(devs, []localIPv4Interface{vm, wifi}, "192.168.1.1", "192.168.1.24")
		if err == nil || !strings.Contains(err.Error(), "NETCUT_WIN_IFACE") {
			t.Fatalf("error: %v", err)
		}
	})
	t.Run("probe uses same local selection", func(t *testing.T) {
		_, ip, _, err := selectLocalDevice(devs, []localIPv4Interface{wifi}, "192.168.1.1", "")
		if err != nil || ip != "192.168.1.28" {
			t.Fatalf("IP %s: %v", ip, err)
		}
	})
}
