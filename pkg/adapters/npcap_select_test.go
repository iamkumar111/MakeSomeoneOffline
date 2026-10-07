package adapters

import "testing"

func TestSelectDevice(t *testing.T) {
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
