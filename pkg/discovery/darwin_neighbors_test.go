package discovery

import "testing"

func TestDarwinNeighbors(t *testing.T) {
	out := "? (192.168.1.1) at a:b:c:d:e:f on en0 ifscope [ethernet]\n? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]\n? (999.1.1.1) at aa:bb:cc:dd:ee:ff on en0\n? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0\n"
	n := ParseDarwinARP(out)
	if len(n) != 1 || n[0].MACAddress != "0a:0b:0c:0d:0e:0f" || n[0].Interface != "en0" {
		t.Fatalf("neighbors: %+v", n)
	}
	ip, err := parseDarwinGateway("route to: default\n gateway: 192.168.1.1\n interface: en0\n")
	if err != nil || ip != "192.168.1.1" {
		t.Fatalf("gateway: %q %v", ip, err)
	}
	if _, err := parseDarwinGateway("gateway: link#4"); err == nil {
		t.Fatal("accepted non-IP gateway")
	}
}
