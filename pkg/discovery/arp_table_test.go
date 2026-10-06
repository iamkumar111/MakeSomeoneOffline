package discovery

import "testing"

func TestParseArpTable(t *testing.T) {
	output := "Interface: 192.168.1.28 --- 0x10\r\n" +
		"  Internet Address      Physical Address      Type\r\n" +
		"  192.168.1.1           8c-ec-4b-aa-bb-cc     dynamic\r\n" +
		"  192.168.1.22          00:E0:22:43:51:6F     dynamic\r\n"
	got := ParseArpTable(output)
	if len(got) != 2 {
		t.Fatalf("expected 2 neighbors, got %d", len(got))
	}
	if got[0].Interface != "192.168.1.28" || got[0].MACAddress != "8c:ec:4b:aa:bb:cc" {
		t.Fatalf("unexpected first neighbor: %+v", got[0])
	}
	if got[1].MACAddress != "00:e0:22:43:51:6f" {
		t.Fatalf("unexpected second neighbor: %+v", got[1])
	}
}
