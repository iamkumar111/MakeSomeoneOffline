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

func TestParseNetshIPv6Neighbors(t *testing.T) {
	output := "Interface 12: Wi-Fi\r\n" +
		"Internet Address                              Physical Address   Type\r\n" +
		"-------------------------------------------- ------------------ -----------\r\n" +
		"fe80::1                                       8c-ec-4b-aa-bb-cc  Reachable\r\n" +
		"fe80::abcd                                    00-E0-22-43-51-6F  Stale\r\n" +
		"fe80::dead                                    00-11-22-33-44-55  Incomplete\r\n" +
		"ff02::1                                       33-33-00-00-00-01  Permanent\r\n"
	got := ParseNetshIPv6Neighbors(output)
	if len(got) != 3 {
		t.Fatalf("expected 3 MACs (incomplete skipped), got %d: %v", len(got), got)
	}
	if len(got["8c:ec:4b:aa:bb:cc"]) != 1 || got["8c:ec:4b:aa:bb:cc"][0].String() != "fe80::1" {
		t.Fatalf("bad gateway entry: %v", got)
	}
	if len(got["00:e0:22:43:51:6f"]) != 1 {
		t.Fatalf("MAC should normalize separators/case: %v", got)
	}
}
