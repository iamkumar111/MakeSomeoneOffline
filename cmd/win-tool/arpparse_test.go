package main

import "testing"

func TestParseWindowsArp(t *testing.T) {
	output := "Interface: 192.168.1.28 --- 0x10\r\n" +
		"  Internet Address      Physical Address      Type\r\n" +
		"  192.168.1.1           8c-ec-4b-aa-bb-cc     dynamic\r\n" +
		"  192.168.1.22          00:E0:22:43:51:6F     dynamic\r\n" +
		"  224.0.0.22            01-00-5e-00-00-16     static\r\n" +
		"  not-an-entry\r\n"
	got := ParseWindowsArp(output)
	if len(got) != 3 {
		t.Fatalf("expected 3 neighbors, got %d (%v)", len(got), got)
	}
	if got[0].IPAddress != "192.168.1.1" || got[0].MACAddress != "8c:ec:4b:aa:bb:cc" || got[0].Type != "dynamic" {
		t.Fatalf("unexpected first neighbor: %+v", got[0])
	}
	if got[1].MACAddress != "00:e0:22:43:51:6f" {
		t.Fatalf("MAC should keep value but normalize separators/case: %+v", got[1])
	}
}
