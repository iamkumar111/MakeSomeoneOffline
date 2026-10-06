package adapters

import (
	"encoding/binary"
	"net"
	"testing"
)

// Portable contract both Linux (AF_PACKET) and Windows (Npcap) transports rely on.
func TestPoisonFrameClaimsOperatorMAC(t *testing.T) {
	hostMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	gwIP, gwMAC := net.ParseIP("192.168.1.1"), mustParseMAC(t, "00:11:22:33:44:55")
	victimIP, victimMAC := net.ParseIP("192.168.1.50"), mustParseMAC(t, "66:77:88:99:aa:bb")

	// Victim-directed frame: gateway IP claimed at OUR mac.
	f, err := buildARPFrame(2, hostMAC, victimMAC, hostMAC, gwIP, victimMAC, victimIP)
	if err != nil {
		t.Fatal(err)
	}
	if got := net.HardwareAddr(f[22:28]); got.String() != hostMAC.String() {
		t.Fatalf("sender MAC should be ours, got %s", got)
	}
	if got := net.IP(f[28:32]); !got.Equal(gwIP) {
		t.Fatalf("sender IP should be gateway, got %s", got)
	}

	// Healing frames must carry TRUE owner MACs, never ours.
	for _, hp := range healingFrames(gwIP, gwMAC, victimIP, victimMAC) {
		if src := net.HardwareAddr(hp.frame[6:12]); src.String() == hostMAC.String() {
			t.Fatalf("heal frame carries poison MAC %s", src)
		}
		if op := binary.BigEndian.Uint16(hp.frame[20:22]); op != 1 && op != 2 {
			t.Fatalf("bad ARP opcode %d", op)
		}
	}
}

func mustParseMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
