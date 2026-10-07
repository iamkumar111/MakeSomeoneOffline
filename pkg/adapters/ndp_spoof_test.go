package adapters

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// Portable contract: the NA storm used by both Linux and Windows transports.
func TestRunNAStormPoisonsBothDirections(t *testing.T) {
	hostMAC := mustParseMAC(t, "aa:bb:cc:dd:ee:ff")
	victimMAC := mustParseMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustParseMAC(t, "00:11:22:33:44:55")
	victimIPs := []net.IP{net.ParseIP("fe80::50")}
	gwIPs := []net.IP{net.ParseIP("fe80::1")}

	type sent struct {
		dst   net.HardwareAddr
		frame []byte
	}
	var got []sent
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runNAStorm(stop, func(dst net.HardwareAddr, f []byte) {
			got = append(got, sent{dst, f})
		}, hostMAC, victimMAC, gwMAC, victimIPs, gwIPs, true)
	}()
	time.Sleep(1100 * time.Millisecond) // initial burst + ~1 tick
	close(stop)
	<-done

	if len(got) < 2 {
		t.Fatalf("expected frames in both directions, got %d", len(got))
	}
	var toGW, toVictim int
	for _, s := range got {
		na := s.frame[54 : 54+32]
		if na[0] != 136 {
			t.Fatalf("not a Neighbor Advertisement: %d", na[0])
		}
		if na[4]&(0x20|0x40) != (0x20 | 0x40) {
			t.Fatalf("poison NA must set Solicited+Override, got %#x", na[4])
		}
		claimed := net.HardwareAddr(s.frame[54+26 : 54+32])
		if claimed.String() != hostMAC.String() {
			t.Fatalf("poison NA must claim our MAC, got %s", claimed)
		}
		// EtherType must be IPv6 (Npcap/AF_PACKET both key off it).
		if binary.BigEndian.Uint16(s.frame[12:14]) != 0x86DD {
			t.Fatalf("bad ethertype %#x", binary.BigEndian.Uint16(s.frame[12:14]))
		}
		switch s.dst.String() {
		case gwMAC.String():
			toGW++
		case victimMAC.String():
			toVictim++
		default:
			t.Fatalf("unexpected dst %s", s.dst)
		}
	}
	if toGW == 0 || toVictim == 0 {
		t.Fatalf("need both directions, toGW=%d toVictim=%d", toGW, toVictim)
	}
}
