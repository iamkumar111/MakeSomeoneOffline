//go:build linux

package adapters

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBuildARPFrameLayout(t *testing.T) {
	src := mustMAC(t, "aa:bb:cc:dd:ee:01")
	dst := mustMAC(t, "aa:bb:cc:dd:ee:02")
	senderIP := net.ParseIP("192.168.1.10")
	targetIP := net.ParseIP("192.168.1.1")

	f, err := buildARPFrame(2, src, dst, src, senderIP, dst, targetIP)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 42 {
		t.Fatalf("expected 42-byte frame, got %d", len(f))
	}
	if binary.BigEndian.Uint16(f[12:14]) != 0x0806 {
		t.Fatal("wrong ethertype")
	}
	if binary.BigEndian.Uint16(f[20:22]) != 2 {
		t.Fatal("wrong opcode")
	}
	if ip := net.IP(f[28:32]).String(); ip != "192.168.1.10" {
		t.Fatalf("wrong sender IP: %s", ip)
	}
	if ip := net.IP(f[38:42]).String(); ip != "192.168.1.1" {
		t.Fatalf("wrong target IP: %s", ip)
	}
	if got := net.HardwareAddr(f[6:12]).String(); got != src.String() {
		t.Fatalf("wrong eth src: %s", got)
	}
}

func TestBuildARPFrameRejectsNonIPv4(t *testing.T) {
	m := mustMAC(t, "aa:bb:cc:dd:ee:01")
	if _, err := buildARPFrame(2, m, m, m, net.ParseIP("fe80::1"), m, net.ParseIP("fe80::2")); err == nil {
		t.Fatal("expected error for IPv6")
	}
	short := net.HardwareAddr{0x01, 0x02}
	if _, err := buildARPFrame(2, short, m, m, net.ParseIP("192.168.1.1"), m, net.ParseIP("192.168.1.2")); err == nil {
		t.Fatal("expected error for short MAC")
	}
}

// Healing frames must carry the TRUE owners' MACs as Ethernet source —
// otherwise "healing" keeps the poison alive.
func TestHealingFramesUseTrueMACs(t *testing.T) {
	gwIP := net.ParseIP("192.168.1.1")
	gwMAC := mustMAC(t, "00:11:22:33:44:55")
	tIP := net.ParseIP("192.168.1.18")
	tMAC := mustMAC(t, "00:e0:27:2e:b1:b3")

	frames := healingFrames(gwIP, gwMAC, tIP, tMAC)
	if len(frames) != 6 {
		t.Fatalf("expected 6 healing frames, got %d", len(frames))
	}
	for i, hp := range frames {
		ethSrc := net.HardwareAddr(hp.frame[6:12])
		senderMAC := net.HardwareAddr(hp.frame[22:28])
		if ethSrc.String() != senderMAC.String() {
			t.Fatalf("frame %d: eth src %s != claimed sender %s (still spoofed)", i, ethSrc, senderMAC)
		}
		if ethSrc.String() != gwMAC.String() && ethSrc.String() != tMAC.String() {
			t.Fatalf("frame %d: eth src %s is neither owner", i, ethSrc)
		}
	}
	// First frame restores the gateway mapping on the target.
	if ip := net.IP(frames[0].frame[28:32]).String(); ip != "192.168.1.1" {
		t.Fatalf("frame 0 should announce gateway IP, got %s", ip)
	}
}

func TestSelectCutInterfacePrefersGatewaySubnet(t *testing.T) {
	wifi := net.Interface{Index: 1, Name: "wlan0", HardwareAddr: mustMAC(t, "aa:bb:cc:dd:ee:01"), Flags: 0x1003}
	eth := net.Interface{Index: 2, Name: "eth0", HardwareAddr: mustMAC(t, "aa:bb:cc:dd:ee:02"), Flags: 0x1003}
	_, wifiNet, _ := net.ParseCIDR("10.10.0.5/24")
	_, ethNet, _ := net.ParseCIDR("192.168.1.50/24")
	cands := []ifaceCandidate{
		{iface: wifi, addrs: []net.Addr{&net.IPNet{IP: net.ParseIP("10.10.0.5"), Mask: wifiNet.Mask}}},
		{iface: eth, addrs: []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.50"), Mask: ethNet.Mask}}},
	}
	// Gateway is on eth0's subnet even though wlan0 sorts first.
	iface := selectCutInterfaceFrom(net.ParseIP("192.168.1.1"), cands)
	if iface == nil || iface.Name != "eth0" {
		t.Fatalf("expected eth0, got %+v", iface)
	}
	// Unknown subnet falls back to the first candidate.
	iface = selectCutInterfaceFrom(net.ParseIP("172.16.9.1"), cands)
	if iface == nil || iface.Name != "wlan0" {
		t.Fatalf("expected fallback wlan0, got %+v", iface)
	}
	if selectCutInterfaceFrom(net.ParseIP("192.168.1.1"), nil) != nil {
		t.Fatal("expected nil for no candidates")
	}
}

func TestForwardingEnabledFrom(t *testing.T) {
	dir := t.TempDir()
	on := filepath.Join(dir, "on")
	off := filepath.Join(dir, "off")
	if err := os.WriteFile(on, []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(off, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !forwardingEnabledFrom(on) {
		t.Fatal("expected true for '1'")
	}
	if forwardingEnabledFrom(off) {
		t.Fatal("expected false for '0'")
	}
	if !forwardingEnabledFrom(filepath.Join(dir, "missing")) {
		t.Fatal("unknown forwarding must require a firewall drop")
	}
}

func TestHealBurstCoversStubbornCaches(t *testing.T) {
	total := 0
	for i := 0; i < healRounds; i++ {
		total += 0 // rounds counted via vars below
	}
	_ = total
	if healRounds < 15 {
		t.Fatalf("healRounds=%d: too few to reliably heal Windows ARP caches", healRounds)
	}
	if d := healInterval; d < 100*time.Millisecond || d > time.Second {
		t.Fatalf("healInterval=%v out of sane range", d)
	}
}

func TestBuildNAFrameStructure(t *testing.T) {
	ethSrc := mustMAC(t, "8c:ec:4b:6f:b6:0c")
	ethDst := mustMAC(t, "00:e0:27:2e:b1:b3")
	srcIP := net.ParseIP("fe80::1")
	dstIP := net.ParseIP("fe80::abcd")
	claimedMAC := mustMAC(t, "8c:ec:4b:6f:b6:0c")

	f, err := buildNAFrame(ethSrc, ethDst, srcIP, dstIP, srcIP, claimedMAC)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 14+40+24+8 {
		t.Fatalf("expected 86-byte frame, got %d", len(f))
	}
	if binary.BigEndian.Uint16(f[12:14]) != 0x86DD {
		t.Fatal("wrong ethertype (want IPv6)")
	}
	ip6 := f[14:54]
	if ip6[0]>>4 != 6 {
		t.Fatal("wrong IP version")
	}
	if ip6[6] != 58 {
		t.Fatal("wrong next header (want ICMPv6)")
	}
	if ip6[7] != 255 {
		t.Fatal("NDP requires hop limit 255")
	}
	na := f[54 : 54+32]
	if na[0] != 136 || na[1] != 0 {
		t.Fatal("wrong ICMPv6 type/code (want NA)")
	}
	if na[4]&(0x20|0x40) == 0 {
		t.Fatal("expected Solicited+Override flags")
	}
	if net.IP(na[8:24]).String() != "fe80::1" {
		t.Fatalf("wrong target address: %s", net.IP(na[8:24]))
	}
	if na[24] != 2 || na[25] != 1 {
		t.Fatal("wrong target-ll option header")
	}
	if got := net.HardwareAddr(na[26:32]).String(); got != claimedMAC.String() {
		t.Fatalf("wrong claimed MAC: %s", got)
	}
	// Checksum must validate: recompute over frame with checksum zeroed.
	cpy := append([]byte(nil), f...)
	cpy[54+2], cpy[54+3] = 0, 0
	if got := icmpv6Checksum(net.ParseIP("fe80::1"), net.ParseIP("fe80::abcd"), cpy[54:54+32]); got != binary.BigEndian.Uint16(na[2:4]) {
		t.Fatalf("checksum mismatch: frame=%04x recomputed=%04x", binary.BigEndian.Uint16(na[2:4]), got)
	}
	if _, err := buildNAFrame(ethSrc, ethDst, net.ParseIP("192.168.1.1"), dstIP, srcIP, claimedMAC); err == nil {
		t.Fatal("expected error for IPv4 addresses")
	}
}

func TestParseIPv6Neigh(t *testing.T) {
	sample := "fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE\n" +
		"fe80::abcd dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE\n" +
		"fe80::dead dev eth0  FAILED\n" +
		"192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n"
	m := parseIPv6Neigh(sample)
	if len(m["00:11:22:33:44:55"]) != 1 || m["00:11:22:33:44:55"][0].String() != "fe80::1" {
		t.Fatalf("gateway addrs wrong: %v", m)
	}
	if len(m["aa:bb:cc:dd:ee:ff"]) != 1 {
		t.Fatalf("victim addrs wrong: %v", m)
	}
	for mac, ips := range m {
		for _, ip := range ips {
			if ip.String() == "fe80::dead" || ip.String() == "192.168.1.1" {
				t.Fatalf("bad entry leaked: %s -> %s", mac, ip)
			}
		}
	}
}

func TestHealingNAFramesUseTrueMACs(t *testing.T) {
	gwMAC := mustMAC(t, "00:11:22:33:44:55")
	tMAC := mustMAC(t, "00:e0:27:2e:b1:b3")
	frames := healingNAFrames(
		[]net.IP{net.ParseIP("fe80::1")}, gwMAC,
		[]net.IP{net.ParseIP("fe80::abcd")}, tMAC,
	)
	if len(frames) != 2 {
		t.Fatalf("expected 2 healing NAs, got %d", len(frames))
	}
	for i, hp := range frames {
		ethSrc := net.HardwareAddr(hp.frame[6:12]).String()
		sender := net.HardwareAddr(hp.frame[54+26 : 54+32]).String()
		if ethSrc != sender {
			t.Fatalf("frame %d: eth src %s != claimed %s", i, ethSrc, sender)
		}
		if sender != gwMAC.String() && sender != tMAC.String() {
			t.Fatalf("frame %d claims non-owner %s", i, sender)
		}
	}
}
