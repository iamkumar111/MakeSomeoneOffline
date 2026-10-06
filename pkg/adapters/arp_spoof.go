package adapters

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Shared ARP spoof/heal frame logic. Transport (AF_PACKET on Linux,
// Npcap on Windows) only moves these bytes; the poisoning semantics are
// identical: victims and gateways are told the operator's MAC owns the
// other side's IP, and release sends genuine-MAC healing frames.

// buildARPFrame constructs a 42-byte Ethernet+ARP frame. Ethernet source
// MUST equal the claimed sender MAC for legitimate packets (replies, healing,
// gratuitous announcements); poisoning packets intentionally set both to ours.
func buildARPFrame(op uint16, ethSrc, ethDst, senderMAC net.HardwareAddr, senderIP net.IP, targetMAC net.HardwareAddr, targetIP net.IP) ([]byte, error) {
	if len(ethSrc) != 6 || len(ethDst) != 6 || len(senderMAC) != 6 || len(targetMAC) != 6 {
		return nil, fmt.Errorf("all MAC addresses must be 6 bytes")
	}
	sIP := senderIP.To4()
	tIP := targetIP.To4()
	if sIP == nil || tIP == nil {
		return nil, fmt.Errorf("only IPv4 is supported (got %s -> %s)", senderIP, targetIP)
	}

	frame := make([]byte, 42)
	copy(frame[0:6], ethDst)
	copy(frame[6:12], ethSrc)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806) // EtherType ARP

	binary.BigEndian.PutUint16(frame[14:16], 1)      // Hardware: Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // Protocol: IPv4
	frame[18] = 6                                    // HW Len
	frame[19] = 4                                    // Proto Len
	binary.BigEndian.PutUint16(frame[20:22], op)     // Opcode: 1=Req, 2=Reply

	copy(frame[22:28], senderMAC)
	copy(frame[28:32], sIP)
	copy(frame[32:38], targetMAC)
	copy(frame[38:42], tIP)
	return frame, nil
}

// Healing burst: stubborn stacks (notably Windows) ignore a single
// gratuitous ARP, so restoration repeats ~5s. Shorter bursts left victims
// offline until they re-ARP'd on their own (or the user reconnected).
var (
	healRounds   = 20
	healInterval = 250 * time.Millisecond
)

// healPacket is one restoration frame plus its Ethernet destination.
type healPacket struct {
	dst   net.HardwareAddr
	frame []byte
}

// healingFrames builds cache-restoration packets for lifting a cut.
// Every frame carries the TRUE owner's MAC as Ethernet source — that is what
// distinguishes healing from poisoning.
func healingFrames(gwIP net.IP, gwMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr) []healPacket {
	bcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	type spec struct {
		op       uint16
		ethSrc   net.HardwareAddr
		ethDst   net.HardwareAddr
		senderIP net.IP
		sender   net.HardwareAddr
		tgtIP    net.IP
		tgtMAC   net.HardwareAddr
	}
	specs := []spec{
		// Tell target: gateway is really at gwMAC.
		{2, gwMAC, targetMAC, gwIP, gwMAC, targetIP, targetMAC},
		{1, gwMAC, targetMAC, gwIP, gwMAC, targetIP, targetMAC},
		// Tell gateway: target is really at targetMAC.
		{2, targetMAC, gwMAC, targetIP, targetMAC, gwIP, gwMAC},
		{1, targetMAC, gwMAC, targetIP, targetMAC, gwIP, gwMAC},
		// Gratuitous broadcasts so switches relearn ports too.
		{2, gwMAC, bcast, gwIP, gwMAC, gwIP, bcast},
		{2, targetMAC, bcast, targetIP, targetMAC, targetIP, bcast},
	}
	var out []healPacket
	for _, s := range specs {
		f, err := buildARPFrame(s.op, s.ethSrc, s.ethDst, s.sender, s.senderIP, s.tgtMAC, s.tgtIP)
		if err != nil {
			continue
		}
		out = append(out, healPacket{dst: s.ethDst, frame: f})
	}
	return out
}
