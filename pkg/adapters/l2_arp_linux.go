//go:build linux

package adapters

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// L2ARPAdapter implements Layer-2 ARP quarantine for flat switched networks.
type L2ARPAdapter struct {
	mu          sync.Mutex
	gwIP        net.IP
	gwMAC       net.HardwareAddr
	iface       *net.Interface
	hostMAC     net.HardwareAddr
	nft         *LinuxNFTablesAdapter
	rawFD       int
	activeCuts  map[string]chan struct{} // keyed by TargetIP
	targetMACs  map[string]net.HardwareAddr
	isAvailable bool
	closed      bool
	stopListen  chan struct{}
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// NewL2ARPAdapter creates an L2 ARP quarantine adapter with raw packet sockets.
func NewL2ARPAdapter(gwIPStr, gwMACStr string, iface *net.Interface, nft *LinuxNFTablesAdapter) (*L2ARPAdapter, error) {
	gwIP := net.ParseIP(gwIPStr)
	if gwIP == nil || gwIP.To4() == nil {
		return nil, fmt.Errorf("invalid gateway IPv4: %s", gwIPStr)
	}
	gwMAC, err := net.ParseMAC(gwMACStr)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway MAC: %s", gwMACStr)
	}

	if iface == nil {
		iface = selectCutInterface(gwIP)
	}

	if iface == nil {
		return nil, fmt.Errorf("no suitable physical network interface found")
	}

	adapter := &L2ARPAdapter{
		gwIP:        gwIP,
		gwMAC:       gwMAC,
		iface:       iface,
		hostMAC:     iface.HardwareAddr,
		nft:         nft,
		activeCuts:  make(map[string]chan struct{}),
		targetMACs:  make(map[string]net.HardwareAddr),
		stopListen:  make(chan struct{}),
		isAvailable: true,
	}

	// Open raw AF_PACKET socket for ARP
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		adapter.isAvailable = false
		return adapter, nil
	}
	adapter.rawFD = fd

	// Start responsive listener for who-has requests
	go adapter.listenAndIntercept()

	return adapter, nil
}

// ifaceCandidate pairs an interface with its addresses for subnet matching.
type ifaceCandidate struct {
	iface net.Interface
	addrs []net.Addr
}

// selectCutInterface picks the physical interface to spoof from: the one
// whose subnet contains the gateway (multi-homed boxes often have several
// NICs; the FIRST one is frequently the wrong network). Falls back to the
// first usable physical interface.
func selectCutInterface(gwIP net.IP) *net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var cands []ifaceCandidate
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || len(ifi.HardwareAddr) != 6 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		cands = append(cands, ifaceCandidate{iface: ifi, addrs: addrs})
	}
	return selectCutInterfaceFrom(gwIP, cands)
}

// selectCutInterfaceFrom is the testable core of selectCutInterface.
func selectCutInterfaceFrom(gwIP net.IP, cands []ifaceCandidate) *net.Interface {
	for i := range cands {
		for _, a := range cands[i].addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.Contains(gwIP) {
				iface := cands[i].iface
				return &iface
			}
		}
	}
	if len(cands) > 0 {
		iface := cands[0].iface
		return &iface
	}
	return nil
}

func (a *L2ARPAdapter) Name() string {
	return "l2_arp"
}
func (a *L2ARPAdapter) Capabilities() []string {
	return []string{"quarantine", "l2_arp_cut", "packet_redirection"}
}

func (a *L2ARPAdapter) Describe() AdapterInfo {
	return AdapterInfo{
		Name: "l2_arp", Label: "L2 ARP Cut — side-host LAN quarantine (disruptive)",
		Kind: KindLab, Effectiveness: 4,
		Capabilities:       a.Capabilities(),
		RecommendedWhen:    "Side host on an unmanaged LAN (this box is NOT the gateway): redirects victim↔gateway traffic through this host, then drops it. Works for wired and WiFi alike.",
		Requires:           "Linux + root + raw socket, gateway IP/MAC auto-detected, same broadcast domain as victim.",
		Description:        "ARP enforcement (same technique as NetCut/NAC appliances): poison victim and gateway caches, drop the attracted traffic via nftables. Explicit selection only — never automatic.",
		Warning:            "Use ONLY on networks you own. Disruptive by design; victims see a network outage. Short TTL recommended; lifting the quarantine heals caches automatically.",
		LabOnly:            true,
		SupportsQuarantine: true, SupportsShaping: false,
	}
}

func (a *L2ARPAdapter) IsAvailable(ctx context.Context) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.isAvailable && a.rawFD > 0
}

func (a *L2ARPAdapter) sendARPPacket(op uint16, srcMAC, destMAC net.HardwareAddr, senderIP, targetIP net.IP, senderMAC, targetMAC net.HardwareAddr) error {
	frame, err := buildARPFrame(op, srcMAC, destMAC, senderMAC, senderIP, targetMAC, targetIP)
	if err != nil {
		return err
	}
	return a.sendRaw(destMAC, frame, syscall.ETH_P_ARP)
}

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

// sendRaw transmits a prebuilt frame to ethDst with the given EtherType.
func (a *L2ARPAdapter) sendRaw(ethDst net.HardwareAddr, frame []byte, ethProto uint16) error {
	if a.rawFD <= 0 || a.iface == nil {
		return fmt.Errorf("raw socket not open")
	}
	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(ethProto),
		Ifindex:  a.iface.Index,
		Halen:    6,
	}
	copy(sll.Addr[:6], ethDst)
	return syscall.Sendto(a.rawFD, frame, 0, sll)
}

func (a *L2ARPAdapter) listenAndIntercept() {
	buf := make([]byte, 1500)
	for {
		if a.closed {
			return
		}
		n, _, err := syscall.Recvfrom(a.rawFD, buf, 0)
		if err != nil {
			if a.closed {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n < 42 {
			continue
		}

		ethType := binary.BigEndian.Uint16(buf[12:14])
		if ethType != 0x0806 {
			continue
		}
		op := binary.BigEndian.Uint16(buf[20:22])
		if op != 1 { // Only intercept ARP Requests
			continue
		}

		srcIP := net.IP(buf[28:32])
		reqIP := net.IP(buf[38:42])

		a.mu.Lock()
		for tIPStr, tMAC := range a.targetMACs {
			tIP := net.ParseIP(tIPStr)
			// Target asks who has Gateway -> answer immediately with hostMAC
			if srcIP.Equal(tIP) && reqIP.Equal(a.gwIP) {
				_ = a.sendARPPacket(2, a.hostMAC, tMAC, a.gwIP, tIP, a.hostMAC, tMAC)
			}
			// Gateway asks who has Target -> answer immediately with hostMAC
			if srcIP.Equal(a.gwIP) && reqIP.Equal(tIP) {
				_ = a.sendARPPacket(2, a.hostMAC, a.gwMAC, tIP, a.gwIP, a.hostMAC, a.gwMAC)
			}
		}
		a.mu.Unlock()
	}
}

func (a *L2ARPAdapter) ApplyQuarantine(ctx context.Context, e *models.Enforcement) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if e.DryRun {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateApplied
		return nil
	}

	targetIPStr := e.TargetIP
	targetMACStr := e.TargetMAC
	if targetIPStr == "" || targetMACStr == "" {
		return fmt.Errorf("target IP and MAC are required for L2 ARP quarantine")
	}

	targetIP := net.ParseIP(targetIPStr)
	if targetIP == nil || targetIP.To4() == nil {
		return fmt.Errorf("target IP %q is not valid IPv4", targetIPStr)
	}
	targetMAC, err := net.ParseMAC(targetMACStr)
	if err != nil {
		return fmt.Errorf("invalid target MAC %q: %w", targetMACStr, err)
	}

	// Poisoned traffic lands on THIS host. It only dies here if either the
	// kernel doesn't forward it, or our nftables drop rules catch it.
	// If forwarding is ON and the nft drop failed, the cut silently does
	// nothing (we'd just be a transparent bridge) — fail loudly instead.
	nftOK := false
	if a.nft != nil {
		if err := a.nft.ApplyQuarantine(ctx, e); err == nil {
			nftOK = true
		} else {
			e.ErrorMessage = err.Error()
		}
	}
	if forwardingEnabled() && !nftOK {
		return fmt.Errorf("kernel IP forwarding is enabled but the nftables drop could not be installed (%s); the cut would be a transparent bridge — disable forwarding (echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward) or run on the gateway", e.ErrorMessage)
	}
	if !nftOK {
		// Forwarding is off so attracted traffic dies in the kernel anyway;
		// don't leave a stale nft error on a working enforcement.
		e.ErrorMessage = ""
	}

	// If already running for this target, cancel old loop
	if stop, ok := a.activeCuts[targetIPStr]; ok {
		close(stop)
		delete(a.activeCuts, targetIPStr)
	}

	stopCh := make(chan struct{})
	a.activeCuts[targetIPStr] = stopCh
	a.targetMACs[targetIPStr] = targetMAC

	// Run periodic background poisoner
	go func(tIP net.IP, tMAC net.HardwareAddr, stop <-chan struct{}) {
		ticker := time.NewTicker(350 * time.Millisecond)
		defer ticker.Stop()

		// Initial fast burst
		for i := 0; i < 4; i++ {
			_ = a.sendARPPacket(2, a.hostMAC, tMAC, a.gwIP, tIP, a.hostMAC, tMAC)
			_ = a.sendARPPacket(1, a.hostMAC, tMAC, a.gwIP, tIP, a.hostMAC, tMAC)
			_ = a.sendARPPacket(2, a.hostMAC, a.gwMAC, tIP, a.gwIP, a.hostMAC, a.gwMAC)
			_ = a.sendARPPacket(1, a.hostMAC, a.gwMAC, tIP, a.gwIP, a.hostMAC, a.gwMAC)
		}

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				// Tell Target: Gateway is at Host MAC
				_ = a.sendARPPacket(2, a.hostMAC, tMAC, a.gwIP, tIP, a.hostMAC, tMAC)
				_ = a.sendARPPacket(1, a.hostMAC, tMAC, a.gwIP, tIP, a.hostMAC, tMAC)

				// Tell Gateway: Target is at Host MAC
				_ = a.sendARPPacket(2, a.hostMAC, a.gwMAC, tIP, a.gwIP, a.hostMAC, a.gwMAC)
				_ = a.sendARPPacket(1, a.hostMAC, a.gwMAC, tIP, a.gwIP, a.hostMAC, a.gwMAC)
			}
		}
	}(targetIP, targetMAC, stopCh)

	// Pair the v4 cut with NDP spoofing when both sides have IPv6 neighbor
	// addresses; otherwise dual-stack victims stay online over v6.
	// Best effort: v4 enforcement stands regardless.
	victimIPs := ndpAddrsForMAC(ctx, targetMAC)
	gwIPs := ndpAddrsForMAC(ctx, a.gwMAC)
	if len(victimIPs) > 0 && len(gwIPs) > 0 {
		go a.startNAStorm(stopCh, targetMAC, a.gwMAC, victimIPs, gwIPs, true)
	}

	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateApplied
	return nil
}

func (a *L2ARPAdapter) RemoveQuarantine(ctx context.Context, e *models.Enforcement) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	targetIPStr := e.TargetIP
	targetMACStr := e.TargetMAC

	if stop, ok := a.activeCuts[targetIPStr]; ok {
		close(stop)
		delete(a.activeCuts, targetIPStr)
		delete(a.targetMACs, targetIPStr)
	}

	// Remove nftables rules. Do NOT swallow this: a leftover drop is the
	// exact "internet still dead after Unblock All" symptom and must be
	// visible (and retryable) to the enforcement engine.
	var nftErr error
	if a.nft != nil {
		nftErr = a.nft.RemoveQuarantine(ctx, e)
	}

	// Heal caches with packets carrying the TRUE owners' MACs as Ethernet
	// source (a "heal" that still claims our MAC would keep the poison alive).
	if targetIPStr != "" && targetMACStr != "" {
		targetIP := net.ParseIP(targetIPStr)
		targetMAC, err := net.ParseMAC(targetMACStr)
		if err == nil && targetIP != nil {
			frames := healingFrames(a.gwIP, a.gwMAC, targetIP, targetMAC)
			naFrames := healingNAFrames(ndpAddrsForMAC(ctx, a.gwMAC), a.gwMAC, ndpAddrsForMAC(ctx, targetMAC), targetMAC)
			go func() {
				for round := 0; round < healRounds; round++ {
					for _, hp := range frames {
						_ = a.sendRaw(hp.dst, hp.frame, syscall.ETH_P_ARP)
					}
					for _, hp := range naFrames {
						_ = a.sendRaw(hp.dst, hp.frame, syscall.ETH_P_IPV6)
					}
					time.Sleep(healInterval)
				}
			}()
		}
	}

	if nftErr != nil {
		e.ActualState = models.StateApplied
		e.ErrorMessage = nftErr.Error()
		return nftErr
	}

	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateRolledBack
	return nil
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

// forwardingEnabled reports kernel IPv4 forwarding (per networking stack).
// Poisoned traffic that arrives here is forwarded when on — the cut then
// depends entirely on the nftables drop.
func forwardingEnabled() bool {
	return forwardingEnabledFrom("/proc/sys/net/ipv4/ip_forward")
}

func forwardingEnabledFrom(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

func (a *L2ARPAdapter) ApplyRateLimit(ctx context.Context, e *models.Enforcement) error {
	return fmt.Errorf("rate limiting not supported by L2 ARP adapter (use linux_tc)")
}

func (a *L2ARPAdapter) RemoveRateLimit(ctx context.Context, e *models.Enforcement) error {
	return nil
}

func (a *L2ARPAdapter) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	if a.rawFD > 0 {
		_ = syscall.Close(a.rawFD)
		a.rawFD = -1
	}
}

// ---------------------------------------------------------------------------
// IPv6 Neighbor Discovery spoofing.
//
// Cutting ARP alone leaves dual-stack victims online over IPv6, so a v4 cut
// is paired with forged Neighbor Advertisements (same idea, NDP layer):
// victim learns gateway link-local -> our MAC, gateway learns victim
// link-local -> our MAC. Attracted v6 traffic dies in the kernel (no
// forwarding) or in the ip6 nft drop rules. Only runs when both sides have
// neighbor-cache IPv6 addresses; v4 enforcement is unaffected otherwise.
// ---------------------------------------------------------------------------

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

// parseIPv6Neigh extracts neighbor-cache IPv6 addresses per MAC from
// `ip -6 neigh show` output, skipping FAILED/INCOMPLETE entries.
func parseIPv6Neigh(output string) map[string][]net.IP {
	out := make(map[string][]net.IP)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		state := strings.ToUpper(fields[len(fields)-1])
		if state == "FAILED" || state == "INCOMPLETE" {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() != nil {
			continue
		}
		var mac string
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "lladdr" {
				mac = strings.ToLower(fields[i+1])
				break
			}
		}
		if mac == "" {
			continue
		}
		out[mac] = append(out[mac], ip)
	}
	return out
}

// ndpAddrsForMAC returns cached IPv6 addresses for a MAC (link-locals first).
func ndpAddrsForMAC(ctx context.Context, mac net.HardwareAddr) []net.IP {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, "ip", "-6", "neigh", "show").CombinedOutput()
	if err != nil {
		return nil
	}
	addrs := parseIPv6Neigh(string(out))[strings.ToLower(mac.String())]
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

// startNAStorm poisons NDP in both directions until stop closes.
// victimIPs: victim addresses to claim at the gateway; gwIPs: gateway
// addresses to claim at the victim. True-owner variants heal on release.
func (a *L2ARPAdapter) startNAStorm(stop <-chan struct{}, victimMAC, gwMAC net.HardwareAddr, victimIPs, gwIPs []net.IP, poison bool) {
	claimedVictim, claimedGW := victimMAC, gwMAC
	if poison {
		claimedVictim, claimedGW = a.hostMAC, a.hostMAC
	}
	ticker := time.NewTicker(naVictimInterval)
	defer ticker.Stop()
	send := func() {
		for _, vip := range victimIPs {
			// Tell gateway: victim IP is at claimedVictim MAC.
			if f, err := buildNAFrame(a.hostMAC, gwMAC, vip, gwPickSrc(gwIPs), vip, claimedVictim); err == nil {
				_ = a.sendRaw(gwMAC, f, syscall.ETH_P_IPV6)
			}
		}
		for _, gip := range gwIPs {
			// Tell victim: gateway IP is at claimedGW MAC.
			if f, err := buildNAFrame(a.hostMAC, victimMAC, gip, gwPickSrc(victimIPs), gip, claimedGW); err == nil {
				_ = a.sendRaw(victimMAC, f, syscall.ETH_P_IPV6)
			}
		}
	}
	send()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			send()
		}
	}
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
