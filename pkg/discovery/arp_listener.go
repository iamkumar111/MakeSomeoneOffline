package discovery

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// NetworkScanner probes and parses ARP tables, local neighbors, and network interfaces.
type NetworkScanner struct {
	mu           sync.Mutex
	fusionEngine *IdentityFusionEngine
	interfaces   []string
	stopCh       chan struct{}
}

// NewNetworkScanner creates a scanner that feeds observations into the fusion engine.
func NewNetworkScanner(fusion *IdentityFusionEngine, ifaces []string) *NetworkScanner {
	return &NetworkScanner{
		fusionEngine: fusion,
		interfaces:   ifaces,
		stopCh:       make(chan struct{}),
	}
}

// Start begins periodic ARP scanning and neighbor table inspection.
func (s *NetworkScanner) Start(ctx context.Context, interval time.Duration) {
	if interval < 5*time.Second {
		interval = 10 * time.Second
	}

	go func() {
		// Run initial scan immediately
		s.ScanOnce(ctx)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.ScanOnce(ctx)
			}
		}
	}()
}

// Stop cleanly stops the scanner.
func (s *NetworkScanner) Stop() {
	close(s.stopCh)
}

// ScanOnce performs one pass of active subnet sweep, local interface ingestion, /proc/net/arp, and `ip neigh`.
func (s *NetworkScanner) ScanOnce(ctx context.Context) {
	// 1. Ingest local machine physical interfaces so the host itself is always tracked with full MAC & hostname
	s.ingestLocalInterfaces()

	// 2. Trigger concurrent subnet sweeps on physical LAN subnets to refresh the kernel ARP/neighbor cache
	s.probeSubnet(ctx)

	// 3. Read /proc/net/arp populated by kernel ARP replies
	s.readProcNetARP()

	// 4. Read `ip neigh`
	s.readIPNeigh(ctx)
}

func isPhysicalInterface(iface net.Interface) bool {
	if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
		return false
	}
	if len(iface.HardwareAddr) == 0 {
		return false
	}
	return isPhysicalInterfaceName(iface.Name)
}

func isPhysicalInterfaceName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}

	virtualPrefixes := []string{
		"docker", "br-", "veth", "virbr", "vmnet", "vboxnet",
		"tun", "tap", "dummy", "wg", "tailscale", "zt", "cni", "flannel", "lo",
	}
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}

	if _, err := os.Stat("/sys/class/net/" + name + "/device"); err == nil {
		return true
	}

	return strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "en") ||
		strings.HasPrefix(name, "wl") || strings.HasPrefix(name, "wlan")
}

func (s *NetworkScanner) ingestLocalInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	hostname, _ := os.Hostname()
	now := time.Now().UTC()

	for _, iface := range ifaces {
		if !isPhysicalInterface(iface) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}

			s.fusionEngine.IngestObservation(models.Observation{
				Timestamp: now,
				Source:    "local_interface",
				MAC:       iface.HardwareAddr.String(),
				IP:        ipNet.IP.String(),
				Interface: iface.Name,
				Hostname:  hostname,
				Attributes: map[string]interface{}{
					"is_local_host": true,
					"is_online":     true,
				},
			})
		}
	}
}

func (s *NetworkScanner) readProcNetARP() {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line: IP address HW type Flags HW address Mask Device
	if scanner.Scan() {
		_ = scanner.Text()
	}

	now := time.Now().UTC()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			ip := fields[0]
			flags := fields[2]
			mac := fields[3]
			iface := fields[5]

			if !isPhysicalInterfaceName(iface) {
				continue
			}

			// Flags 0x0 means incomplete/failed resolution, 0x2 is resolved
			if flags != "0x0" && mac != "00:00:00:00:00:00" && len(mac) == 17 {
				// Reverse-DNS is a weak hint (router caches go stale on DHCP
				// reassignment), so it travels as ptr_hostname (rank 1) and can
				// never overwrite NetBIOS/mDNS/DHCP names.
				attrs := map[string]interface{}{}
				if ptr := resolveHostname(ip); ptr != "" {
					attrs["ptr_hostname"] = ptr
				}
				s.fusionEngine.IngestObservation(models.Observation{
					Timestamp:  now,
					Source:     "arp_proc",
					MAC:        mac,
					IP:         ip,
					Interface:  iface,
					Attributes: attrs,
				})
			}
		}
	}
}

func (s *NetworkScanner) readIPNeigh(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "ip", "neigh", "show")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	now := time.Now().UTC()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		// Format: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
		if len(fields) >= 5 {
			ip := fields[0]
			var dev string
			var mac string
			for i := 0; i < len(fields)-1; i++ {
				if fields[i] == "dev" {
					dev = fields[i+1]
				}
				if fields[i] == "lladdr" {
					mac = fields[i+1]
				}
			}

			if !isPhysicalInterfaceName(dev) {
				continue
			}

			state := fields[len(fields)-1]
			// STALE means previously confirmed reachable — still online.
			// Only FAILED/INCOMPLETE mean "no MAC". Everything else is a sighting.
			isOnline := (state != "FAILED" && state != "INCOMPLETE")

			if mac != "" && mac != "00:00:00:00:00:00" && state != "FAILED" && state != "INCOMPLETE" {
				attrs := map[string]interface{}{
					"neigh_state": state,
					"is_online":   isOnline,
				}
				// Reverse-DNS is a weak hint (rank 1) — see readProcNetARP.
				if ptr := resolveHostname(ip); ptr != "" {
					attrs["ptr_hostname"] = ptr
				}
				s.fusionEngine.IngestObservation(models.Observation{
					Timestamp:  now,
					Source:     "ip_neigh",
					MAC:        mac,
					IP:         ip,
					Interface:  dev,
					Attributes: attrs,
				})

				go s.asyncFingerprint(ctx, ip, mac, dev)
			}
		}
	}
}

func (s *NetworkScanner) asyncFingerprint(ctx context.Context, ip, mac, iface string) {
	fp := FingerprintHost(ctx, ip)
	if fp.Hostname == "" && fp.OS == "" && fp.DeviceType == "" {
		return
	}

	attrs := make(map[string]interface{})
	attrs["is_online"] = true
	if fp.OS != "" {
		attrs["os"] = fp.OS
	}
	if fp.DeviceType != "" {
		attrs["device_type"] = fp.DeviceType
	}
	if fp.Vendor != "" {
		attrs["fingerprint_vendor"] = fp.Vendor
	}
	for k, v := range fp.Metadata {
		attrs[k] = v
	}

	obs := models.Observation{
		Timestamp:  time.Now().UTC(),
		Source:     "fingerprint",
		MAC:        mac,
		IP:         ip,
		Interface:  iface,
		Hostname:   fp.Hostname,
		Attributes: attrs,
	}

	s.fusionEngine.IngestObservation(obs)
}

func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		h := strings.TrimSuffix(names[0], ".")
		if h != "" && h != ip {
			return h
		}
	}
	return ""
}

// probeSubnet sends fast non-blocking UDP packets to physical subnets to populate ARP entries.
func (s *NetworkScanner) probeSubnet(ctx context.Context) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, iface := range ifaces {
		if !isPhysicalInterface(iface) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}

			// Broadcast address probe
			broadcastIP := getBroadcastIP(ipNet)
			if broadcastIP != nil {
				conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
					IP:   broadcastIP,
					Port: 5353,
				})
				if err == nil {
					_, _ = conn.Write([]byte{0x00})
					_ = conn.Close()
				}
			}

			// Unicast active subnet sweep across all hosts in subnet
			s.sweepSubnetIPs(ctx, ipNet)
		}
	}
}

func (s *NetworkScanner) sweepSubnetIPs(ctx context.Context, ipNet *net.IPNet) {
	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		return
	}

	mask := ipNet.Mask
	if len(mask) != 4 {
		return
	}

	ones, bits := mask.Size()
	sweepMask := mask
	if bits == 32 && ones < 24 {
		sweepMask = net.CIDRMask(24, 32)
	}

	netNum := binary.BigEndian.Uint32(ipv4) & binary.BigEndian.Uint32(sweepMask)
	broadcastNum := netNum | ^binary.BigEndian.Uint32(sweepMask)

	var targets []net.IP
	for num := netNum + 1; num < broadcastNum; num++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, num)
		targets = append(targets, ip)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(ip net.IP) {
			defer func() {
				<-sem
				wg.Done()
			}()

			conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
				IP:   ip,
				Port: 5353,
			})
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(40 * time.Millisecond))
				_, _ = conn.Write([]byte{0x00})
				_ = conn.Close()
			}
		}(target)
	}

	wg.Wait()
	// Allow a brief moment for kernel to receive and register ARP responses
	time.Sleep(150 * time.Millisecond)
}

func getBroadcastIP(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		return nil
	}
	mask := n.Mask
	broadcast := make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}

// GetDefaultGateway attempts to find the default gateway IP and MAC.
func GetDefaultGateway(ctx context.Context) (ip string, mac string, err error) {
	// Look up default route via `ip route show default`
	cmd := exec.CommandContext(ctx, "ip", "route", "show", "default")
	out, err := cmd.Output()
	if err == nil {
		fields := strings.Fields(string(out))
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "via" {
				ip = fields[i+1]
				break
			}
		}
	}

	if ip == "" {
		return "", "", fmt.Errorf("default gateway not found")
	}

	// Lookup MAC from /proc/net/arp or `ip neigh`
	file, err := os.Open("/proc/net/arp")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 && fields[0] == ip {
				mac = fields[3]
				break
			}
		}
	}

	return ip, mac, nil
}
