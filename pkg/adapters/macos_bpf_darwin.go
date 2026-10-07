//go:build darwin

package adapters

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/open-netcut/open-netcut/pkg/discovery"
)

func macBPFDevice() (*os.File, error) {
	for i := 0; i < 256; i++ {
		file, err := os.OpenFile(fmt.Sprintf("/dev/bpf%d", i), os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err == nil {
			return file, nil
		}
		if errors.Is(err, syscall.EBUSY) {
			continue
		}
		return nil, fmt.Errorf("BPF device unavailable (root required): %w", err)
	}
	return nil, fmt.Errorf("all BPF descriptors are busy")
}

func macIOCTL(file *os.File, command uintptr, data unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), command, uintptr(data))
	runtime.KeepAlive(data)
	if errno != 0 {
		return errno
	}
	return nil
}

func openMacBPF(iface string) (io.WriteCloser, error) {
	if !macEthernetInterface(iface) {
		return nil, fmt.Errorf("only physical enN interfaces are supported")
	}
	file, err := macBPFDevice()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (io.WriteCloser, error) { file.Close(); return nil, err }
	// Darwin struct ifreq is 32 bytes: IFNAMSIZ (16) + 16-byte union.
	var ifreq [32]byte
	copy(ifreq[:16], iface)
	if err := macIOCTL(file, syscall.BIOCSETIF, unsafe.Pointer(&ifreq[0])); err != nil {
		return fail(fmt.Errorf("BIOCSETIF %s: %w", iface, err))
	}
	var dlt uint32
	if err := macIOCTL(file, syscall.BIOCGDLT, unsafe.Pointer(&dlt)); err != nil {
		return fail(err)
	}
	if dlt != 1 {
		return fail(fmt.Errorf("BPF interface is not Ethernet (DLT %d)", dlt))
	}
	// Preserve Ethernet sources in true-owner healing frames, not just ARP payloads.
	complete := uint32(1)
	if err := macIOCTL(file, syscall.BIOCSHDRCMPLT, unsafe.Pointer(&complete)); err != nil {
		return fail(fmt.Errorf("cannot preserve Ethernet source: %w", err))
	}
	complete = 0
	if err := macIOCTL(file, syscall.BIOCGHDRCMPLT, unsafe.Pointer(&complete)); err != nil || complete != 1 {
		return fail(fmt.Errorf("BPF complete-header verification failed: %v", err))
	}
	return file, nil
}

func checkMacBPF(_ context.Context) error {
	if os.Getenv("ENABLE_MACOS_L2_ARP") != "1" {
		return fmt.Errorf("set ENABLE_MACOS_L2_ARP=1 for explicit macOS live quarantine opt-in")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("root required; start the server with sudo")
	}
	for _, key := range []string{"net.inet.ip.forwarding", "net.inet6.ip6.forwarding"} {
		value, err := syscall.SysctlUint32(key)
		if err != nil {
			return fmt.Errorf("cannot verify %s: %w", key, err)
		}
		if value != 0 {
			return fmt.Errorf("%s is ON; disable routing/Internet Sharing before side-host quarantine", key)
		}
	}
	file, err := macBPFDevice()
	if err != nil {
		return err
	}
	return file.Close() // readiness probe sends no packets
}

func macCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	limited, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(limited, name, args...).Output()
}

func resolveMacPlan(ctx context.Context, target net.IP) (macOSPlan, error) {
	var plan macOSPlan
	out, err := macCommand(ctx, "/sbin/route", "-n", "get", "default")
	if err != nil {
		return plan, fmt.Errorf("default route: %w", err)
	}
	plan.iface = macRouteField(string(out), "interface")
	plan.gwIP = net.ParseIP(macRouteField(string(out), "gateway"))
	if !macEthernetInterface(plan.iface) || plan.gwIP == nil || plan.gwIP.To4() == nil {
		return plan, fmt.Errorf("default IPv4 route must use a physical enN interface")
	}
	out, err = macCommand(ctx, "/sbin/route", "-n", "get", target.String())
	if err != nil || macRouteField(string(out), "interface") != plan.iface {
		return plan, fmt.Errorf("target route must use the same LAN interface as the gateway")
	}
	iface, err := net.InterfaceByName(plan.iface)
	if err != nil {
		return plan, err
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || !validUnicastMAC(iface.HardwareAddr) {
		return plan, fmt.Errorf("LAN interface must be up with a six-byte unicast MAC")
	}
	plan.hostMAC = iface.HardwareAddr
	addresses, err := iface.Addrs()
	if err != nil {
		return plan, err
	}
	for _, address := range addresses {
		if subnet, ok := address.(*net.IPNet); ok && subnet.IP.To4() != nil && subnet.Contains(plan.gwIP) && subnet.Contains(target) {
			plan.hostIP = subnet.IP
			break
		}
	}
	if plan.hostIP == nil {
		return plan, fmt.Errorf("target and gateway must be on the local interface's IPv4 subnet")
	}
	out, err = macCommand(ctx, "/usr/sbin/arp", "-an")
	if err != nil {
		return plan, err
	}
	for _, n := range discovery.ParseDarwinARP(string(out)) {
		if n.Interface != plan.iface {
			continue
		}
		if n.IPAddress == plan.gwIP.String() {
			plan.gwMAC, _ = net.ParseMAC(n.MACAddress)
		}
		if n.IPAddress == target.String() {
			plan.targetMAC, _ = net.ParseMAC(n.MACAddress)
		}
	}
	if !validUnicastMAC(plan.gwMAC) {
		return plan, fmt.Errorf("genuine gateway MAC missing; ping the gateway once and retry")
	}
	if !validUnicastMAC(plan.targetMAC) {
		return plan, fmt.Errorf("target MAC missing from the local LAN neighbor cache; refresh discovery")
	}
	if out, err = macCommand(ctx, "/usr/sbin/ndp", "-an"); err == nil {
		neighbors := parseMacNDP(string(out), plan.iface)
		plan.victimIPv6 = neighbors[plan.targetMAC.String()]
		plan.gatewayIPv6 = neighbors[plan.gwMAC.String()]
	}
	return plan, nil
}

// MacOSProbe opens/configures/closes BPF; it never sends any packets.
func MacOSProbe(ctx context.Context, target string) (MacOSProbeResult, error) {
	result := MacOSProbeResult{Blockers: []string{}, Note: "No packets sent. Writable Ethernet BPF is not proof of injection on the wire or target isolation."}
	fail := func(err error) (MacOSProbeResult, error) {
		result.Blockers = append(result.Blockers, err.Error())
		return result, err
	}
	if err := checkMacBPF(ctx); err != nil {
		return fail(err)
	}
	if target == "" {
		out, err := macCommand(ctx, "/sbin/route", "-n", "get", "default")
		if err != nil {
			return fail(err)
		}
		target = macRouteField(string(out), "gateway")
	}
	ip := net.ParseIP(target)
	if ip == nil || ip.To4() == nil {
		return fail(fmt.Errorf("valid IPv4 target required"))
	}
	plan, err := resolveMacPlan(ctx, ip)
	if err != nil {
		return fail(err)
	}
	result.Interface = plan.iface
	result.LocalIP = plan.hostIP.String()
	result.GatewayIP = plan.gwIP.String()
	result.TargetIP = target
	writer, err := openMacBPF(plan.iface)
	if err != nil {
		return fail(err)
	}
	if err := writer.Close(); err != nil {
		return fail(err)
	}
	result.Ready = true
	return result, nil
}
