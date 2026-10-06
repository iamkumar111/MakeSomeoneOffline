//go:build windows

package adapters

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/discovery"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// WindowsSideHostAdapter implements side-host ARP quarantine on Windows.
//
// Poison path: Npcap injects forged ARP frames (victim told gateway-IP is at
// our MAC; gateway told victim-IP is at our MAC) on a ~350ms loop, mirroring
// the Linux l2_arp adapter. Attracted traffic is NOT forwarded — Windows IP
// forwarding must be off, which Apply verifies and refuses otherwise.
// Release path: loop stops, genuine-MAC healing frames are broadcast, then
// the Npcap handle closes.
//
// Safety: explicit adapter selection only, allowlist enforced by the policy
// engine, TTL auto-release, audit trail. Use only on networks you own.
type WindowsSideHostAdapter struct {
	mu     sync.Mutex
	active map[string]*windowsCut // target IP -> live cut
}

type windowsCut struct {
	stop   chan struct{}
	done   chan struct{}
	handle uintptr
}

// NewWindowsSideHostAdapter creates the adapter (no I/O; devices open lazily
// per enforcement so multi-homed hosts pick the right interface per cut).
func NewWindowsSideHostAdapter() *WindowsSideHostAdapter {
	return &WindowsSideHostAdapter{active: make(map[string]*windowsCut)}
}

func (a *WindowsSideHostAdapter) Name() string { return "windows_sidehost" }

func (a *WindowsSideHostAdapter) Capabilities() []string {
	return []string{"quarantine", "dry_run"}
}

func (a *WindowsSideHostAdapter) Describe() AdapterInfo {
	return AdapterInfo{
		Name:  "windows_sidehost",
		Label: "Windows Side-Host — ARP quarantine",
		Kind:  KindLab, Effectiveness: 4,
		Capabilities:       a.Capabilities(),
		RecommendedWhen:    "Windows PC on an unmanaged LAN (this box is NOT the gateway).",
		Requires:           "Administrator + Npcap + IP forwarding OFF.",
		Description:        "ARP enforcement: poison victim and gateway caches; attracted traffic dies here instead of being forwarded.",
		Warning:            "Use only on networks you own. Disruptive by design.",
		LabOnly:            true,
		SupportsQuarantine: true, SupportsShaping: false,
	}
}

// IsAvailable reports whether this host can enforce right now: Npcap present
// and IP forwarding off. Admin rights are checked at Apply time with a clear
// error (opening the dashboard must never require elevation by itself).
func (a *WindowsSideHostAdapter) IsAvailable(_ context.Context) bool {
	if !npcapAvailable() {
		return false
	}
	fwd, err := windowsForwardingEnabled()
	return err == nil && !fwd
}

func windowsIsAdmin() bool {
	return exec.Command("net", "session").Run() == nil
}

// windowsForwardingEnabled reads the IPEnableRouter flag. Absent/unreadable
// is treated as an error (refuse rather than assume) except when the value is
// confirmed 0.
func windowsForwardingEnabled() (bool, error) {
	out, err := exec.Command("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"/v", "IPEnableRouter").CombinedOutput()
	if err != nil {
		// Value absent means default (disabled) — but only if reg itself ran.
		if strings.Contains(strings.ToLower(string(out)), "unable to find") ||
			strings.Contains(strings.ToLower(string(out)), "error: the system was unable to find") {
			return false, nil
		}
		return false, fmt.Errorf("cannot verify IP forwarding state: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(line), "ipenablerouter") {
			if strings.Contains(strings.ToLower(line), "0x1") {
				return true, nil
			}
			return false, nil
		}
	}
	return false, nil
}

func windowsHostMAC(ipStr string) (net.HardwareAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.String() == ipStr {
				if len(iface.HardwareAddr) == 6 {
					return iface.HardwareAddr, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no interface found with IP %s", ipStr)
}

func (a *WindowsSideHostAdapter) ApplyQuarantine(ctx context.Context, e *models.Enforcement) error {
	if e.DryRun {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateApplied
		return nil
	}

	targetIP := net.ParseIP(strings.TrimSpace(e.TargetIP))
	if targetIP == nil || targetIP.To4() == nil {
		return fmt.Errorf("target IP %q is not valid IPv4", e.TargetIP)
	}
	targetMAC, err := net.ParseMAC(strings.TrimSpace(e.TargetMAC))
	if err != nil {
		return fmt.Errorf("invalid target MAC %q: %w", e.TargetMAC, err)
	}
	if !windowsIsAdmin() {
		return fmt.Errorf("administrator rights required (run elevated); Npcap injection is privileged")
	}
	if fwd, err := windowsForwardingEnabled(); err != nil {
		return fmt.Errorf("refusing cut: %v", err)
	} else if fwd {
		return fmt.Errorf("refusing cut: IP forwarding is ON — this host would route victim traffic instead of dropping it (set IPEnableRouter=0)")
	}
	gwIPStr, gwMACStr, err := discovery.GetDefaultGateway(ctx)
	if err != nil || gwIPStr == "" || gwMACStr == "" {
		return fmt.Errorf("refusing cut: default gateway IP/MAC not resolvable (%v)", err)
	}
	gwIP := net.ParseIP(gwIPStr)
	gwMAC, err := net.ParseMAC(gwMACStr)
	if err != nil {
		return fmt.Errorf("refusing cut: bad gateway MAC %q", gwMACStr)
	}

	devices, err := npcapIPv4Devices()
	if err != nil {
		return fmt.Errorf("refusing cut: %v (install Npcap)", err)
	}
	devName, devIP, err := selectDevice(devices)
	if err != nil {
		return fmt.Errorf("refusing cut: %v", err)
	}
	hostMAC, err := windowsHostMAC(devIP)
	if err != nil {
		return fmt.Errorf("refusing cut: %v", err)
	}
	handle, err := npcapOpen(devName)
	if err != nil {
		return fmt.Errorf("refusing cut: %v", err)
	}

	a.mu.Lock()
	if old, ok := a.active[targetIP.String()]; ok {
		close(old.stop)
		<-old.done
		npcapClose(old.handle)
		delete(a.active, targetIP.String())
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	a.active[targetIP.String()] = &windowsCut{stop: stop, done: done, handle: handle}
	a.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(350 * time.Millisecond)
		defer ticker.Stop()
		send := func() {
			// Victim: gateway IP is at our MAC.
			for _, op := range []uint16{2, 1} {
				if f, err := buildARPFrame(op, hostMAC, targetMAC, hostMAC, gwIP, targetMAC, targetIP); err == nil {
					_ = npcapSend(handle, f)
				}
			}
			// Gateway: victim IP is at our MAC.
			for _, op := range []uint16{2, 1} {
				if f, err := buildARPFrame(op, hostMAC, gwMAC, hostMAC, targetIP, gwMAC, gwIP); err == nil {
					_ = npcapSend(handle, f)
				}
			}
		}
		for i := 0; i < 4; i++ { // initial burst
			select {
			case <-stop:
				return
			default:
				send()
			}
		}
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				send()
			}
		}
	}()

	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateApplied
	return nil
}

func (a *WindowsSideHostAdapter) RemoveQuarantine(_ context.Context, e *models.Enforcement) error {
	a.mu.Lock()
	cut, ok := a.active[strings.TrimSpace(e.TargetIP)]
	if ok {
		delete(a.active, strings.TrimSpace(e.TargetIP))
	}
	a.mu.Unlock()
	if !ok {
		now := time.Now().UTC()
		e.AppliedAt = &now
		e.ActualState = models.StateRolledBack
		return nil
	}
	close(cut.stop)
	<-cut.done

	// Heal with genuine-MAC frames before closing the handle.
	if gwIP, gwMAC, targetIP, targetMAC, ok := parseHealAddrs(e); ok {
		for _, hp := range healingFrames(gwIP, gwMAC, targetIP, targetMAC) {
			_ = npcapSend(cut.handle, hp.frame)
		}
		time.Sleep(healInterval)
		for _, hp := range healingFrames(gwIP, gwMAC, targetIP, targetMAC) {
			_ = npcapSend(cut.handle, hp.frame)
		}
	}
	npcapClose(cut.handle)

	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateRolledBack
	return nil
}

func parseHealAddrs(e *models.Enforcement) (gwIP net.IP, gwMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr, ok bool) {
	targetIP = net.ParseIP(strings.TrimSpace(e.TargetIP))
	var err error
	targetMAC, err = net.ParseMAC(strings.TrimSpace(e.TargetMAC))
	if targetIP == nil || err != nil {
		return nil, nil, nil, nil, false
	}
	// Gateway may have changed; resolve fresh. If unresolvable, skip healing
	// rather than sending wrong frames.
	gwIPStr, gwMACStr, err := discovery.GetDefaultGateway(context.Background())
	if err != nil {
		return nil, nil, nil, nil, false
	}
	gwIP = net.ParseIP(gwIPStr)
	gwMAC, err = net.ParseMAC(gwMACStr)
	if gwIP == nil || err != nil {
		return nil, nil, nil, nil, false
	}
	return gwIP, gwMAC, targetIP, targetMAC, true
}

func (a *WindowsSideHostAdapter) ApplyRateLimit(_ context.Context, _ *models.Enforcement) error {
	return fmt.Errorf("windows rate limiting is not implemented yet (gateway tc only)")
}

func (a *WindowsSideHostAdapter) RemoveRateLimit(_ context.Context, e *models.Enforcement) error {
	now := time.Now().UTC()
	e.AppliedAt = &now
	e.ActualState = models.StateRolledBack
	return nil
}
